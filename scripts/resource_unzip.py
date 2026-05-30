#!/usr/bin/env python3
"""Helpers for the resource-unzip skill.

The script is intentionally conservative: it stages renamed copies or hardlinks
instead of changing source files, extracts one archive at a time, and writes
JSONL logs suitable for later reporting.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable


ARCHIVE_EXTS = {".zip": "zip", ".7z": "7z", ".rar": "rar"}
DISGUISED_ARCHIVE_EXTS = {".exe": "zip"}
MEDIA_EXTS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".bmp",
    ".heic",
    ".mp4",
    ".mov",
    ".mkv",
    ".avi",
    ".wmv",
    ".m4v",
}
TEXT_EXTS = {".txt", ".nfo", ".url", ".md"}
DEFAULT_PASSWORDS = ["上老王论坛当老王", "@月暖如梵音", "freeshare.com"]
DELETE_WORD_RE = re.compile(r"(删除|删掉|删)")
JUNK_NAME_RE = re.compile(r"(文宣|宣传|广告|推广|网址发布|最新地址|防走失)")
PART_RE = re.compile(r"^(?P<base>.+)\.(?P<num>\d{3})$")
PASSWORD_RE = re.compile(
    r"(?:解压密码|压缩密码|密码|pass(?:word)?|pwd)\s*[:：=]\s*([^\s,，;；。]+)",
    re.IGNORECASE,
)
FOLDER_PASSWORD_RE = re.compile(r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]{4,64}")


def write_log(log_path: Path | None, event: str, **data: object) -> None:
    if not log_path:
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {"event": event, **data}
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def sniff_archive(path: Path) -> str | None:
    try:
        with path.open("rb") as fh:
            head = fh.read(8)
    except OSError:
        return None
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    return None


def archive_kind_from_name(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix in ARCHIVE_EXTS:
        return ARCHIVE_EXTS[suffix]
    if suffix in DISGUISED_ARCHIVE_EXTS:
        return DISGUISED_ARCHIVE_EXTS[suffix]
    part = split_part(path)
    if part:
        base_suffix = Path(part[0]).suffix.lower()
        return ARCHIVE_EXTS.get(base_suffix) or DISGUISED_ARCHIVE_EXTS.get(base_suffix)
    return None


def split_part(path: Path) -> tuple[str, str] | None:
    match = PART_RE.match(path.name)
    if not match:
        return None
    return match.group("base"), match.group("num")


def iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for filename in sorted(filenames):
            yield Path(dirpath) / filename


def safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def decode_small_text(path: Path, max_bytes: int = 2_000_000) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if len(raw) > max_bytes:
        return None
    for encoding in ("utf-8-sig", "gb18030", "big5", "utf-16", "latin1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def extract_passwords(text: str) -> list[str]:
    return [match.group(1).strip().strip("\"'") for match in PASSWORD_RE.finditer(text)]


def dedupe(values: Iterable[str | None]) -> list[str | None]:
    seen: set[str | None] = set()
    result: list[str | None] = []
    for value in values:
        if value == "":
            value = None
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def collect_scan(root: Path) -> dict[str, object]:
    archives: list[dict[str, object]] = []
    suspicious: list[dict[str, object]] = []
    media_by_dir: dict[str, int] = {}
    password_hints: list[dict[str, str]] = []
    folder_passwords: list[str] = []
    part_groups: dict[str, dict[str, object]] = {}

    for file_path in iter_files(root):
        rel = safe_rel(file_path, root)
        sniffed = sniff_archive(file_path)
        named = archive_kind_from_name(file_path)
        kind = sniffed or named
        suffix = file_path.suffix.lower()
        part = split_part(file_path)

        for parent in file_path.parents:
            if parent == parent.parent:
                break
            name = parent.name
            if FOLDER_PASSWORD_RE.fullmatch(name):
                folder_passwords.append(name)
            if parent == root:
                break

        if suffix in MEDIA_EXTS:
            media_by_dir[safe_rel(file_path.parent, root)] = media_by_dir.get(
                safe_rel(file_path.parent, root), 0
            ) + 1

        if kind or part:
            reason = "magic" if sniffed else "extension_or_part"
            archives.append(
                {
                    "path": rel,
                    "kind": kind,
                    "size": file_path.stat().st_size,
                    "reason": reason,
                }
            )

        if sniffed and archive_kind_from_name(file_path) != sniffed:
            suspicious.append(
                {
                    "path": rel,
                    "detected": sniffed,
                    "suggested_suffix": f".{sniffed}",
                }
            )
        elif suffix in DISGUISED_ARCHIVE_EXTS:
            suspicious.append(
                {
                    "path": rel,
                    "detected": DISGUISED_ARCHIVE_EXTS[suffix],
                    "suggested_suffix": f".{DISGUISED_ARCHIVE_EXTS[suffix]}",
                }
            )

        if part:
            base, num = part
            key = str(file_path.parent / base)
            entry = part_groups.setdefault(
                key,
                {
                    "directory": safe_rel(file_path.parent, root),
                    "base": base,
                    "parts": [],
                    "detected": None,
                },
            )
            entry["parts"].append(num)
            if num == "001" and sniffed:
                entry["detected"] = sniffed

        if suffix in TEXT_EXTS:
            for hint in extract_passwords(file_path.name):
                password_hints.append({"source": rel, "password": hint})
            text = decode_small_text(file_path)
            if text:
                for hint in extract_passwords(text):
                    password_hints.append({"source": rel, "password": hint})

    password_candidates = dedupe(
        [hint["password"] for hint in password_hints]
        + folder_passwords
        + DEFAULT_PASSWORDS
    )
    return {
        "root": str(root),
        "archives": archives,
        "suspicious": suspicious,
        "part_groups": list(part_groups.values()),
        "media_by_dir": media_by_dir,
        "password_hints": password_hints,
        "password_candidates": password_candidates,
    }


def print_scan(scan: dict[str, object]) -> None:
    archives = scan["archives"]
    suspicious = scan["suspicious"]
    part_groups = scan["part_groups"]
    media_by_dir = scan["media_by_dir"]
    password_candidates = scan["password_candidates"]

    print(f"Root: {scan['root']}")
    print(f"Archive candidates: {len(archives)}")
    for item in archives[:50]:
        print(f"  - {item['path']} kind={item['kind']} reason={item['reason']}")
    if len(archives) > 50:
        print(f"  ... {len(archives) - 50} more")

    print(f"Suspicious disguised archives: {len(suspicious)}")
    for item in suspicious[:50]:
        print(f"  - {item['path']} -> {item['suggested_suffix']}")

    print(f"Multipart groups: {len(part_groups)}")
    for group in part_groups[:50]:
        parts = ",".join(sorted(group["parts"]))
        print(f"  - {group['directory']}/{group['base']} parts={parts} detected={group['detected']}")

    print("Media directories:")
    for directory, count in sorted(media_by_dir.items(), key=lambda item: (-item[1], item[0]))[:25]:
        print(f"  - {directory}: {count}")

    print("Password candidates:")
    for password in password_candidates:
        print(f"  - {password}")


def clean_component(name: str) -> str:
    cleaned = DELETE_WORD_RE.sub("", name).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned or "unnamed"


def replacement_name(name: str, kind: str | None, part_kind: str | None = None) -> str:
    part = PART_RE.match(name)
    if part:
        base = clean_component(part.group("base"))
        num = part.group("num")
        actual_kind = kind or part_kind
        if actual_kind:
            suffix = Path(base).suffix.lower()
            if suffix not in ARCHIVE_EXTS:
                if suffix:
                    base = base[: -len(suffix)] + f".{actual_kind}"
                else:
                    base = f"{base}.{actual_kind}"
        return f"{base}.{num}"

    cleaned = clean_component(name)
    actual_kind = kind
    if actual_kind:
        suffix = Path(cleaned).suffix.lower()
        if suffix not in ARCHIVE_EXTS:
            if suffix:
                cleaned = cleaned[: -len(suffix)] + f".{actual_kind}"
            else:
                cleaned = f"{cleaned}.{actual_kind}"
    return cleaned


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    for index in range(1, 10_000):
        candidate = parent / f"{stem}__{index}{suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"could not find unique name for {path}")


def build_part_kind_map(root: Path) -> dict[tuple[Path, str], str]:
    part_kind: dict[tuple[Path, str], str] = {}
    for file_path in iter_files(root):
        part = split_part(file_path)
        if not part:
            continue
        base, num = part
        if num != "001":
            continue
        kind = sniff_archive(file_path) or archive_kind_from_name(file_path)
        if kind:
            part_kind[(file_path.parent, base)] = kind
    return part_kind


def normalize(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    stage = args.stage.resolve()
    log_path = args.log.resolve() if args.log else None
    part_kind = build_part_kind_map(root)
    actions: list[dict[str, str]] = []

    for source in iter_files(root):
        rel_parts = source.relative_to(root).parts
        cleaned_dirs = [clean_component(part) for part in rel_parts[:-1]]
        part = split_part(source)
        inherited_kind = None
        if part:
            inherited_kind = part_kind.get((source.parent, part[0]))
        kind = sniff_archive(source) or archive_kind_from_name(source)
        target_name = replacement_name(source.name, kind, inherited_kind)
        target = unique_path(stage.joinpath(*cleaned_dirs, target_name))
        actions.append({"source": str(source), "target": str(target)})

        if args.dry_run:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            if args.copy:
                shutil.copy2(source, target)
            else:
                os.link(source, target)
        except OSError:
            shutil.copy2(source, target)
        write_log(log_path, "normalize", source=str(source), target=str(target))

    for action in actions:
        print(f"{action['source']} -> {action['target']}")
    return 0


def load_passwords(args: argparse.Namespace) -> list[str | None]:
    values: list[str | None] = [None]
    values.extend(args.password or [])
    if args.password_file:
        text = decode_small_text(args.password_file) or ""
        values.extend(line.strip() for line in text.splitlines() if line.strip())
    if args.include_defaults:
        values.extend(DEFAULT_PASSWORDS)
    return dedupe(values)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_external(command: list[str]) -> subprocess.CompletedProcess[str]:
    def lower_priority() -> None:
        try:
            os.nice(10)
        except OSError:
            pass

    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=lower_priority if hasattr(os, "nice") else None,
        check=False,
    )


def try_python_zip(archive: Path, output: Path, password: str | None) -> tuple[bool, str]:
    try:
        with zipfile.ZipFile(archive) as zf:
            pwd = password.encode("utf-8") if password else None
            zf.extractall(output, pwd=pwd)
        return True, "python zipfile"
    except Exception as exc:  # noqa: BLE001 - surface extractor diagnostics.
        return False, f"python zipfile failed: {exc}"


def try_extract_with_tool(
    archive: Path,
    attempt_dir: Path,
    password: str | None,
    tool: str,
) -> tuple[bool, str]:
    kind = sniff_archive(archive) or archive_kind_from_name(archive)
    if tool == "7z" and command_exists("7z"):
        command = ["7z", "x", "-y", "-mmt=2", f"-o{attempt_dir}"]
        if password is not None:
            command.append(f"-p{password}")
        command.append(str(archive))
        result = run_external(command)
        return result.returncode == 0, result.stdout[-4000:]

    if tool == "unar" and command_exists("unar"):
        command = ["unar", "-quiet", "-force-overwrite", "-output-directory", str(attempt_dir)]
        if password is not None:
            command.extend(["-password", password])
        command.append(str(archive))
        result = run_external(command)
        return result.returncode == 0, result.stdout[-4000:]

    if tool == "python-zip" and kind == "zip":
        return try_python_zip(archive, attempt_dir, password)

    if tool == "bsdtar" and command_exists("bsdtar") and password is None:
        result = run_external(["bsdtar", "-xf", str(archive), "-C", str(attempt_dir)])
        return result.returncode == 0, result.stdout[-4000:]

    return False, f"tool {tool} is unavailable or not applicable"


def move_attempt_contents(attempt_dir: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for child in attempt_dir.iterdir():
        shutil.move(str(child), str(unique_path(output / child.name)))


def extract(args: argparse.Namespace) -> int:
    archive = args.archive.resolve()
    output = args.output.resolve()
    log_path = args.log.resolve() if args.log else None
    passwords = load_passwords(args)
    tool_order = ["7z", "unar", "python-zip", "bsdtar"] if args.tool == "auto" else [args.tool]

    print(f"Archive: {archive}")
    print(f"Output: {output}")
    print(f"Tools: {', '.join(tool_order)}")
    print(f"Password attempts: {len(passwords)}")

    if args.dry_run:
        for password in passwords:
            print(f"DRY-RUN password={password}")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    for password in passwords:
        for tool in tool_order:
            attempt_dir = Path(
                tempfile.mkdtemp(prefix=".resource-unzip-attempt-", dir=str(output.parent))
            )
            ok, detail = try_extract_with_tool(archive, attempt_dir, password, tool)
            has_output = any(attempt_dir.iterdir()) if attempt_dir.exists() else False
            write_log(
                log_path,
                "extract_attempt",
                archive=str(archive),
                output=str(output),
                tool=tool,
                password=password,
                ok=ok,
                has_output=has_output,
                detail=detail,
            )
            if ok and has_output:
                move_attempt_contents(attempt_dir, output)
                shutil.rmtree(attempt_dir, ignore_errors=True)
                write_log(
                    log_path,
                    "extract_success",
                    archive=str(archive),
                    output=str(output),
                    tool=tool,
                    password=password,
                )
                print(f"SUCCESS tool={tool} password={password}")
                return 0
            shutil.rmtree(attempt_dir, ignore_errors=True)
            print(f"FAILED tool={tool} password={password}: {detail.splitlines()[-1:]}")

    write_log(
        log_path,
        "extract_failure",
        archive=str(archive),
        output=str(output),
        tried_passwords=passwords,
        tools=tool_order,
    )
    return 2


def scan(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    log_path = args.log.resolve() if args.log else None
    result = collect_scan(root)
    write_log(log_path, "scan", result=result)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_scan(result)
    return 0


def path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def cleanup_candidate(path: Path) -> tuple[bool, str]:
    if sniff_archive(path):
        return True, "archive_magic"
    if archive_kind_from_name(path):
        return True, "archive_extension"
    if split_part(path):
        return True, "multipart_suffix"
    return False, ""


def cleanup(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    target = args.target.resolve()
    log_path = args.log.resolve() if args.log else None

    if not root.is_dir():
        print(f"ERROR cleanup root is not a directory: {root}", file=sys.stderr)
        return 2
    if not target.is_dir():
        print(f"ERROR target is not a directory: {target}", file=sys.stderr)
        return 2
    if target == root or not path_is_within(target, root):
        print("ERROR target must be a child directory of cleanup root", file=sys.stderr)
        return 2

    candidates: list[tuple[Path, str]] = []
    for file_path in iter_files(root):
        resolved = file_path.resolve()
        if path_is_within(resolved, target):
            continue
        is_candidate, reason = cleanup_candidate(file_path)
        if is_candidate:
            candidates.append((file_path, reason))

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"Cleanup root: {root}")
    print(f"Target preserved: {target}")
    print(f"Mode: {mode}")
    print(f"Archive candidates: {len(candidates)}")

    deleted = 0
    for file_path, reason in candidates:
        print(f"  - {file_path} reason={reason}")
        write_log(
            log_path,
            "cleanup_candidate",
            root=str(root),
            target=str(target),
            path=str(file_path),
            reason=reason,
            apply=args.apply,
        )
        if args.apply:
            file_path.unlink()
            deleted += 1
            write_log(log_path, "cleanup_deleted", path=str(file_path), reason=reason)

    print(f"Deleted: {deleted}")
    if not args.apply:
        print("Nothing deleted. Re-run with --apply after reviewing the list.")
    write_log(
        log_path,
        "cleanup_summary",
        root=str(root),
        target=str(target),
        apply=args.apply,
        candidates=len(candidates),
        deleted=deleted,
    )
    return 0


def junk_candidate(path: Path) -> tuple[bool, str]:
    if JUNK_NAME_RE.search(path.name):
        return True, "junk_name"
    return False, ""


def remove_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def clean_junk(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    target = args.target.resolve() if args.target else None
    log_path = args.log.resolve() if args.log else None

    if not root.is_dir():
        print(f"ERROR junk cleanup root is not a directory: {root}", file=sys.stderr)
        return 2
    if target is not None and not target.is_dir():
        print(f"ERROR target is not a directory: {target}", file=sys.stderr)
        return 2
    if target is not None and not path_is_within(target, root):
        print("ERROR target must be inside junk cleanup root", file=sys.stderr)
        return 2

    candidates: list[tuple[Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        current = Path(dirpath)
        for dirname in list(dirnames):
            candidate = current / dirname
            resolved = candidate.resolve()
            if target is not None and (resolved == target or path_is_within(target, resolved)):
                continue
            is_candidate, reason = junk_candidate(candidate)
            if is_candidate:
                candidates.append((candidate, reason))
                dirnames.remove(dirname)
        for filename in filenames:
            candidate = current / filename
            is_candidate, reason = junk_candidate(candidate)
            if is_candidate:
                candidates.append((candidate, reason))

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"Junk cleanup root: {root}")
    if target is not None:
        print(f"Target checked: {target}")
    print(f"Mode: {mode}")
    print(f"Junk candidates: {len(candidates)}")

    deleted = 0
    for path, reason in candidates:
        print(f"  - {path} reason={reason}")
        write_log(
            log_path,
            "junk_cleanup_candidate",
            root=str(root),
            target=str(target) if target else None,
            path=str(path),
            reason=reason,
            apply=args.apply,
        )
        if args.apply:
            remove_path(path)
            deleted += 1
            write_log(log_path, "junk_cleanup_deleted", path=str(path), reason=reason)

    print(f"Deleted: {deleted}")
    if not args.apply:
        print("Nothing deleted. Re-run with --apply after reviewing the list.")
    write_log(
        log_path,
        "junk_cleanup_summary",
        root=str(root),
        target=str(target) if target else None,
        apply=args.apply,
        candidates=len(candidates),
        deleted=deleted,
    )
    return 0


def delete_source(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    target = args.target.resolve()
    log_path = args.log.resolve() if args.log else None

    if not source.is_dir():
        print(f"ERROR source is not a directory: {source}", file=sys.stderr)
        return 2
    if not target.is_dir():
        print(f"ERROR target is not a directory: {target}", file=sys.stderr)
        return 2
    if source == target:
        print("ERROR source and target are the same directory", file=sys.stderr)
        return 2
    if path_is_within(target, source):
        print(
            "ERROR target is inside source; move the target folder out before deleting source",
            file=sys.stderr,
        )
        return 2
    if path_is_within(source, target):
        print("ERROR source is inside target; refusing to delete inside the target folder", file=sys.stderr)
        return 2

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"Source folder: {source}")
    print(f"Verified target folder: {target}")
    print(f"Mode: {mode}")
    write_log(
        log_path,
        "delete_source_candidate",
        source=str(source),
        target=str(target),
        apply=args.apply,
    )

    if args.apply:
        shutil.rmtree(source)
        write_log(log_path, "delete_source_deleted", source=str(source), target=str(target))
        print("Deleted: 1")
    else:
        print("Deleted: 0")
        print("Nothing deleted. Re-run with --apply after confirming the target folder is correct.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan, stage, and extract disguised archives.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a directory for archives and hints.")
    scan_parser.add_argument("root", type=Path)
    scan_parser.add_argument("--log", type=Path)
    scan_parser.add_argument("--json", action="store_true")
    scan_parser.set_defaults(func=scan)

    normalize_parser = subparsers.add_parser(
        "normalize",
        help="Stage files with cleaned names and archive suffixes inferred from magic bytes.",
    )
    normalize_parser.add_argument("root", type=Path)
    normalize_parser.add_argument("--stage", type=Path, required=True)
    normalize_parser.add_argument("--log", type=Path)
    normalize_parser.add_argument("--copy", action="store_true", help="Copy instead of hardlinking.")
    normalize_parser.add_argument("--dry-run", action="store_true")
    normalize_parser.set_defaults(func=normalize)

    extract_parser = subparsers.add_parser("extract", help="Extract one archive with password attempts.")
    extract_parser.add_argument("archive", type=Path)
    extract_parser.add_argument("--output", type=Path, required=True)
    extract_parser.add_argument("--password", action="append")
    extract_parser.add_argument("--password-file", type=Path)
    extract_parser.add_argument("--include-defaults", action="store_true")
    extract_parser.add_argument("--tool", choices=["auto", "7z", "unar", "python-zip", "bsdtar"], default="auto")
    extract_parser.add_argument("--log", type=Path)
    extract_parser.add_argument("--dry-run", action="store_true")
    extract_parser.set_defaults(func=extract)

    cleanup_parser = subparsers.add_parser(
        "cleanup",
        help="Delete confirmed archive candidates outside a preserved target directory.",
    )
    cleanup_parser.add_argument("root", type=Path)
    cleanup_parser.add_argument("--target", type=Path, required=True)
    cleanup_parser.add_argument("--log", type=Path)
    cleanup_parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete listed archive candidates. Without this flag, only preview the list.",
    )
    cleanup_parser.set_defaults(func=cleanup)

    clean_junk_parser = subparsers.add_parser(
        "clean-junk",
        help="Delete promo/junk files or folders such as 文宣, 宣传, 广告, 推广.",
    )
    clean_junk_parser.add_argument("root", type=Path)
    clean_junk_parser.add_argument("--target", type=Path)
    clean_junk_parser.add_argument("--log", type=Path)
    clean_junk_parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete listed junk candidates. Without this flag, only preview the list.",
    )
    clean_junk_parser.set_defaults(func=clean_junk)

    delete_source_parser = subparsers.add_parser(
        "delete-source",
        help="Delete the original source folder after the final target folder is verified.",
    )
    delete_source_parser.add_argument("source", type=Path)
    delete_source_parser.add_argument("--target", type=Path, required=True)
    delete_source_parser.add_argument("--log", type=Path)
    delete_source_parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete the source folder. Without this flag, only preview the action.",
    )
    delete_source_parser.set_defaults(func=delete_source)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
