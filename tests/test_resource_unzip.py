from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "resource_unzip.py"
SPEC = importlib.util.spec_from_file_location("resource_unzip", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
resource_unzip = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = resource_unzip
SPEC.loader.exec_module(resource_unzip)


class PasswordOrderTests(unittest.TestCase):
    def test_default_password_priority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_dir = root / "folder-password"
            archive_dir.mkdir()
            archive = archive_dir / "archive.zip"
            archive.touch()

            hint_root = root / "hint-root"
            (hint_root / "nested-folder-password").mkdir(parents=True)
            (hint_root / "密码.txt").write_text("密码:text-hint\n", encoding="utf-8")

            password_file = root / "passwords.txt"
            password_file.write_text("file-hint\n", encoding="utf-8")
            common_password_file = root / "common-passwords.txt"
            common_password_file.write_text("custom-common\n", encoding="utf-8")

            args = argparse.Namespace(
                archive=archive,
                password=["cli-hint"],
                password_file=password_file,
                password_hint_root=[hint_root],
                no_common_passwords=False,
                common_password_file=common_password_file,
            )

            candidates = resource_unzip.load_passwords(args)
            values = [candidate.value for candidate in candidates]

            self.assertEqual(values[0], "上老王论坛当老王")
            self.assertLess(values.index("folder-password"), values.index("custom-common"))
            self.assertLess(values.index("hint-root"), values.index("custom-common"))
            self.assertLess(values.index("nested-folder-password"), values.index("custom-common"))
            self.assertLess(values.index("nested-folder-password"), values.index(None))
            self.assertLess(values.index(None), values.index("custom-common"))
            self.assertLess(values.index("123"), values.index("cli-hint"))

    def test_builtin_common_passwords_include_short_values(self) -> None:
        self.assertIn("11aa", resource_unzip.BUILTIN_COMMON_PASSWORDS)
        self.assertIn("123", resource_unzip.BUILTIN_COMMON_PASSWORDS)


class MultiMp4ArchiveTests(unittest.TestCase):
    def test_scan_and_normalize_multiple_mp4_archive_parts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "input"
            stage = Path(tmp) / "stage"
            root.mkdir()
            (root / "video.7z.001.mp4").write_bytes(b"part-one")
            (root / "video.7z.002.mp4").write_bytes(b"part-two")

            scan = resource_unzip.collect_scan(root)
            markers = scan["multi_mp4_archive_markers"]
            self.assertEqual(
                [marker["suggested_name"] for marker in markers],
                ["video.7z.001", "video.7z.002"],
            )

            args = argparse.Namespace(
                root=root,
                stage=stage,
                log=None,
                copy=True,
                dry_run=False,
            )
            self.assertEqual(resource_unzip.normalize(args), 0)
            self.assertTrue((stage / "video.7z.001").is_file())
            self.assertTrue((stage / "video.7z.002").is_file())

    def test_single_mp4_is_not_treated_as_archive_from_name_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "video.7z.mp4").write_bytes(b"ordinary-media")

            scan = resource_unzip.collect_scan(root)

            self.assertEqual(scan["multi_mp4_archive_markers"], [])
            self.assertEqual(scan["archives"], [])


if __name__ == "__main__":
    unittest.main()
