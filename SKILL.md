---
name: resource-unzip
description: Use this skill when Codex needs to unpack files downloaded from cloud drives or forums where archives are disguised as PNG/JPG/PDF/MP4/EXE/unknown files, split into .001/.002 parts, nested through multiple layers, or protected by passwords. It guides recursive archive identification, safe suffix normalization to zip/7z/rar, multipart staging, password discovery from folder names and text hints, persistent common-password learning, extraction logging, final media-folder detection, junk promo cleanup, source-folder deletion after verified success, archive cleanup after success, and resource-conscious operation.
---

# Resource Unzip

## 总体目标

把网盘下载文件递归解压到最终目标文件夹。不要被文件后缀迷惑：看魔数、结构和解压结果，而不是只看 `.png`、`.jpg`、`.pdf`、`.mp4`、`.exe` 或未知后缀。

最终目标通常是包含多张图片或多个视频的文件夹。如果只得到一个图片或视频，先确认它是否仍是伪装压缩包或分卷的一部分，再判断是否结束。

## 工作原则

1. 解压过程中保留原始下载文件。先创建 staging 工作区，在 staging 中复制或硬链接文件、清理文件名、修改后缀并解压；只有最终目标文件夹确认无误后，才删除最初的源文件夹。
2. 每轮只处理少量候选压缩包，优先一个压缩包一个压缩包解压。不要并行爆破密码或并行展开大量大文件。
3. 每次解压都记录：输入文件、实际尝试的后缀/工具、输出目录、成功或失败、尝试过的密码、是否识别出目标文件夹。
4. 已经是 `.zip`、`.7z`、`.rar` 或明确可解压格式的文件，先直接解压，不要先改后缀。
5. 文件名包含 `删`、`删除`、`删掉` 等字样时，先在 staging 文件名中移除这些字样，再判断和修改后缀。
6. 修改伪装后缀时保留分卷编号。例如 `解压缩.png.001` 应改成 `解压缩.zip.001`，不能改成 `解压缩.zip`。
7. 遇到 `.001`、`.002` 等分卷时，把同一组分卷放在同一 staging 文件夹下再解压。不同分卷散落在不同目录时，复制或硬链接到同一目录，不要直接移动原件。
8. 注意密码和文件名编码。读取提示文本时尝试 UTF-8、GB18030、Big5、UTF-16、Latin-1；遇到乱码文件名时优先用 `unar` 或 `7z`，并保留原始字节来源。
9. 如果成功解压使用的是 `.txt`、`.nfo`、`.url`、`.md` 等文本提示中看到的密码，完成解压后把该密码加入 `common_passwords.txt`，供后续任务按常用密码优先级复用。
10. 如果解压结果中有多个 `.mp4`，检查这些文件名是否包含 `7z`、`zip`、`rar` 等压缩格式表述。只要存在这种表述，就不能把当前目录当作最终目标文件夹；应在 staging 中移除伪装 `.mp4` 后缀或改成对应压缩后缀，再继续解压。
11. 找到最终目标文件夹后，清理其所属解压目录：删除目标文件夹之外已经确认属于本次解压链路的压缩包、伪装压缩包和分卷文件。不要删除目标文件夹，不要删除未确认用途的普通文件。先预览删除列表，再执行删除，并把结果写入日志。
12. 解压结果中遇到 `文宣`、`宣传`、`广告`、`推广`、`网址发布`、`最新地址`、`防走失` 等明显推广或说明性质的文件/文件夹，确认不属于目标媒体后删除。
13. 删除最初源文件夹前必须确认：目标文件夹已验证可用；目标文件夹不在源文件夹内部；日志中没有仍需从源文件夹继续处理的候选压缩包。

## 快速流程

1. 建立工作目录：
   - `staging/`：放清理和改名后的候选文件。
   - `extracted/`：放每层解压输出。
   - `resource-unzip-log.jsonl` 或 `resource-unzip-log.md`：记录过程。
2. 盘点输入：用 `file`、`find`、`rg --files` 或本技能脚本识别压缩包魔数、分卷组、媒体文件、txt 密码提示，以及多个 `.mp4` 文件名中的 `7z`、`zip`、`rar` 压缩格式表述。
3. 生成密码候选，按优先级去重。
4. 在 staging 中规范化文件名和伪装后缀。
5. 解压一层后，对输出目录重复步骤 2 到步骤 4，直到找到目标媒体文件夹或无法继续。
6. 找到目标文件夹后，预览并清理目标文件夹内外的推广/文宣类垃圾项。
7. 预览并清理同层及上层解压目录中已处理的压缩包和分卷文件。
8. 确认目标文件夹无误且不在源文件夹内部后，删除最初的源文件夹。
9. 最后报告成功解压项、失败项、删除项、未识别目标文件夹、未找到密码的压缩包，以及已尝试密码。

## 密码候选顺序

按下面顺序尝试，并记录每个候选：

1. 固定首选密码：
   - `上老王论坛当老王`
2. 当前文件夹、密码提示根目录及其子目录、解压得到的某层文件夹名。
3. 空密码或无密码解压。
4. `common_passwords.txt` 中除首选密码之外的常用密码，以及脚本内置的兜底常用密码：
   - `@月暖如梵音`
   - `freeshare.com`
   - `11aa`
   - `123`
5. 用户通过 `--password` 明确给出的密码、`--password-file` 中的密码，以及当前目录或同层目录中 `.txt`、`.nfo`、`.url`、`.md` 等小文本文件内提取到的密码提示，例如 `密码:xxx`、`解压密码：xxx`、`password=xxx`、`pwd:xxx`。

脚本的 `extract` 命令默认严格按上面的优先级尝试密码。成功密码如果来自 `--password-hint-root` 扫描到的文本提示，或来自 `--password-file` 指向的密码文本文件，会自动追加到 `common_passwords.txt`。如果要把新增常用密码同步到其他电脑，提交并推送 `common_passwords.txt`。

## 后缀和分卷判断

优先用魔数判断：

- ZIP：文件头通常是 `PK`
- 7z：文件头通常是 `7z BC AF 27 1C`
- RAR：文件头通常是 `Rar!`

处理规则：

- `.exe` 文件按伪装 ZIP 处理：在 staging 中改为 `.zip`，不要把它当作 Windows 可执行文件运行或分析。
- `foo.png` 魔数是 ZIP：在 staging 中改为 `foo.zip`。
- `foo.pdf` 魔数是 7z：在 staging 中改为 `foo.7z`。
- `foo.mp4` 魔数是 RAR：在 staging 中改为 `foo.rar`。
- `foo.exe.001` 按 ZIP 分卷处理：整组改为 `foo.zip.001`、`foo.zip.002`。
- `foo.png.001` 第一分卷魔数是 ZIP：整组改为 `foo.zip.001`、`foo.zip.002`。
- 同一目录中出现多个 `.mp4` 时，检查文件名中的 `7z`、`zip`、`rar` 表述。例如 `foo.7z.001.mp4`、`foo.7z.002.mp4` 应改成 `foo.7z.001`、`foo.7z.002` 后继续解压。
- 后续分卷没有魔数时，根据 `.001` 的判断统一改名。
- 无法用魔数判断但高度可疑时，按 `.zip`、`.7z`、`.rar` 的顺序复制出候选名逐个测试，不覆盖原文件。

## 使用辅助脚本

脚本位于 `scripts/resource_unzip.py`，用于降低重复操作和漏记日志的概率。

扫描输入目录：

```bash
python3 scripts/resource_unzip.py scan /path/to/download --log resource-unzip-log.jsonl
```

把伪装文件复制或硬链接到 staging，并按魔数修正后缀：

```bash
python3 scripts/resource_unzip.py normalize /path/to/download --stage /path/to/staging --log resource-unzip-log.jsonl
```

尝试解压单个候选包：

```bash
python3 scripts/resource_unzip.py extract /path/to/staging/archive.zip --output /path/to/extracted/layer-1 --password-hint-root /path/to/download --password-file passwords.txt --log resource-unzip-log.jsonl
```

`--password-hint-root` 可重复传入，用于尝试目录名，并扫描当前目录、同层目录或上一层解压目录中的 `.txt`、`.nfo`、`.url`、`.md` 密码提示。常用密码会自动参与尝试；只有明确不想尝试常用密码时才加 `--no-common-passwords`。

找到目标文件夹后，先预览 `文宣`、`宣传`、`广告`、`推广` 等垃圾项：

```bash
python3 scripts/resource_unzip.py clean-junk /path/to/extracted --target /path/to/extracted/final-media --log resource-unzip-log.jsonl
```

确认列表中不是目标媒体后，再执行删除：

```bash
python3 scripts/resource_unzip.py clean-junk /path/to/extracted --target /path/to/extracted/final-media --apply --log resource-unzip-log.jsonl
```

找到目标文件夹后，先预览要删除的压缩包：

```bash
python3 scripts/resource_unzip.py cleanup /path/to/extracted --target /path/to/extracted/final-media --log resource-unzip-log.jsonl
```

确认列表中只有目标文件夹之外、本次解压链路的压缩包和分卷后，再执行删除：

```bash
python3 scripts/resource_unzip.py cleanup /path/to/extracted --target /path/to/extracted/final-media --apply --log resource-unzip-log.jsonl
```

确认最终目标文件夹可用后，预览删除最初源文件夹：

```bash
python3 scripts/resource_unzip.py delete-source /path/to/original-download-folder --target /path/to/extracted/final-media --log resource-unzip-log.jsonl
```

确认目标文件夹不在源文件夹内部，并且源文件夹不再需要后，执行删除：

```bash
python3 scripts/resource_unzip.py delete-source /path/to/original-download-folder --target /path/to/extracted/final-media --apply --log resource-unzip-log.jsonl
```

脚本会自动优先使用 `7z` 或 `7zz`，其次 `unar`，再退回到 Python ZIP 或 `bsdtar` 能处理的场景。即使 Codex 的 PATH 受限，也会额外查找 `~/.local/bin`、`/opt/homebrew/bin`、`/usr/local/bin`。缺少 `7z`/`7zz` 或 `unar` 时，RAR/7z 和加密 ZIP 可能无法完整处理；这时在日志中记录工具缺口，不要假装压缩包不可解。

## 判断是否完成

可以结束的条件：

- 已得到一个目标文件夹，里面有多个可正常打开的图片或视频；
- 该目标文件夹及其子目录中没有新的压缩包魔数、分卷文件或可疑单一大媒体文件；
- 解压日志中没有仍可继续处理的候选压缩包。
- 已删除确认无用的 `文宣`/推广类文件或文件夹。
- 已清理目标文件夹之外、本次解压链路中确认不再需要的压缩包和分卷文件。
- 已删除最初源文件夹；如果目标文件夹在源文件夹内部，则先把目标文件夹迁出再删除源文件夹，或跳过删除并报告原因。

需要继续排查的情况：

- 只得到一个图片或视频；
- 媒体文件体积异常大，或 `file` 显示其魔数不是对应媒体格式；
- 得到多个 `.mp4`，且文件名中仍包含 `7z`、`zip`、`rar` 等压缩格式表述；
- 文件夹里还有 `.001/.002`、无后缀大文件、伪装后缀文件、或疑似密码提示文本；
- 解压输出是另一个单文件，而不是最终媒体集合。

## 输出报告

完成任务时给用户简洁报告：

- 最终目标文件夹路径；
- 成功解压的文件和层级；
- 删除的 `文宣`/推广类文件或文件夹；
- 找到目标文件夹后删除的压缩包和分卷文件；
- 是否删除了最初源文件夹；如果没有，说明原因；
- 未能解压的文件、原因、已尝试密码；
- 未确认是否为最终目标的文件夹；
- 任何工具限制，例如缺少 `7z`、`unar` 或磁盘空间不足。
