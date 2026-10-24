# zip-name-audit

Check ZIP filenames before shipping an archive to users on another operating system.
Detect names that collide or fail under a conservative Windows/macOS/Linux portability
policy, **without extracting or reading member contents**. Python 3.11+, no runtime dependencies.

## Install and try

```sh
git clone https://github.com/KanadeK/zip-name-audit.git
cd zip-name-audit
python -m venv .venv
# POSIX:
.venv/bin/python -m pip install .
.venv/bin/python examples/make_demo.py demo-output
.venv/bin/zip-name-audit demo-output/good.zip
.venv/bin/zip-name-audit demo-output/problem.zip --json
```

Windows PowerShell: use `.venv\Scripts\python.exe` and `.venv\Scripts\zip-name-audit.exe`.
With an activated environment, `python -m zip_name_audit` also works.
The first audit prints `PASS` and exits `0`. The second exits `1`, reporting the implicit
directory spelling collision `Guide`/`guide`, reserved `NUL.txt`, and the conflict between
file `assets` and directory `assets/`. The generator refuses to overwrite existing archives;
use a new output directory for another run. All data is synthetic.

## What it checks

| Rule | Example |
|---|---|
| `portable_collision` | `Readme.txt` / `README.txt`; composed/decomposed accents; implicit `Docs/a` / `docs/b` |
| `duplicate_member` | Two central-directory members with exactly the same original name |
| `file_directory_conflict` | File `a` alongside `a/b.txt` or explicit `a/` |
| `absolute_path`, `dot_component` | `/etc/file`, drive paths, `../file`, `a/./b` |
| `backslash_separator`, `empty_component` | Backslash paths, `a//b`, empty path components |
| `reserved_device` | `CON`, `nul.txt`, `LPT¹.log`, reserved components anywhere in a path |
| `reserved_character`, `trailing_dot_or_space` | `a:b`, `report.`, `folder /x` |
| `empty_or_nul_name`, `control_character` | NUL, terminal escapes, bidi/format control characters |
| `component_length`, `path_length`, `depth_limit` | Oversized UTF-8/UTF-16 components, relative path budget, excess depth |
| `symlink`, `special_file`, `directory_marker_mismatch` | Unix links/devices/FIFOs or conflicting directory metadata |

`portable-v1` trims trailing dots/spaces, applies Unicode NFC, casefolds, then applies NFC
again to each component for collision detection. This intentionally errs on the side of
reporting risk; it does not emulate NTFS, APFS, HFS+, 8.3 aliases or every extraction tool.
Directory spelling collisions are reported even when the leaf files differ, so casing
is not silently dependent on extraction order.

## Limits and reports

| Option | Default | Meaning |
|---|---:|---|
| `--max-archive-bytes` | 33554432 | Input archive size bound, checked before central-directory parsing |
| `--max-entries` | 50000 | Maximum parsed members |
| `--max-depth` | 64 | Per-name component count; exceeding it is a finding |
| `--max-nodes` | 200000 | Maximum distinct normalized path components in the trie |
| `--max-path-units` | 240 | Relative member name budget in UTF-16 code units |
| `--max-findings` | 1000 | Maximum detailed findings; summary still counts all detected findings |
| `--json` | off | Versioned JSON on stdout |

All numeric limits must be positive. Archive/entry/node limit failures return `2`; they
never produce a passing report. The entry limit applies after zipfile parses metadata;
the archive byte limit is the earlier bound. Large legitimate ZIPs may require raising it.

Exit codes: `0` no policy findings, `1` policy findings (including truncated reports),
`2` invalid input, unsupported/malformed metadata or a resource limit prevents a full audit.
Member indices are zero-based central-directory positions. Each collision lists at most
20 member indices and a total affected count. Name samples are capped at 256 characters;
`name_truncated` marks this. Text output also escapes control characters. Reports contain
filenames, which may themselves be sensitive.

## Why this tool and its boundary

[Python zipfile](https://docs.python.org/3/library/zipfile.html) lists/tests archive contents.
[wheelaudit](https://github.com/kriskimmerle/wheelaudit) targets Python wheel security.
This tool focuses on arbitrary ZIP **delivery names**, including implicit directories,
with consistent offline policy and CI exit codes. The problem is real: see the
[RLEAPP overwrite report](https://github.com/abrignoni/RLEAPP/issues/416) and
[Microsoft filename rules](https://learn.microsoft.com/windows/desktop/FileIO/naming-a-file).

A passing result is a filename-policy check. It does not verify CRC, compressed data,
local/central header agreement, signatures, malware, expansion ratios, destination-disk
collisions or extractor behavior. It never extracts, repairs, renames or modifies an archive.
Compressed payload sizes do not need to be trusted because payloads are not decompressed.
Input files must remain stable during the audit. No network or telemetry is used.

## Test and cleanup

See [CONTRIBUTING.md](CONTRIBUTING.md) for tests, lint and build commands and
[design notes](docs/design.md) for acceptance. `python -m pip uninstall zip-name-audit`
removes the package; deleting its dedicated `.venv` removes an isolated install.
The auditor creates no files. Remove only the synthetic `demo-output` directory when done.

MIT. [Security](SECURITY.md) · [Third-party licenses](THIRD_PARTY.md).

## 中文说明

在发布 ZIP 前，离线检查大小写/Unicode 名称冲突、Windows 保留名称、目录与文件冲突、
危险路径及符号链接等问题。无需解压，不读取压缩内容，也不修改原文件。
示例第一份 ZIP 通过，第二份应失败；退出码 0/1/2 分别代表通过、发现问题、无法完成检查。
该策略偏保守，包含隐式目录名称检查，不能保证所有文件系统或解压工具的行为一致，
也不代替病毒扫描或 CRC 校验。报告中的文件名可能敏感，分享前请检查。
