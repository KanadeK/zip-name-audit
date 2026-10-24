import argparse
import json
import sys
import zipfile

from . import __version__
from .core import audit_zip


def main(argv=None):
    parser = argparse.ArgumentParser(description="Preflight ZIP names without extracting contents.")
    parser.add_argument("archive")
    parser.add_argument("--max-archive-bytes", type=int, default=33554432)
    parser.add_argument("--max-entries", type=int, default=50000)
    parser.add_argument("--max-depth", type=int, default=64)
    parser.add_argument("--max-nodes", type=int, default=200000)
    parser.add_argument("--max-path-units", type=int, default=240)
    parser.add_argument("--max-findings", type=int, default=1000)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--version", action="version", version=__version__)
    args = vars(parser.parse_args(argv))
    as_json = args.pop("as_json")
    path = args.pop("archive")
    try:
        report = audit_zip(path, **args)
    except (
        OSError,
        ValueError,
        UnicodeError,
        zipfile.BadZipFile,
        NotImplementedError,
        OverflowError,
    ):
        report = {"schema_version": 1, "ok": False, "error": "invalid_archive_or_limit"}
        if as_json:
            print(json.dumps(report, sort_keys=True))
        else:
            print(
                "Cannot audit: invalid/unreadable archive, unsupported metadata or limit exceeded.",
                file=sys.stderr,
            )
        return 2
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        print(
            f"{'PASS' if report['ok'] else 'FAIL'}: {report['entries']} entries, "
            f"{report['finding_count']} findings"
        )
        for item in report["findings"]:
            # JSON escapes control/bidi characters even in human output.
            sample = json.dumps(item["name_sample"], ensure_ascii=True)
            print(f"{item['code']} members={item['member_indices']} name={sample}")
        if report["findings_truncated"]:
            print("Findings truncated; increase --max-findings for more detail.")
    return 0 if report["ok"] else 1
