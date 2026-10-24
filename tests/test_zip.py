import json
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from zip_name_audit.core import AuditError, audit_names, audit_zip


class ZipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "sample.zip"

    def make(self, names):
        with warnings.catch_warnings(), zipfile.ZipFile(self.path, "w") as archive:
            warnings.simplefilter("ignore", UserWarning)
            for name in names:
                archive.writestr(name, "payload")
        return self.path

    def codes(self, **kwargs):
        return {item["code"] for item in audit_zip(self.path, **kwargs)["findings"]}

    def test_clean_and_empty(self):
        for names in ([], ["docs/", "docs/a.txt", "中文.txt", "emoji-😀.txt"]):
            self.make(names)
            self.assertTrue(audit_zip(self.path)["ok"])

    def test_implicit_directory_case_collision(self):
        self.make(["Docs/one.txt", "docs/two.txt"])
        report = audit_zip(self.path)
        self.assertFalse(report["ok"])
        finding = next(f for f in report["findings"] if f["code"] == "portable_collision")
        self.assertEqual(finding["member_indices"], [0, 1])
        self.assertEqual(finding["affected_members"], 2)

    def test_unicode_casefold_and_nfc(self):
        for names in (["café.txt", "cafe\u0301.txt"], ["Straße/a", "STRASSE/b"]):
            self.make(names)
            self.assertIn("portable_collision", self.codes())

    def test_duplicate_members(self):
        self.make(["same.txt", "same.txt"])
        self.assertIn("duplicate_member", self.codes())
        finding = next(
            f for f in audit_zip(self.path)["findings"] if f["code"] == "duplicate_member"
        )
        self.assertEqual(finding["member_indices"], [0, 1])

    def test_file_directory_and_prefix_conflict(self):
        for names in (["a", "a/b.txt"], ["a", "a/"], ["A", "a/b/c.txt"]):
            self.make(names)
            self.assertIn("file_directory_conflict", self.codes())

    def test_win32_names(self):
        self.make(["NUL.txt", "folder/COM¹.log", "Lpt9", "con .txt", "a:b", "trailing. "])
        codes = self.codes()
        self.assertTrue({"reserved_device", "reserved_character", "trailing_dot_or_space"} <= codes)
        findings = [f for f in audit_zip(self.path)["findings"] if f["code"] == "reserved_device"]
        self.assertEqual(len(findings), 4)

    def test_paths_controls_and_formats(self):
        self.make(
            ["/root/a", "C:/a", "../parent", "a/./b", "a//b", "escape\x1b.txt", "bidi\u202e.txt"]
        )
        self.assertTrue(
            {"absolute_path", "dot_component", "empty_component", "control_character"}
            <= self.codes()
        )

    def test_original_names_preserved(self):
        self.make(["dir/x.txt", "abcd.txt"])
        raw = (
            self.path.read_bytes()
            .replace(b"dir/x.txt", b"dir\\x.txt")
            .replace(b"abcd.txt", b"a\x00cd.txt")
        )
        self.path.write_bytes(raw)
        self.assertTrue(
            {"backslash_separator", "empty_or_nul_name", "control_character"} <= self.codes()
        )

    def test_symlink_special_and_marker(self):
        infos = []
        for name, kind in (
            ("link", stat.S_IFLNK),
            ("fifo", stat.S_IFIFO),
            ("dir", stat.S_IFDIR),
            ("file/", stat.S_IFREG),
        ):
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (kind | 0o644) << 16
            infos.append(info)
        codes = {f["code"] for f in audit_names(infos)["findings"]}
        self.assertTrue({"symlink", "special_file", "directory_marker_mismatch"} <= codes)

    def test_trailing_spelling_collision(self):
        self.make(["dir/report", "dir/report.", "dir/report "])
        self.assertIn("portable_collision", self.codes())

    def test_component_depth_and_length_limits(self):
        self.make(["a/b/c.txt", "x" * 256, "中" * 86])
        self.assertTrue(
            {"depth_limit", "component_length", "path_length"} <= self.codes(max_depth=2)
        )

    def test_resource_limits_fail_closed(self):
        self.make(["one/a", "two/b"])
        for options in (
            {"max_archive_bytes": 1},
            {"max_entries": 1},
            {"max_nodes": 1},
            {"max_findings": 0},
            {"max_depth": -1},
            {"max_path_units": 0},
        ):
            with self.subTest(options=options), self.assertRaises(AuditError):
                audit_zip(self.path, **options)

    def test_truncated_report_and_samples(self):
        self.make([f"CON/{n}.txt" for n in range(25)] + ["a" * 300])
        report = audit_zip(self.path, max_findings=1)
        self.assertFalse(report["ok"])
        self.assertTrue(report["findings_truncated"])
        self.assertGreater(report["finding_count"], len(report["findings"]))
        self.make(["a" * 300])
        report = audit_zip(self.path)
        self.assertTrue(all(f["name_truncated"] for f in report["findings"]))
        self.assertTrue(all(len(f["name_sample"]) == 256 for f in report["findings"]))
        self.make([f"Docs/{n}" for n in range(25)] + ["docs/z"])
        collision = next(
            f for f in audit_zip(self.path)["findings"] if f["code"] == "portable_collision"
        )
        self.assertEqual(collision["affected_members"], 26)
        self.assertEqual(len(collision["member_indices"]), 20)

    def test_no_content_reads_or_extraction(self):
        self.make(["good/a.txt"])
        original = self.path.read_bytes()
        with (
            patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("member read")),
            patch.object(zipfile.ZipFile, "extract", side_effect=AssertionError("extraction")),
            patch.object(zipfile.ZipFile, "extractall", side_effect=AssertionError("extraction")),
        ):
            self.assertTrue(audit_zip(self.path)["ok"])
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_corrupt_payload_not_claimed_as_integrity_check(self):
        self.make(["good.txt"])
        self.path.write_bytes(self.path.read_bytes().replace(b"payload", b"tamper!"))
        self.assertTrue(audit_zip(self.path)["ok"])
        with zipfile.ZipFile(self.path) as archive:
            self.assertEqual(archive.testzip(), "good.txt")

    def test_cli_exit_codes_and_escaped_output(self):
        command = [sys.executable, "-m", "zip_name_audit", str(self.path)]
        self.make(["normal.txt"])
        result = subprocess.run(command + ["--json"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["ok"])
        self.make(["bad\x1b\u202e.txt"])
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("\x1b", result.stdout)
        self.assertNotIn("\u202e", result.stdout)
        self.path.write_bytes(b"not an archive")
        result = subprocess.run(command + ["--json"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
