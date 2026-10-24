"""Conservative portable-name policy, independent of the host filesystem."""

import os
import re
import stat
import unicodedata
import zipfile
from pathlib import Path

RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    prefix + suffix for prefix in ("COM", "LPT") for suffix in "123456789¹²³"
}


class AuditError(ValueError):
    """Invalid archive, metadata limit, or policy configuration."""


def canonical(component):
    return unicodedata.normalize(
        "NFC", unicodedata.normalize("NFC", component.rstrip(" .")).casefold()
    )


def units(value):
    return len(value.encode("utf-16-le")) // 2


class Node:
    def __init__(self, spelling=""):
        self.children = {}
        self.spelling = spelling
        self.variants = False
        self.indices = []
        self.count = 0
        self.files = 0
        self.directories = 0

    def add(self, spelling, index, directory):
        self.variants |= spelling != self.spelling
        self.count += 1
        if len(self.indices) < 20:
            self.indices.append(index)
        if directory:
            self.directories += 1
        else:
            self.files += 1


def audit_names(
    infos,
    *,
    max_entries=50000,
    max_depth=64,
    max_nodes=200000,
    max_path_units=240,
    max_findings=1000,
):
    """Inspect ZipInfo metadata only. No members are opened or extracted."""
    limits = (max_entries, max_depth, max_nodes, max_path_units, max_findings)
    if any(not isinstance(n, int) or n <= 0 for n in limits):
        raise AuditError("limits must be positive integers")
    if len(infos) > max_entries:
        raise AuditError("entry limit exceeded")
    root = Node()
    nodes = 0
    findings = []
    finding_count = 0

    def issue(code, indices, name, *, affected=1):
        nonlocal finding_count
        finding_count += 1
        if len(findings) < max_findings:
            findings.append(
                {
                    "code": code,
                    "member_indices": indices,
                    "affected_members": affected,
                    "name_sample": name[:256],
                    "name_truncated": len(name) > 256,
                }
            )

    seen = {}
    for index, info in enumerate(infos):
        # orig_filename preserves NUL/backslash spellings that ZipInfo may alter.
        raw = info.orig_filename
        if raw in seen:
            issue("duplicate_member", [seen[raw], index], raw, affected=2)
        else:
            seen[raw] = index
        codes = set()
        if not raw or "\0" in raw:
            codes.add("empty_or_nul_name")
        if raw.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", raw):
            codes.add("absolute_path")
        if "\\" in raw:
            codes.add("backslash_separator")
        name = raw.replace("\\", "/")
        directory = name.endswith("/")
        parts = name[:-1].split("/") if directory else name.split("/")
        if len(parts) > max_depth:
            codes.add("depth_limit")
        if units(name) > max_path_units:
            codes.add("path_length")
        for part in parts:
            if not part:
                codes.add("empty_component")
            if part in {".", ".."}:
                codes.add("dot_component")
            if any(unicodedata.category(c) in {"Cc", "Cf"} for c in part):
                codes.add("control_character")
            if any(c in '<>:"|?*' for c in part):
                codes.add("reserved_character")
            if part.endswith((".", " ")):
                codes.add("trailing_dot_or_space")
            if part.split(".")[0].rstrip(" ").upper() in RESERVED:
                codes.add("reserved_device")
            if len(part.encode("utf-8")) > 255 or units(part) > 255:
                codes.add("component_length")
        mode = info.external_attr >> 16 if info.create_system == 3 else 0
        kind = stat.S_IFMT(mode)
        if kind == stat.S_IFLNK:
            codes.add("symlink")
        elif kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
            codes.add("special_file")
        if kind == stat.S_IFDIR and not directory:
            codes.add("directory_marker_mismatch")
        if kind == stat.S_IFREG and directory:
            codes.add("directory_marker_mismatch")
        for code in sorted(codes):
            issue(code, [index], raw)
        if len(parts) > max_depth:
            continue  # Already fails. Avoid constructing an unbounded-depth trie.
        node = root
        for position, part in enumerate(parts):
            key = canonical(part)
            if key not in node.children:
                nodes += 1
                if nodes > max_nodes:
                    raise AuditError("path node limit exceeded")
                node.children[key] = Node(part)
            node = node.children[key]
            node.add(part, index, position < len(parts) - 1 or directory)

    pending = list(root.children.values())
    while pending:
        node = pending.pop()
        pending.extend(node.children.values())
        if node.variants:
            issue("portable_collision", node.indices, node.spelling, affected=node.count)
        if node.files and node.directories:
            issue("file_directory_conflict", node.indices, node.spelling, affected=node.count)
    return {
        "schema_version": 1,
        "policy": "portable-v1",
        "ok": finding_count == 0,
        "entries": len(infos),
        "path_nodes": nodes,
        "finding_count": finding_count,
        "findings_truncated": finding_count > len(findings),
        "findings": findings,
        "limits": {
            "max_entries": max_entries,
            "max_depth": max_depth,
            "max_nodes": max_nodes,
            "max_path_units": max_path_units,
            "max_findings": max_findings,
        },
    }


def audit_zip(path, *, max_archive_bytes=33554432, **kwargs):
    """Bound archive bytes before parsing the central directory."""
    if max_archive_bytes < 1:
        raise AuditError("archive byte limit must be positive")
    with Path(path).open("rb") as stream:
        if os.fstat(stream.fileno()).st_size > max_archive_bytes:
            raise AuditError("archive byte limit exceeded")
        with zipfile.ZipFile(stream) as archive:
            report = audit_names(archive.infolist(), **kwargs)
    report["limits"]["max_archive_bytes"] = max_archive_bytes
    return report
