# Design and acceptance

Target users are archive distributors and maintainers of cross-platform datasets.
MVP: inspect one ZIP, apply portable-v1, report exact member positions and stable rule IDs,
and return an automation-friendly exit code. No extraction or automatic renaming exists.

The original decoded central-directory spelling is used, including names ZipInfo may
truncate at NUL or normalize on Windows. A normalized component trie tracks both explicit
and implicit directories. Different raw spellings on the same normalized node are collisions;
files and directory uses at the same node conflict. Iterative traversal avoids recursion limits.
Archive bytes, parsed entries, path depth, nodes and detailed findings have explicit limits.

Acceptance: clean and empty ZIPs pass; duplicate/case/Unicode/Win32/control/path/symlink
fixtures fail with the expected rules; implicit directory and file-prefix cases are covered;
limit failures cannot pass; monkeypatching member reads/extraction to raise still permits
an audit; a header-only archive with a corrupt payload is auditable because this tool
intentionally does not claim content integrity. Fresh installation runs both synthetic demos.

No third-party implementation is reused. This is a conservative policy, not a parser-differential
or malware scanner. Names and metadata are untrusted; human output uses JSON string escaping.
