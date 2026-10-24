# v0.1.0

Initial CLI and Python API for extraction-free ZIP filename portability checks.
Includes case/Unicode collisions at implicit directories, duplicate member indices,
file/directory conflicts, Win32 reserved names, unsafe paths, symlinks/special metadata,
length/resource limits and versioned escaped JSON reports. No runtime dependencies.

Validation: 16 unittest methods cover the documented policy and limits, clean/empty ZIPs,
original NUL/backslash spellings, report truncation, control-character escaping and CLI
exit codes. Monkeypatched member reads and extraction prove those APIs are unused.
A deliberately corrupted payload demonstrates that content integrity is outside scope.
Fresh wheel installation, the two generated README demos, lint/format and package builds
passed locally on Windows/Python 3.13. Release waits for all nine CI matrix jobs to pass.

Limits: portable-v1 is conservative, not exact filesystem emulation. It does not validate
payload CRCs, header agreement, expansion ratios, malware or an existing extraction target.
Reports contain filename samples. See README for default resource limits and their behavior.
