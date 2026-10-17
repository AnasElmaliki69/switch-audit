# Validation performed on 2026-10-10

- Python 3.12.14 on Windows; Netmiko 4.8.0 and PyYAML 6.0.3.
- `python -m unittest discover -s tests -v`: **22 tests passed**.
- `python main.py --demo`: **exit 0**, three successful fictional backups and CSV output.
- The standalone demo also ran without Netmiko/PyYAML on its import path.
- Windows run folder/file ACLs were inspected: the run folder grants the current
  user full control and backup files inherit restricted grants. This environment
  also retains explicit SYSTEM, Administrators and OWNER RIGHTS grants; no
  Everyone, Users or Authenticated Users grants were present.

Expected findings matched the output: secure = no issues found by implemented
checks; insecure = 2 Telnet, 3 plaintext, 1 type 7, 1 potential common/default
username; ambiguous = 2 VTY reviews and 1 password encoding review.

Tests cover mocked collection, including strict host-key options, changed-key
rejection, hidden-prompt fallback refusal, empty/error/truncated responses,
authentication/read/command failures, and continuing to subsequent devices.

No live switches were contacted. Live SSH behavior remains unverified until
tested against an authorized IOS/IOS XE switch. POSIX permissions are implemented
and have an OS-conditional test, but were not executed on this Windows host.
Configuration analysis cannot prove port reachability or use of a default password.

## Windows lab integration checks — 2026-10-18

- Created a project `.venv` using Python 3.12.14 and installed requirements
  (Netmiko 4.8.0, Paramiko 5.0.0, PyYAML 6.0.3).
- `python -m unittest discover -s tests -v`: **28 tests passed**.
- `python main.py --demo`: **exit 0**, all three fictional collections passed
  and the expected secure/insecure/ambiguous findings were preserved.
- `python -m pip check`: **No broken requirements found**.
- Added regression coverage for optional inventory usernames, password prompt
  precedence and redaction, unknown/changed SSH keys, and IOL-L2 configurations
  with SSH-only VTY 0-4 and no additional VTY lines.
- Live endpoint readiness is recorded separately in Git-ignored artifacts.
  No authenticated lab collection was performed: this process had no switch
  password. TCP/SSH handshake success is not evidence of successful login,
  a configuration backup, or a live audit report.
