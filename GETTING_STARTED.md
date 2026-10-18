# Reference notes

Installation, the demo, and the lab walkthrough are in [README.md](README.md).
This file explains the options and checks in more detail.

## Command options

Choose exactly one mode: `--demo` or `--inventory PATH`.

| Option | Meaning |
| --- | --- |
| `--demo` | Read three fictional configurations without SSH or credentials |
| `--inventory PATH` | Connect only to entries in this YAML inventory |
| `--known-hosts PATH` | Load an additional trusted OpenSSH key file alongside the normal user file |
| `--prompt-password` | Force hidden input instead of using `SWITCH_AUDIT_PASSWORD` |
| `--ask-enable` | Ask for an optional enable secret if none is set in the environment |
| `--output-dir PATH` | Change the output parent; default is `artifacts/` next to `main.py` |
| `--help` | Show supported arguments |

The live path checks dependencies, inventory, and an explicitly supplied
trusted-key file before asking for passwords. YAML errors are reported without
printing source lines. Duplicate fields are rejected instead of silently
overwriting an address or other setting.

## Inventory and credentials

| Field | Required | Constraint |
| --- | --- | --- |
| `name` | Yes | Up to 64 letters, digits, underscores or hyphens; starts with a letter; unique ignoring case; no Windows reserved device names |
| `host` | Yes | One address or hostname; never expanded as a subnet or range |
| `device_type` | No | Only `cisco_ios`, also used for IOS XE |
| `port` | No | Integer from 1 to 65535; defaults to 22 |
| `username` | No | 1 to 128 letters, digits, `.`, `_`, `@` or `-` |

An inventory username takes precedence for that device. Entries without one
use `SWITCH_AUDIT_USERNAME` or a shared username prompt. The tool uses one shared
password per run, supplied through `SWITCH_AUDIT_PASSWORD` or a hidden prompt.
`--prompt-password` ignores that password environment variable.

`SWITCH_AUDIT_ENABLE_SECRET` supplies an optional enable secret. If absent,
`--ask-enable` asks through a hidden prompt; Enter skips it. The flag does not
override an enable secret already set in the environment.

There are no password or enable-secret command-line arguments. Inventory
password fields are rejected. Environment variables remain plaintext in process
memory, so prefer direct hidden prompts for interactive work. Do not put secrets
in shell commands or terminal session logs. SSH key or agent authentication
is not implemented in this CLI.

## Rules

| Rule ID | Severity | Check |
| --- | --- | --- |
| `VTY_TELNET` | high | A VTY `transport input` includes `telnet` or `all` |
| `VTY_REVIEW` | review | No recognized VTY section, or missing, conflicting, negated or unsupported transport settings in a present section |
| `PASSWORD_PLAINTEXT` | high | A recognized credential command has untyped plaintext or explicit type 0 |
| `PASSWORD_TYPE7` | high | A recognized credential command uses reversible type 7 encoding |
| `PASSWORD_REVIEW` | review | Incomplete, ambiguous or unsupported credential syntax, or a local user without an explicit password/secret |
| `DEFAULT_USERNAME` | potential | A local username matches the common-name list |
| `NO_ISSUES` | info | No issues found by implemented checks |
| `COLLECTION_ERROR` | error | Collection failed; inspect `collection_status` |

The case-insensitive common-name list is `admin`, `administrator`, `cisco`,
`root`, `guest`, and `user`. The `DEFAULT_USERNAME` ID is retained for existing
CSV users. It does not identify confirmed default credentials. No passwords
are tested against the switch.

The parser groups top-level commands with indented children and skips banners
and comments. It checks transport only inside VTY sections. Credential checks
cover global `username` and `enable` commands, plus line `password` commands in
VTY, console and auxiliary sections. Missing local credentials alone say little
about an external AAA service. Numeric untyped password values and unfamiliar
syntax can be ambiguous and are marked for review.

## Collection and files

The command is `show running-config`. Accepted output needs a hostname command
and a final `end` outside banner text. CLI diagnostics or pagination outside
banners are rejected. These checks cannot prove every configuration command
was returned, and unusual legitimate output may need manual inspection.

Each run creates a unique UTC-timestamped folder inside `demo/` or `live/`
under the output parent. It contains a `.cfg` per successful device and
`audit.csv`, with `device_name`, `collection_status`, `rule_id`, `severity`,
and `explanation`. There can be several rows per device.

| Collection status | Meaning |
| --- | --- |
| `success` | Output accepted and backup written |
| `authentication_failed` | SSH login failed |
| `timeout` | Connection or command read timed out |
| `host_key_untrusted` | Offered key absent from the trusted files |
| `host_key_changed` | Offered key differs from the trusted entry |
| `ssh_error` | Other SSH negotiation failure |
| `command_error` | Enable failed or output rejected |
| `io_error` | Network or file operation failed |
| `dependency_error` | Collection dependency could not be imported |
| `collection_error` | Unexpected collection failure |

Raw exception text is suppressed to protect secrets, which limits diagnostics.
Use local OpenSSH to investigate SSH failures. Do not respond to a key error
by disabling verification or deleting an entry without verifying device identity.

File creation is exclusive. Failed writes attempt to remove the incomplete
new file. If cleanup also fails, a partial file can remain in the private run
folder; it is not reported as a successful backup.

Windows run folders remove inherited ACL entries and grant the current user's
SID full control before collecting. Explicit SYSTEM, Administrators or owner
grants may remain. POSIX folders use 0700 and files use 0600. Permissions do
not encrypt a backup or restrict an administrator. Custom output parents must
also be trusted.

Exit 0 means all collections succeeded, even if findings exist. Exit 1 means
at least one collection failed. Exit 2 means a setup, interruption, report-write
or other run-level error. Earlier successful backups may remain if writing
the final report fails.

## Dependencies and test scope

`requirements.txt` pins the three directly imported third-party packages to
versions used for the Windows tests. Paramiko is listed directly because the
collector uses its SSH exception types. Transitive packages are not fully
locked. Pinning is not a security review or a guarantee of identical installations
on other operating systems.

Offline tests use fictional data, mock SSH connections and temporary files.
They do not contact the inventory. Passing them does not prove that a real
switch is reachable or will accept a password.
