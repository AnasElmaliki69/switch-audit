# switch-audit

A small, beginner-friendly, read-only Python project for Cisco IOS and IOS XE
switches. It saves `show running-config` backups and reports a few potentially
insecure settings. Start with the fictional demo: it makes **no network
connections** and requires **no credentials**.

Python 3.10 or newer is required. These commands assume a terminal opened in
this `switch-audit` folder. The short README also covers the Windows CML lab.

## Windows PowerShell

Install Python 3.10+ with the Python launcher if `py` is unavailable. Use the
virtual environment's interpreter directly; activation and execution-policy
changes are unnecessary.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py --demo
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Prepare your own inventory and verified host keys as described below, then:

```powershell
Copy-Item devices.example.yaml devices.yaml
notepad devices.yaml
.\.venv\Scripts\python.exe main.py --inventory devices.yaml --known-hosts "$HOME\.ssh\known_hosts"
# If the login account needs an enable secret:
.\.venv\Scripts\python.exe main.py --inventory devices.yaml --known-hosts "$HOME\.ssh\known_hosts" --ask-enable
```

## macOS / Linux

Install Python 3.10+ with your usual OS tools. On some Linux distributions the
Python venv package must also be installed.

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python main.py --demo
./.venv/bin/python -m unittest discover -s tests -v
cp devices.example.yaml devices.yaml
# Edit devices.yaml in your preferred text editor before running live mode.
./.venv/bin/python main.py --inventory devices.yaml --known-hosts "$HOME/.ssh/known_hosts"
# If needed:
./.venv/bin/python main.py --inventory devices.yaml --known-hosts "$HOME/.ssh/known_hosts" --ask-enable
```

If your virtual environment is activated, the shorter commands are:

```text
python main.py --demo
python -m unittest discover -s tests -v
python main.py --inventory devices.yaml
```

## Inventory and authorization

Run live mode only against switches you are authorized to access. The example
uses fictional documentation addresses. Replace them before a live run.

```yaml
devices:
  - name: lab-access-01
    host: 192.0.2.10
    port: 22
    device_type: cisco_ios
```

Only `name`, `host`, optional `port` (default 22), optional `device_type`
(only `cisco_ios`), and optional `username` are accepted. A username is an
account identifier, not a password. Passwords and enable secrets are forbidden
in the inventory. Netmiko uses this driver for both IOS and IOS
XE. Names must start with a letter, use letters/digits/underscores/hyphens and
be unique ignoring case. Reserved Windows filenames are rejected. Hosts must
be individual IP addresses or DNS names, never subnets or ranges. The complete
inventory is validated before SSH. Only its listed hosts receive connection
attempts, sequentially. DNS names use the system resolver; use literal IPs if
you need an exact endpoint allowlist.

No discovery, network scans, default-password login attempts, or configuration
changes are performed. Netmiko may issue normal session preparation commands
to disable paging/set terminal width and, if requested, enter enable mode.
The configuration collection command is `show running-config`.

## Credentials

An inventory `username` takes precedence for that device. For entries without
one, the tool uses `SWITCH_AUDIT_USERNAME` or prompts for a shared username.
Password input is hidden with Python's `getpass`. Add `--prompt-password` to
force the hidden prompt even if `SWITCH_AUDIT_PASSWORD` is set.
Add `--ask-enable` to hide-prompt for an optional enable
secret (Enter skips it). If the account already has sufficient privilege, no
enable secret is necessary. Prompts occur once and the credentials are used
for each listed device.

If a hidden prompt is unavailable (for example in a redirected/noninteractive
terminal), the run stops instead of falling back to visibly echoed input.
Use a normal interactive terminal or the environment variables below.

Alternatively supply `SWITCH_AUDIT_USERNAME`, `SWITCH_AUDIT_PASSWORD`, and
optionally `SWITCH_AUDIT_ENABLE_SECRET` in the process environment. There are
no password command-line flags or inventory password fields. Avoid typing
secrets into shell commands, which can retain them in history. These examples
set the password from a hidden prompt:

```powershell
$env:SWITCH_AUDIT_USERNAME = Read-Host 'SSH username'
$securePassword = Read-Host 'SSH password' -AsSecureString
$credential = [System.Management.Automation.PSCredential]::new($env:SWITCH_AUDIT_USERNAME, $securePassword)
$env:SWITCH_AUDIT_PASSWORD = $credential.GetNetworkCredential().Password
.\.venv\Scripts\python.exe main.py --inventory devices.yaml
Remove-Item Env:SWITCH_AUDIT_USERNAME, Env:SWITCH_AUDIT_PASSWORD -ErrorAction SilentlyContinue
Remove-Item Env:SWITCH_AUDIT_ENABLE_SECRET -ErrorAction SilentlyContinue
$credential = $null
$securePassword = $null
```

```bash
read -r -p 'SSH username: ' SWITCH_AUDIT_USERNAME
read -r -s -p 'SSH password: ' SWITCH_AUDIT_PASSWORD; printf '\n'
export SWITCH_AUDIT_USERNAME SWITCH_AUDIT_PASSWORD
./.venv/bin/python main.py --inventory devices.yaml
unset SWITCH_AUDIT_USERNAME SWITCH_AUDIT_PASSWORD SWITCH_AUDIT_ENABLE_SECRET
```

The second block uses Bash. Environment variables still contain plaintext
secrets in process memory; prefer the tool's direct prompts for interactive
use. Never commit secrets or debug/session logs. The project does not enable
Netmiko session logging and does not print raw exceptions or configuration
lines in reports.

## Trust SSH host keys first

Host-key verification is mandatory. Connections use Netmiko's
`ssh_strict=True` and `system_host_keys=True`; unknown or changed keys are
rejected. The normal `~/.ssh/known_hosts` is loaded. `--known-hosts PATH` loads
an additional OpenSSH-format trusted-key file. There is no insecure bypass.
These settings are described in the [Netmiko API documentation](https://ktbyers.github.io/netmiko/docs/netmiko/base_connection.html).

Before running live mode, obtain the switch's SSH host-key fingerprint from
your administrator or a separately trusted console/management channel. With
an installed OpenSSH client, connect to that *specific authorized host*:

```text
ssh -p 22 your-authorized-user@your-authorized-switch
```

Compare the displayed SHA256 fingerprint to your independently verified
fingerprint. Accept the key only when they match, then exit the session. This
creates a trusted `known_hosts` entry. Use the same hostname/IP and port as
the inventory; a nonstandard port entry uses `[host]:port`. An administrator
can instead provision the verified OpenSSH key entry directly. A changed key
requires independent verification before updating the trusted file. Do not
blindly accept keys or trust unverified `ssh-keyscan` output.

## Findings and limits

| Rule ID | Severity | What it means |
| --- | --- | --- |
| `VTY_TELNET` | high | An explicit VTY `transport input` permits `telnet` or `all`, including mixed lists. |
| `VTY_REVIEW` | review | A VTY section/transport setting is absent, conflicting, negated, or unsupported. |
| `PASSWORD_PLAINTEXT` | high | A recognized credential command has an untyped plaintext password/secret or explicit type 0. |
| `PASSWORD_TYPE7` | high | A recognized credential command uses Cisco reversible type 7 encoding. |
| `PASSWORD_REVIEW` | review | Recognized credential syntax/encoding is incomplete or unsupported, or a local username has no explicit password/secret. |
| `DEFAULT_USERNAME` | potential | A local username matches a common-name list; this is **not** proof of default credentials. |
| `COLLECTION_ERROR` | error | Collection failed; its status gives the category. |
| `NO_ISSUES` | info | No issues found by implemented checks. |

The case-insensitive common-name list is **admin, administrator, cisco, root,
guest, user**. It is a small heuristic, not a vendor database. Legitimate
administrators can use these names. Findings never include account names,
passwords, hashes, or other secret values.

The parser groups top-level commands with indented children. It examines
transport settings only in `line vty` sections, credential commands in global
`username`/`enable` settings, and `password` commands in VTY/console/aux line
sections. Comments, descriptions and banner contents are ignored. Type 5/8/9
credential encodings are recognized without declaring their strength or
checking hashes. Other encodings need review. Missing transport settings are
not assigned assumed IOS defaults, which vary by software/platform. Only
present VTY sections are checked: an SSH-only `line vty 0 4` section does not
require additional VTY lines 5-15. See the
[Cisco terminal services command reference](https://www.cisco.com/c/en/us/td/docs/ios/termserv/command/reference/tsv_book/tsv_s1.html).

This is a focused audit, not a full IOS parser or compliance engine. It does
not audit SNMP communities, routing protocol keys, AAA policies, ACLs,
management VRFs, certificates, password strength, or every possible Cisco
credential syntax. Missing local/enable credentials alone do not prove unsafe
authentication: AAA and privilege policies need separate review. Configuration
analysis **cannot prove a port is reachable or a default password is in use**.
Even the secure demo only yields **“No issues found by implemented checks.”**

## Backups, reports, and failures

Each run creates a unique UTC timestamped folder under `artifacts/demo/` or
`artifacts/live/`. It contains one `.cfg` backup per successful device and an
`audit.csv` report. Override the parent with `--output-dir PATH`. The CSV has
`device_name`, `collection_status`, `rule_id`, `severity`, `explanation`; a
device can have multiple rows. The same findings appear in the terminal.

Backups contain **sensitive full configurations**, including credentials.
Treat them as secrets even though reports omit those values. POSIX run folders
use mode 0700 and files use 0600. On Windows, before writing any backup, the
tool removes inherited permissions on each new run folder and grants the
current user's SID full control; files inherit this restricted ACL. Windows
may retain privileged SYSTEM, Administrators and owner-related explicit grants
on the newly created folder. The tool
stops before collection if it cannot establish that folder protection. Use a
local filesystem that supports permissions/ACLs. Administrator access, cloud
sync, archive copies, and filesystem limitations still require care. Do not
place output in a shared or untrusted parent folder. No automatic deletion or
retention policy is implemented.

Authentication failures, connection/read timeouts, SSH host-key failures,
enable/command failures, and file errors are recorded per device; the next
listed device is still attempted. Empty output, CLI diagnostics, pagination,
and output lacking an IOS `hostname` and final `end` marker are rejected.
This conservative completeness check can reject unusual legitimate output:
review the device manually rather than accepting a partial backup. Exception
details are deliberately suppressed to avoid leaking secrets.

Exit codes: **0** means all collections succeeded (findings may exist), **1**
means at least one device failed collection, **2** means setup, inventory,
report-writing, or other run-level failure/interruption. Existing backups from
successful devices can remain if writing the final report fails.

`.gitignore` excludes real YAML inventories, credentials, trusted-key files,
backups, reports, generated configs and virtual environments. Only the example
inventory and fictional demo configs are allowlisted. Review every staged file
before committing; ignore rules cannot protect files already tracked by Git.

## Expected demo and tests

The fixtures are fictional, including all placeholder passwords and hashes:

| Device | Expected result |
| --- | --- |
| `demo-secure` | No issues found by implemented checks. |
| `demo-insecure` | 2 Telnet findings, 3 plaintext password findings, 1 type 7 finding, 1 potential common/default username finding. |
| `demo-ambiguous` | 2 VTY review findings and 1 password encoding review finding. |

Tests use mock SSH connections and temporary files, **never live switches**.
They check section boundaries, banner/description false positives, redaction,
credential formats, invalid inventories, private storage, strict host-key
options, continuation after errors, and rejection of empty/error/partial
outputs. The demo path is checked with network and credential prompts blocked.

**Live SSH behavior remains unverified until tested against an authorized
switch.** Test with a small authorized inventory first, verify host keys,
confirm the backup is complete, and compare findings with the actual config.

## Code map

- `main.py`: command-line modes, prompts, terminal output, CSV.
- `audit/inventory.py`: validates the explicit device allowlist.
- `audit/collection.py`: collects each config, validates output, handles failures.
- `audit/rules.py`: small section-aware checks and safe finding text.
- `audit/storage.py`: timestamped private folders and exclusive file creation.
- `demo/`: fictional configs; `tests/`: offline unittest tests.
