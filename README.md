# switch-audit

This is a small Python network automation project. It saves a Cisco switch's
running configuration and checks a few settings that deserve a closer look.
The aim is to make the same checks repeatable without reading the entire
configuration by hand each time.

It supports Cisco IOS and IOS XE through Netmiko over SSH. You can try it with
fictional configurations before connecting to a switch.

## What it does

1. Reads an explicit YAML inventory and validates it before connecting.
2. Verifies the switch's SSH host key and logs in with your credentials.
3. Runs `show running-config` and rejects empty, erroneous or incomplete output.
4. Saves a backup in a private folder named with a UTC timestamp.
5. Prints findings and writes an `audit.csv` report in the same folder.

The checks look for Telnet permitted in VTY sections, explicit plaintext
passwords, Cisco type 7 passwords, and local usernames from a small common-name
list. Missing or unsupported settings are marked for review where the parser
cannot establish their meaning.

A configuration permitting Telnet does not prove that its port is reachable.
A username such as `admin` does not prove that a default password is in use.
These are configuration findings, not confirmed vulnerabilities.

## Try the demo

Use Python 3.10 or newer. Open a terminal in the folder containing `main.py`.
On Windows, `py -3` refers to the installed Python launcher. If it is unavailable,
use the path to your installed Python interpreter to create the environment.
If `.venv` already exists, reuse it and skip the first command.

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py --demo
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

macOS or Linux:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python main.py --demo
./.venv/bin/python -m unittest discover -s tests -v
```

The demo uses only files in `demo/`. It makes no network connections and asks
for no credentials. Its expected results are:

| Sample | Result |
| --- | --- |
| `demo-secure` | No issues found by implemented checks |
| `demo-insecure` | Two Telnet findings, three plaintext password findings, one type 7 finding, one potential common-username issue |
| `demo-ambiguous` | Two VTY settings and one password encoding marked for review |

An activated environment also lets you use `python main.py --demo`.
Use `python main.py --help` to see all options.

## Connect to an authorized switch

All addresses in the public examples are fictional documentation addresses.
Replace them with your authorized switch's current address before a live run.
The program does not discover devices, expand subnets, or try default passwords.

In PowerShell, make a local inventory:

```powershell
Copy-Item devices.example.yaml devices.local.yaml
notepad devices.local.yaml
```

Keep only the devices you intend to contact. For example:

```yaml
devices:
  - name: lab-access-01
    host: 192.0.2.10
    device_type: cisco_ios
    username: laboperator
    port: 22
```

The account name can be in the inventory. Passwords and enable secrets cannot.
The complete inventory is validated before SSH. If you use a DNS name, your
system resolver decides which address it reaches.

Before connecting, obtain the switch's SSH host-key fingerprint through a
separately trusted console or administrator. Connect with OpenSSH and compare
the offered fingerprint with that trusted fingerprint:

```powershell
ssh -o StrictHostKeyChecking=ask -p 22 laboperator@192.0.2.10
```

Accept only a matching key, log in locally, then exit. This creates an entry
in `$HOME\.ssh\known_hosts`. Key size and SSH version alone do not verify
the device's identity. Do not blindly trust `ssh-keyscan` output.

Then run the backup and audit:

```powershell
.\.venv\Scripts\python.exe main.py --inventory devices.local.yaml --known-hosts "$HOME\.ssh\known_hosts" --prompt-password
```

`--prompt-password` uses hidden `getpass` input, even if a password environment
variable is set. Input stops if a hidden prompt is unavailable. Add
`--ask-enable` if the account requires a separate enable secret. A privilege 15
account normally does not need that step.

For macOS or Linux, use the same options with `./.venv/bin/python` and
`"$HOME/.ssh/known_hosts"`. Further options and credential details are in
[GETTING_STARTED.md](GETTING_STARTED.md).

## Reading a result

This is a sanitized example using a fictional device name:

```csv
device_name,collection_status,rule_id,severity,explanation
lab-access-01,success,VTY_TELNET,high,line vty 4: transport input permits Telnet in the configuration; reachability is unverified.
```

`success` means configuration collection and backup succeeded. It does not
mean the settings are secure. A device can have several finding rows. When
none of the implemented checks finds an issue, the report says
`No issues found by implemented checks`.

Each run writes a new folder under `artifacts/live/` or `artifacts/demo/`.
Open the CSV in the folder printed by that run, rather than an older report.
Exit code 0 means collections succeeded, 1 means a device failed collection,
and 2 means the run stopped because of a setup or run-level error. Findings
alone do not change the exit code to 1.

## The lab and what was tested

I used a Windows lab with VMware Workstation, CML Free 2.10.1, and an IOL-L2
switch running IOL L2 XE 17.18.02. The recorded setup uses VMware NAT and a
CML External Connector configured as `System Bridge / bridge0`.

Windows connects directly to the switch's Vlan1 management IP on TCP 22.
The CML server's management IP is a different endpoint. Vlan1 gets its address
through DHCP, so the inventory may need updating after a restart.

Local backups and CSV reports support a successful SSH-only collection, a
Telnet finding on VTY 4 during a controlled change, and a later SSH-only result
after that setting was restored. A separate run recorded a timeout. Those
private artifacts were reviewed, but are not committed. The public example
above is reconstructed and sanitized, not a raw switch backup.

The IOL image accepted VTY lines 0-4. The tool checks the sections present and
does not require VTY lines 5-15. Offline tests use fictional text and mocked
connections; they are separate from these live lab results. See
[VALIDATION.md](VALIDATION.md) for the scope of the evidence and remaining gaps.

### What I practiced

The lab exercise connected SSH access, Python command collection, and reading
VTY settings in a real running configuration. The Telnet test also showed why
a backup is a snapshot: an earlier CSV still described the earlier settings.
The finding identifies a configuration choice; it does not test whether a
Telnet connection can actually reach the switch.

### Troubleshooting the lab

| Symptom | What to check |
| --- | --- |
| Unreachable or timeout | Check the node is running, Vlan1 is up/up, and the External Connector reaches VMware NAT. Test only the intended endpoint with `Test-NetConnection -ComputerName 192.0.2.10 -Port 22`, replacing the fictional IP. |
| Address changed | Read `show ip interface brief` in the CML switch console, update the local inventory, and verify the device identity at the new address. |
| Authentication failed | Check the account and password using OpenSSH in your own terminal. Do not put a password in the inventory. |
| Unknown host key | Verify the fingerprint through the trusted console and enroll it with OpenSSH. |
| Changed host key | Check for a changed DHCP lease or regenerated key. Verify the replacement before updating the trusted entry. Do not disable verification. |
| Rejected output | Check command permissions and output manually. An error response is not a backup. |

## Security choices and limits

The collector uses `ssh_strict=True` and loads trusted host keys. It does not
offer an insecure bypass. It collects configuration without changing switch
settings. Netmiko may prepare the terminal session to disable paging and set
its width, and the optional enable step changes session privilege.

Reports omit configuration lines and secret values. Raw SSH exceptions are
not printed because they can contain command output. Authentication failures,
timeouts, host-key failures, and command errors are recorded per device so
other inventory entries can still be attempted.

Full backups can contain credentials and password hashes. They are stored
unencrypted. New run folders use restricted Windows ACLs or POSIX mode 0700;
POSIX files use 0600. Administrator access, filesystem support, and copies to
shared or synced folders remain outside that protection. Failed writes attempt
to remove partial files. There is no backup rotation or automatic restore.

The parser covers a subset of IOS syntax. It does not assess password strength,
ACL reachability, AAA policies, SNMP communities, every credential format, or
other vendors. Types 5, 8 and 9 are recognized without declaring their hashes
strong. Finding severities are a small local checklist, not a compliance standard
or vulnerability score. Broad device compatibility and large inventories have
not been tested.

`.gitignore` excludes local inventories, secrets, keys, backups, reports, logs,
and virtual environments. Ignoring a file does not remove it from an existing
commit or Git history. Review staged files before publishing. Earlier lab
addresses remain in historical documentation; no history was rewritten here.

## Code layout

| File | Responsibility |
| --- | --- |
| `main.py` | CLI modes, prompts, terminal summary, CSV report |
| `audit/inventory.py` | Inventory validation, including duplicate field rejection |
| `audit/collection.py` | SSH collection, output validation, per-device failures |
| `audit/rules.py` | Section parsing and configuration checks |
| `audit/storage.py` | Private run folders and exclusive file creation |
| `demo/` and `tests/` | Fictional examples and offline checks |
