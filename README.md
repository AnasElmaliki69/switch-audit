# switch-audit

Back up Cisco IOS/IOS XE configurations over SSH and flag settings that need
review. For the full setup and rule reference, see [GETTING_STARTED.md](GETTING_STARTED.md).

## Windows CML lab

The existing lab uses Windows → VMware NAT → CML Free 2.10.1's External
Connector (`System Bridge / bridge0`) → IOL-L2 XE 17.18.02. Connect directly
to the switch's Vlan1 address, **not** the CML server address. The last observed
addresses were `192.168.181.129` for `LabSwitch` (node `iol-l2-0`) and
`192.168.181.128` for CML. Vlan1 uses DHCP, so check the switch's current
address in the CML console with `show ip interface brief` after a restart.

Open PowerShell in this project folder. Create the environment only if it is
missing, then install dependencies:

```powershell
if (-not (Test-Path .\.venv\Scripts\python.exe)) { py -3 -m venv .venv }
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py --help
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe main.py --demo
```

The Git-ignored `devices.local.yaml` is already prepared locally with
`name: LabSwitch`, `host: 192.168.181.129`, `device_type: cisco_ios`,
`username: netadmin`, and `port: 22`, beneath the `devices:` list. It has no
password. A fresh clone should copy `devices.example.yaml` to
`devices.local.yaml`, replace the fictional fields, and add `username: netadmin`.

Check the single authorized endpoint from your Windows terminal:

```powershell
Test-NetConnection -ComputerName 192.168.181.129 -Port 22
```

### Trust the switch's SSH key

SSH host-key verification stays enabled. Through the trusted CML console,
obtain the switch's SSH host public key/fingerprint (for example, inspect
`show crypto key mypubkey rsa`) and compare its SHA256 fingerprint with the
one offered by Windows OpenSSH. The configured key size of 4096 bits and
`show ip ssh` reporting version 2 do **not** establish key identity by themselves.
If the console only shows the public key data, have your lab administrator
derive its fingerprint in OpenSSH format before accepting it. Do not compare
an MD5 fingerprint directly with a SHA256 fingerprint.

```powershell
ssh -o StrictHostKeyChecking=ask -p 22 netadmin@192.168.181.129
```

Accept only when the fingerprint matches the independently verified key.
Enter your private password locally if prompted, then `exit`. This enrolls
the trusted key in `$HOME\.ssh\known_hosts`. Do not blindly trust
`ssh-keyscan` output or disable checking. If Windows reports a changed key,
first confirm the current DHCP lease and verify the replacement through CML;
only then remove the obsolete entry and enroll the verified key again:

```powershell
# Run only after independently verifying the changed key and device identity.
ssh-keygen -R 192.168.181.129 -f "$HOME\.ssh\known_hosts"
```

### Run the read-only backup and audit

```powershell
.\.venv\Scripts\python.exe main.py --inventory devices.local.yaml --known-hosts "$HOME\.ssh\known_hosts" --prompt-password
```

`--prompt-password` always uses hidden `getpass` input, even if a password
environment variable exists. Do not paste passwords into commands, this file,
the inventory, or chat. `netadmin` already has privilege 15, so an enable
secret should normally be unnecessary. Add `--ask-enable` only if your actual
login requires it; that prompt is also hidden.

Successful collection saves `LabSwitch.cfg` and `audit.csv` inside a private,
UTC-timestamped folder under `artifacts/live/`. Backups contain sensitive full
configurations; report findings omit secret values. Failed or empty command
output never counts as a successful backup. Real inventories, environments,
trusted-key files, backups, and reports are ignored by Git.

### If it fails

- **Unreachable / timeout:** Start the CML node, check Vlan1 is up/up and the
  link through Ethernet0/0 → bridge0 → VMware NAT, then repeat the TCP test.
  Do not target the CML management IP or scan the subnet.
- **DHCP address changed:** Read `show ip interface brief` in the switch
  console and update only `host` in `devices.local.yaml`. Verify the host key
  for that address before logging in; another device may have the old lease.
- **Authentication failed:** Confirm `netadmin` and your locally configured
  password with OpenSSH. The private-password placeholder is never a password.
  The collector does not try default passwords or retry with other accounts.
- **Host-key error:** `host_key_untrusted` needs verified enrollment;
  `host_key_changed` needs device/key re-verification. A generic `ssh_error`
  may also mean SSH algorithm negotiation failed; inspect `ssh -v` locally
  without weakening the collector's host-key checks.
- **Missing dependency / hidden input unavailable:** Use the project's `.venv`
  interpreter in an interactive PowerShell terminal and install requirements.

The image supports only `line vty 0 4`; `transport input ssh` is SSH-only and
absent VTY lines 5-15 do not produce a finding. A common username is only a
potential issue, never proof of a default password. Config analysis cannot
prove port reachability or password use. No findings means **“No issues found
by implemented checks”**, not full compliance. Live SSH collection is confirmed
only after a real authenticated run succeeds; offline tests and TCP reachability
alone do not establish that.
