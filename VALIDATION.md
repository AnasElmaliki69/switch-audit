# Validation notes

## Evidence reviewed

The repository contains fictional configurations and offline tests. The local
workspace also contains private live backups and CSV reports excluded by Git.
Their collection statuses and VTY settings were reviewed without publishing
configuration lines containing credentials or secret values.

The recorded lab setup is Windows, VMware Workstation with NAT, CML Free
2.10.1, and IOL L2 XE 17.18.02. A CML External Connector uses
`System Bridge / bridge0`. Vlan1 uses DHCP. These describe one lab, not support
for other images or network designs.

Local run folders have UTC timestamps on 2026-10-17, corresponding to
2026-10-18 in Europe/Paris. Device names and addresses are omitted here.

| Existing local evidence | Observed result |
| --- | --- |
| SSH-only backup and report | Collection succeeded; VTY 0-4 allowed SSH; report contained `NO_ISSUES` |
| Separate attempted collection | Report recorded `timeout`; that run folder contained no configuration backup |
| Telnet test backup and report | Collection succeeded; VTY 0-3 allowed SSH and VTY 4 allowed Telnet plus SSH; report contained `VTY_TELNET` |
| Later restored backup and report | Collection succeeded; VTY 0-4 allowed SSH; report contained `NO_ISSUES` |

The backups have a hostname and final `end`. Re-running the parser on those
files agrees with the reported rule IDs. This supports the live collection and
detection results for this lab. It is not a packet capture, proof of Telnet
reachability, or testing across multiple real devices. Private originals are
intentionally not in the public repository. README output is reconstructed
and sanitized rather than a raw report.

## Current offline verification

On 2026-10-18, the existing Windows `.venv` used Python 3.12.14, Netmiko 4.8.0,
Paramiko 5.0.0, and PyYAML 6.0.3. The review ran:

| Command, using `.venv\Scripts\python.exe` | Result |
| --- | --- |
| `-m pip install -r requirements.txt` | All three pinned direct dependencies were already installed |
| `-m unittest discover -s tests -v` | 38 tests passed |
| `main.py --help` | Options matched the README and reference notes |
| `main.py --demo` | Exit 0; three fictional backups and CSV report created; findings matched the documented counts |
| `-m pip check` | No broken requirements found |

New tests cover banner text versus real CLI errors, incomplete output hidden
inside a banner, partial-write cleanup, preservation of an existing file,
duplicate inventory fields, missing input files, and errors that must not echo
secret-bearing YAML. The demo test blocks connection and credential prompts.

The verification above was completed locally before publication. No new
authenticated switch session or switch configuration change was performed
during this review.

## Git review

Before editing, the repository was clean on `main`, tracking `origin/main`.
The review examined all six commits reachable from local refs and 26 unique
file blobs. Only source, documentation, fictional configurations, the example
inventory and tests were tracked. Real inventories, live artifacts and the
virtual environment were not tracked.

A targeted scan found no private-key blocks or recognizable GitHub/AWS token
markers. It is not an exhaustive secret audit. Credential-like strings in the
tests and demo files are explicitly synthetic.

The previous README included private lab IPs. Current examples use fictional
documentation addresses. Earlier details remain in Git history. No commits,
remote settings or history were rewritten in this review. An ignore rule does
not remove a committed file or revoke an exposed credential.

## What remains untested

No new authenticated switch session is part of this review. It uses existing
local live artifacts and new offline verification. The macOS/Linux setup,
POSIX permission behavior, other images, large inventories, and negotiation
with other SSH servers have not been verified here. The Windows Python-launcher
bootstrap is documented but the existing `.venv` is reused, not recreated.

The checks do not test reachability, password strength, AAA/ACL policy, SNMP
secrets, all Cisco credential formats, restore behavior or backup retention.
No vulnerability-scanner or regulatory-compliance claim is made.
