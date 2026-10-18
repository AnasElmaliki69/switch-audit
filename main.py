"""Run the fictional demo or collect only an explicit inventory."""

import argparse
import csv
from getpass import getpass, GetPassWarning
import io
import os
from pathlib import Path
import sys
import warnings

from audit.collection import Result, collect_all, validate_config
from audit.inventory import InventoryError, load_inventory
from audit.rules import analyze
from audit.storage import private_directory, private_write

BASE = Path(__file__).resolve().parent


def hidden_prompt(prompt):
    # getpass normally falls back to echoed input when no suitable terminal exists.
    # Refuse that fallback rather than risk showing a password.
    with warnings.catch_warnings():
        warnings.simplefilter("error", GetPassWarning)
        return getpass(prompt)


def report(results, directory):
    successes = sum(r.status == "success" for r in results)
    print(f"\nCollection summary: {successes}/{len(results)} succeeded; {len(results) - successes} failed.")
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(["device_name", "collection_status", "rule_id", "severity", "explanation"])
    for result in results:
        print(f"\n{result.name}: {result.status}")
        if result.status != "success":
            entries = [("COLLECTION_ERROR", "error", result.explanation)]
        elif result.findings:
            entries = [(f.rule_id, f.severity, f.explanation) for f in result.findings]
        else:
            entries = [("NO_ISSUES", "info", "No issues found by implemented checks")]
        for rule, severity, explanation in entries:
            print(f"  [{severity}] {rule}: {explanation}")
            writer.writerow([result.name, result.status, rule, severity, explanation])
    path = directory / "audit.csv"
    private_write(path, buffer.getvalue())
    print(f"\nCSV report: {path}")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only IOS/IOS XE configuration backup and audit")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="Use fictional included configs; no SSH or credentials")
    mode.add_argument("--inventory", type=Path, help="Explicit YAML device allowlist")
    parser.add_argument("--known-hosts", type=Path, help="Additional verified OpenSSH known_hosts file")
    parser.add_argument("--ask-enable", action="store_true", help="Prompt secretly for optional enable secret")
    parser.add_argument("--prompt-password", action="store_true", help="Always use a hidden password prompt instead of SWITCH_AUDIT_PASSWORD")
    parser.add_argument("--output-dir", type=Path, default=BASE / "artifacts", help="Parent folder for private run folders")
    args = parser.parse_args(argv)
    try:
        if args.demo:
            directory = private_directory(args.output_dir / "demo")
            results = []
            for name in ("secure", "insecure", "ambiguous"):
                config = validate_config((BASE / "demo" / f"{name}.cfg").read_text(encoding="utf-8"))
                private_write(directory / f"demo-{name}.cfg", config)
                results.append(Result(f"demo-{name}", "success", findings=analyze(config)))
            print("FICTIONAL DEMO: no network connections made.")
        else:
            devices = load_inventory(args.inventory)
            if args.known_hosts and not args.known_hosts.is_file():
                print("Run stopped: --known-hosts must point to an existing trusted-key file.", file=sys.stderr)
                return 2
            # Dependency and inventory checks happen before asking for secrets.
            import netmiko
            needs_username = any(not device.get("username") for device in devices)
            username = ""
            if needs_username:
                username = os.environ.get("SWITCH_AUDIT_USERNAME") or input("SSH username: ").strip()
            password = None if args.prompt_password else os.environ.get("SWITCH_AUDIT_PASSWORD")
            password = password or hidden_prompt("SSH password: ")
            secret = os.environ.get("SWITCH_AUDIT_ENABLE_SECRET", "")
            if args.ask_enable and not secret:
                secret = hidden_prompt("Enable secret (Enter to skip): ")
            if (needs_username and not username) or not password:
                print("Run stopped: a username and a nonempty password are required.", file=sys.stderr)
                return 2
            directory = private_directory(args.output_dir / "live")
            results = collect_all(devices, dict(username=username, password=password, secret=secret),
                                  directory, known_hosts=args.known_hosts)
        report(results, directory)
        print(f"Backups: {directory}")
        print("Configuration analysis cannot prove port reachability or use of a default password.")
        return 1 if any(r.status != "success" for r in results) else 0
    except InventoryError as error:
        print(f"Inventory error: {error}", file=sys.stderr)
        return 2
    except (GetPassWarning, EOFError):
        print("Run stopped: hidden password input is unavailable. Run this command in an interactive terminal.", file=sys.stderr)
        return 2
    except ModuleNotFoundError as error:
        print(f"Run stopped: missing Python dependency {error.name}. Install requirements.txt with this interpreter.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Run interrupted; collection was not completed.", file=sys.stderr)
        return 2
    except Exception:
        # Do not print raw exceptions: YAML/SSH errors can include sensitive input.
        print("Run stopped: check dependencies, inventory format, credentials, trusted-key path and output permissions.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
