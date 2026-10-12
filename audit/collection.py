"""One explicitly selected device per SSH connection; no config changes."""

from dataclasses import dataclass, field
import re

from .rules import analyze
from .storage import private_write


@dataclass
class Result:
    name: str
    status: str
    explanation: str = ""
    findings: list = field(default_factory=list)


def validate_config(output):
    if not isinstance(output, str) or not output.strip():
        raise ValueError("Empty configuration output")
    # Conservatively reject CLI diagnostics and incomplete/paginated responses.
    if re.search(r"(?im)^\s*%|--\s*More\s*--|(?im:^[ \t]*(?:error:|invalid command|permission denied|command authorization failed))", output):
        raise ValueError("CLI error or pagination")
    if not re.search(r"(?m)^hostname \S+\s*$", output) or output.strip().splitlines()[-1].strip() != "end":
        raise ValueError("Unrecognized or incomplete configuration")
    return output


def collect_device(device, credentials, backup_dir, connector=None, known_hosts=None):
    connection = None
    try:
        from netmiko import ConnectHandler
        from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout
        from paramiko import SSHException
        connector = connector or ConnectHandler
        options = dict(device_type="cisco_ios", host=device["host"], port=device.get("port", 22),
                       username=credentials["username"], password=credentials["password"],
                       secret=credentials.get("secret", ""), ssh_strict=True, system_host_keys=True,
                       use_keys=False, allow_agent=False, conn_timeout=15, auth_timeout=15,
                       banner_timeout=15, timeout=30)
        if known_hosts:
            options.update(alt_host_keys=True, alt_key_file=str(known_hosts))
        connection = connector(**options)
        if credentials.get("secret"):
            connection.enable()
        output = connection.send_command("show running-config", read_timeout=60)
        validate_config(output)
        findings = analyze(output)
        private_write(backup_dir / f"{device['name']}.cfg", output)
        return Result(device["name"], "success", findings=findings)
    except ImportError:
        return Result(device["name"], "dependency_error", "Install requirements.txt before live collection.")
    except NetmikoAuthenticationException:
        return Result(device["name"], "authentication_failed", "SSH authentication failed; no backup saved.")
    except (NetmikoTimeoutException, ReadTimeout, TimeoutError):
        return Result(device["name"], "timeout", "Connection or command timed out; no backup saved.")
    except SSHException:
        return Result(device["name"], "ssh_error", "SSH negotiation or host-key verification failed; no backup saved.")
    except ValueError:
        return Result(device["name"], "command_error", "Enable failed, or output was empty, erroneous, or incomplete; no backup saved.")
    except OSError:
        return Result(device["name"], "io_error", "Network or backup file operation failed.")
    except Exception:
        # Exception strings can contain command output or secrets: deliberately suppress them.
        return Result(device["name"], "collection_error", "Collection failed; no successful backup recorded.")
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass


def collect_all(devices, credentials, backup_dir, connector=None, known_hosts=None):
    return [collect_device(d, credentials, backup_dir, connector, known_hosts) for d in devices]
