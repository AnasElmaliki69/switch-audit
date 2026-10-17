"""Validate the entire allowlist before any SSH connection."""

from pathlib import Path
import re


def load_inventory(path):
    import yaml
    document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or set(document) != {"devices"}:
        raise ValueError("Inventory must contain only a devices list.")
    devices = document["devices"]
    if not isinstance(devices, list) or not devices:
        raise ValueError("devices must be a nonempty list.")
    names = set()
    for device in devices:
        if not isinstance(device, dict) or set(device) - {"name", "host", "port", "device_type", "username"}:
            raise ValueError("Allowed device fields: name, host, port, device_type, username; passwords and enable secrets are forbidden.")
        name, host = device.get("name"), device.get("host")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name):
            raise ValueError("Device names must start with a letter and use up to 64 letters, digits, _ or -.")
        if name.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
            raise ValueError("Reserved filesystem device name.")
        if name.casefold() in names:
            raise ValueError("Device names must be unique, ignoring case.")
        names.add(name.casefold())
        if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", host):
            raise ValueError("host must be a single IP address or hostname, never a range, URL or subnet.")
        port = device.get("port", 22)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("port must be an integer from 1 to 65535.")
        if device.get("device_type", "cisco_ios") != "cisco_ios":
            raise ValueError("Only cisco_ios (IOS/IOS XE) is supported.")
        if "username" in device and (not isinstance(device["username"], str) or
                                     not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", device["username"])):
            raise ValueError("username must use 1-128 letters, digits, ., _, @ or -; never store passwords here.")
    return devices
