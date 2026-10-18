"""Validate the entire allowlist before any SSH connection."""

from pathlib import Path
import re


class InventoryError(ValueError):
    """An inventory problem whose message is safe to show in the terminal."""


def _read_yaml(path):
    import yaml

    class InventoryLoader(yaml.SafeLoader):
        pass

    def unique_mapping(loader, node):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if key in mapping:
                raise InventoryError("Inventory has a duplicate field. Keep each field only once.")
            mapping[key] = loader.construct_object(value_node)
        return mapping

    InventoryLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        raise InventoryError("Cannot read the inventory file. Check its path and permissions.") from None
    try:
        return yaml.load(text, Loader=InventoryLoader)
    except (yaml.YAMLError, TypeError):
        # YAML exceptions can include complete source lines containing passwords.
        raise InventoryError("Invalid inventory YAML. Check indentation and field syntax.") from None


def load_inventory(path):
    document = _read_yaml(path)
    if not isinstance(document, dict) or set(document) != {"devices"}:
        raise InventoryError("Inventory must contain only a devices list.")
    devices = document["devices"]
    if not isinstance(devices, list) or not devices:
        raise InventoryError("devices must be a nonempty list.")
    names = set()
    for device in devices:
        if not isinstance(device, dict) or set(device) - {"name", "host", "port", "device_type", "username"}:
            raise InventoryError("Allowed device fields: name, host, port, device_type, username; passwords and enable secrets are forbidden.")
        name, host = device.get("name"), device.get("host")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name):
            raise InventoryError("Device names must start with a letter and use up to 64 letters, digits, _ or -.")
        if name.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
            raise InventoryError("Reserved filesystem device name.")
        if name.casefold() in names:
            raise InventoryError("Device names must be unique, ignoring case.")
        names.add(name.casefold())
        if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", host):
            raise InventoryError("host must be a single IP address or hostname, never a range, URL or subnet.")
        port = device.get("port", 22)
        if type(port) is not int or not 1 <= port <= 65535:
            raise InventoryError("port must be an integer from 1 to 65535.")
        if device.get("device_type", "cisco_ios") != "cisco_ios":
            raise InventoryError("Only cisco_ios (IOS/IOS XE) is supported.")
        if "username" in device and (not isinstance(device["username"], str) or
                                     not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", device["username"])):
            raise InventoryError("username must use 1-128 letters, digits, ., _, @ or -; never store passwords here.")
    return devices
