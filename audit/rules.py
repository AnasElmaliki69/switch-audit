"""Conservative checks of IOS sections; never copy secrets into findings."""

from dataclasses import dataclass
import re
import shlex

DEFAULT_USERNAMES = frozenset({"admin", "administrator", "cisco", "root", "guest", "user"})


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    explanation: str


def sections(config):
    """Yield top-level commands with their indented children, skipping banners."""
    header, children, delimiter = None, [], None
    for raw in config.splitlines():
        stripped = raw.strip()
        if delimiter is not None:
            if delimiter in raw:
                delimiter = None
            continue
        banner = re.match(r"^banner\s+\S+\s+(\^\S|\S)", raw)
        if banner:
            marker = banner.group(1)
            if marker not in raw[banner.end():]:
                delimiter = marker
            continue
        if not stripped or stripped.startswith("!"):
            continue
        if raw[:1].isspace():
            if header is not None:
                children.append(stripped)
        else:
            if header is not None:
                yield header, children
            header, children = stripped, []
    if header is not None:
        yield header, children


def _password(tokens, start, context):
    value = tokens[start:]
    if not value:
        return Finding("PASSWORD_REVIEW", "review", f"{context}: password setting is incomplete; review required.")
    kind = value[0]
    if kind.isdigit() and len(value) < 2:
        return Finding("PASSWORD_REVIEW", "review", f"{context}: password value or encoding is ambiguous; review required.")
    if kind == "0" or not kind.isdigit():
        return Finding("PASSWORD_PLAINTEXT", "high", f"{context}: explicit plaintext password is configured.")
    if kind == "7":
        return Finding("PASSWORD_TYPE7", "high", f"{context}: Cisco type 7 reversible password is configured.")
    if kind in {"5", "8", "9"} and len(value) == 2:
        return None
    return Finding("PASSWORD_REVIEW", "review", f"{context}: password encoding or syntax is not established by these checks; review required.")


def analyze(config):
    findings, vty_count = [], 0
    for header, children in sections(config):
        vty = re.fullmatch(r"line vty \d+(?: \d+)?", header)
        if vty:
            vty_count += 1
            transports = [c for c in children if c.startswith("transport input") or c.startswith("no transport input")]
            if len(transports) != 1:
                findings.append(Finding("VTY_REVIEW", "review", f"{header}: missing or conflicting transport input settings; review required."))
            for transport in transports:
                protocols = transport.split()[2:]
                if transport.startswith("transport input ") and ({"telnet", "all"} & set(protocols)):
                    findings.append(Finding("VTY_TELNET", "high", f"{header}: transport input permits Telnet in the configuration; reachability is unverified."))
                elif transport not in {"transport input ssh", "transport input none"}:
                    findings.append(Finding("VTY_REVIEW", "review", f"{header}: transport input syntax is not established by these checks; review required."))
        commands = [(header, "Global setting")]
        if re.fullmatch(r"line (?:vty|con|console|aux) \d+(?: \d+)?", header):
            commands += [(c, header) for c in children if c.startswith("password")]
        for command, context in commands:
            try:
                tokens = shlex.split(command)
            except ValueError:
                if command.startswith(("username ", "enable ", "password")):
                    findings.append(Finding("PASSWORD_REVIEW", "review", f"{context}: credential syntax could not be parsed; review required."))
                continue
            if not tokens:
                continue
            start = None
            if tokens[0] == "username" and len(tokens) >= 2:
                context = "Local username setting"
                if tokens[1].casefold() in DEFAULT_USERNAMES:
                    findings.append(Finding("DEFAULT_USERNAME", "potential", "A configured local username matches the documented common-name list; this does not establish a default password."))
                for i, token in enumerate(tokens[2:], 2):
                    if token in {"password", "secret"}:
                        start = i + 1
                        break
                if start is None:
                    findings.append(Finding("PASSWORD_REVIEW", "review", "Local username setting: no explicit password or secret; authentication needs review."))
            elif tokens[0] == "enable" and len(tokens) >= 2 and tokens[1] in {"password", "secret"}:
                context = "Enable credential setting"
                start = 4 if len(tokens) > 3 and tokens[2] == "level" else 2
            elif tokens[0] == "password" and context != "Global setting":
                start = 1
            if start is not None:
                result = _password(tokens, start, context)
                if result:
                    findings.append(result)
    if not vty_count:
        findings.append(Finding("VTY_REVIEW", "review", "No recognized VTY section was present; remote access settings need review."))
    return findings
