"""Create private run folders before writing sensitive files."""

import csv
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import tempfile


def private_directory(parent):
    parent = Path(parent)
    parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ_")
    path = Path(tempfile.mkdtemp(prefix=stamp, dir=parent))
    if os.name == "nt":
        # Use a SID rather than a localized account name. Never place secrets in commands.
        identity = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                                  check=True, capture_output=True, text=True)
        sid = next(csv.reader(identity.stdout.splitlines()))[1]
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"],
                       check=True, capture_output=True, text=True)
    else:
        path.chmod(0o700)
    return path


def private_write(path, content):
    path = Path(path)
    # Exclusive creation avoids silently overwriting files or following an existing symlink.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
    except BaseException:
        # Do not leave a partial backup looking like a complete configuration.
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
