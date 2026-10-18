"""A failed write must not leave a partial configuration behind."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from audit.storage import private_write


class StorageFailureTests(unittest.TestCase):
    def test_partial_file_is_removed_when_write_fails(self):
        real_fdopen = os.fdopen

        class FailingStream:
            def __init__(self, *args, **kwargs):
                self.stream = real_fdopen(*args, **kwargs)

            def __enter__(self):
                return self

            def write(self, content):
                self.stream.write(content[:5])
                raise OSError("simulated disk failure")

            def __exit__(self, *args):
                self.stream.close()

        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "lab.cfg"
            with patch("audit.storage.os.fdopen", side_effect=FailingStream):
                with self.assertRaises(OSError):
                    private_write(target, "FICTIONAL_CONFIG")
            self.assertFalse(target.exists())

    def test_existing_backup_is_preserved_if_exclusive_open_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "lab.cfg"
            target.write_text("ORIGINAL_FICTIONAL_CONFIG")
            with self.assertRaises(FileExistsError):
                private_write(target, "REPLACEMENT")
            self.assertEqual(target.read_text(), "ORIGINAL_FICTIONAL_CONFIG")
