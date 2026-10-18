"""Inventory failures must be useful to diagnose without echoing source lines."""

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from audit.inventory import InventoryError, load_inventory
from main import main


class InventoryErrorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "devices.yaml"

    def test_duplicate_host_cannot_silently_replace_the_target(self):
        self.path.write_text("devices:\n  - name: lab\n    host: 192.0.2.10\n    host: 192.0.2.20\n")
        with self.assertRaisesRegex(InventoryError, "duplicate field"):
            load_inventory(self.path)

    def test_yaml_error_does_not_echo_a_secret_from_the_source(self):
        self.path.write_text('devices: [password: "DO_NOT_ECHO_THIS')
        with patch("netmiko.ConnectHandler", side_effect=AssertionError("no network")), \
                patch("main.getpass", side_effect=AssertionError("no prompt")), \
                contextlib.redirect_stderr(io.StringIO()) as terminal:
            status = main(["--inventory", str(self.path)])
        self.assertEqual(status, 2)
        self.assertIn("Invalid inventory YAML", terminal.getvalue())
        self.assertNotIn("DO_NOT_ECHO_THIS", terminal.getvalue())

    def test_missing_inventory_has_an_actionable_error(self):
        with self.assertRaisesRegex(InventoryError, "Cannot read the inventory"):
            load_inventory(self.path)

    def test_unknown_password_field_is_rejected_without_echoing_it(self):
        self.path.write_text("devices:\n  - name: lab\n    host: 192.0.2.10\n    password: DO_NOT_ECHO_THIS\n")
        with self.assertRaises(InventoryError) as caught:
            load_inventory(self.path)
        self.assertIn("passwords and enable secrets are forbidden", str(caught.exception))
        self.assertNotIn("DO_NOT_ECHO_THIS", str(caught.exception))

    def test_missing_trusted_key_file_stops_before_password_prompt(self):
        self.path.write_text("devices:\n  - name: lab\n    host: 192.0.2.10\n    username: laboperator\n")
        with patch("main.getpass", side_effect=AssertionError("no prompt")), \
                contextlib.redirect_stderr(io.StringIO()) as terminal:
            status = main(["--inventory", str(self.path), "--known-hosts", str(self.path.parent / "missing")])
        self.assertEqual(status, 2)
        self.assertIn("--known-hosts", terminal.getvalue())
