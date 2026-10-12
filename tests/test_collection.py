import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout
from paramiko import BadHostKeyException, RSAKey, SSHException

from audit.collection import collect_all, collect_device
from audit.inventory import load_inventory
from audit.storage import private_directory, private_write
from main import hidden_prompt, main, report

CONFIG = (Path(__file__).resolve().parents[1] / "demo" / "secure.cfg").read_text()
DEVICE = {"name": "lab-switch", "host": "192.0.2.10"}
CREDENTIALS = {"username": "operator", "password": "NEVER_PRINT", "secret": "ENABLE_NEVER_PRINT"}


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def test_success_strict_ssh_enable_disconnect_and_backup(self):
        connection = Mock()
        connection.send_command.return_value = CONFIG
        connector = Mock(return_value=connection)
        result = collect_device(DEVICE, CREDENTIALS, self.directory, connector, "verified_known_hosts")
        self.assertEqual(result.status, "success")
        self.assertEqual((self.directory / "lab-switch.cfg").read_text(), CONFIG)
        options = connector.call_args.kwargs
        self.assertTrue(options["ssh_strict"])
        self.assertTrue(options["system_host_keys"])
        self.assertTrue(options["alt_host_keys"])
        self.assertEqual(options["host"], DEVICE["host"])
        self.assertEqual(options["device_type"], "cisco_ios")
        connection.enable.assert_called_once_with()
        connection.send_command.assert_called_once_with("show running-config", read_timeout=60)
        connection.disconnect.assert_called_once_with()

    def test_bad_outputs_never_saved(self):
        for output in ("", "  ", "% Invalid input detected", CONFIG + "\n% Authorization failed", "hostname TEST\n", CONFIG + "\npartial trailing output", CONFIG.replace("end", "--More--")):
            with self.subTest(output=output[:30]):
                connection = Mock()
                connection.send_command.return_value = output
                result = collect_device(DEVICE, CREDENTIALS, self.directory, Mock(return_value=connection))
                self.assertEqual(result.status, "command_error")
                self.assertFalse(list(self.directory.glob("*.cfg")))
                connection.disconnect.assert_called_once()

    def test_failures_continue_to_next_device(self):
        for exception, status in ((NetmikoAuthenticationException("NEVER_PRINT"), "authentication_failed"),
                                  (NetmikoTimeoutException("NEVER_PRINT"), "timeout"),
                                  (ReadTimeout("NEVER_PRINT"), "timeout"),
                                  (SSHException("NEVER_PRINT"), "ssh_error"),
                                  (ValueError("NEVER_PRINT"), "command_error"),
                                  (RuntimeError("NEVER_PRINT"), "collection_error")):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as folder:
                connection = Mock()
                connection.send_command.return_value = CONFIG
                connector = Mock(side_effect=[exception, connection])
                devices = [DEVICE, {"name": "second", "host": "198.51.100.20"}]
                results = collect_all(devices, CREDENTIALS, Path(folder), connector)
                self.assertEqual([r.status for r in results], [status, "success"])
                self.assertEqual(connector.call_count, 2)
                self.assertNotIn("NEVER_PRINT", repr(results))
                self.assertFalse((Path(folder) / "lab-switch.cfg").exists())
                self.assertTrue((Path(folder) / "second.cfg").exists())

    def test_command_timeout_and_enable_failure_disconnect(self):
        for method, exception, status in (("enable", ValueError("SECRET"), "command_error"),
                                          ("send_command", ReadTimeout("SECRET"), "timeout")):
            connection = Mock()
            getattr(connection, method).side_effect = exception
            result = collect_device(DEVICE, CREDENTIALS, self.directory, Mock(return_value=connection))
            self.assertEqual(result.status, status)
            connection.disconnect.assert_called_once()
            self.assertFalse(list(self.directory.glob("*.cfg")))

    def test_changed_host_key_rejected_without_backup(self):
        key = RSAKey.generate(1024)
        exception = BadHostKeyException(DEVICE["host"], key, key)
        result = collect_device(DEVICE, CREDENTIALS, self.directory, Mock(side_effect=exception))
        self.assertEqual(result.status, "ssh_error")
        self.assertFalse(list(self.directory.glob("*.cfg")))

    def test_no_enable_when_secret_absent(self):
        connection = Mock()
        connection.send_command.return_value = CONFIG
        result = collect_device(DEVICE, {"username": "operator", "password": "SECRET"}, self.directory, Mock(return_value=connection))
        self.assertEqual(result.status, "success")
        connection.enable.assert_not_called()

    def test_backup_write_failure_is_failure_and_continues(self):
        connection = Mock()
        connection.send_command.return_value = CONFIG
        with patch("audit.collection.private_write", side_effect=[OSError("SECRET"), None]):
            results = collect_all([DEVICE, {"name": "second", "host": "198.51.100.20"}], CREDENTIALS,
                                  self.directory, Mock(return_value=connection))
        self.assertEqual([r.status for r in results], ["io_error", "success"])
        self.assertNotIn("SECRET", repr(results))

    def test_failed_device_in_terminal_and_csv(self):
        result = collect_device(DEVICE, CREDENTIALS, self.directory, Mock(side_effect=NetmikoAuthenticationException("SECRET")))
        with contextlib.redirect_stdout(io.StringIO()) as terminal:
            path = report([result], self.directory)
        self.assertIn("authentication_failed", path.read_text())
        self.assertIn("COLLECTION_ERROR", path.read_text())
        self.assertNotIn("SECRET", terminal.getvalue() + path.read_text())

    def test_hidden_prompt_refuses_echo_fallback(self):
        import warnings
        from getpass import GetPassWarning
        def unavailable(prompt):
            warnings.warn("no terminal", GetPassWarning)
            raise AssertionError("must not reach echoed input")
        with patch("main.getpass", side_effect=unavailable), self.assertRaises(GetPassWarning):
            hidden_prompt("Password: ")

    def test_invalid_inventory_never_connects(self):
        path = self.directory / "bad.yaml"
        path.write_text("devices:\n  - name: invalid\n    host: 192.0.2.0/24")
        with patch("netmiko.ConnectHandler", side_effect=AssertionError("network forbidden")), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--inventory", str(path)]), 2)

    def test_inventory_rejects_credentials_ranges_paths_and_duplicates(self):
        path = self.directory / "devices.yaml"
        for fields in ("name: ../escape\n    host: 192.0.2.1", "name: lab\n    host: 192.0.2.0/24",
                       "name: lab\n    host: 192.0.2.1\n    password: SECRET", "name: CON\n    host: 192.0.2.1",
                       "name: lab\n    host: 192.0.2.1\n    port: true"):
            path.write_text("devices:\n  - " + fields)
            with self.assertRaises(ValueError):
                load_inventory(path)
        path.write_text("devices:\n  - name: lab\n    host: 192.0.2.1\n  - name: LAB\n    host: 192.0.2.2")
        with self.assertRaises(ValueError):
            load_inventory(path)

    def test_example_inventory_loads(self):
        path = Path(__file__).resolve().parents[1] / "devices.example.yaml"
        self.assertEqual(len(load_inventory(path)), 2)

    def test_private_write_is_exclusive(self):
        directory = private_directory(self.directory)
        private_write(directory / "test.cfg", CONFIG)
        with self.assertRaises(FileExistsError):
            private_write(directory / "test.cfg", "replacement")
        import os
        if os.name != "nt":
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual((directory / "test.cfg").stat().st_mode & 0o777, 0o600)

    def test_demo_never_connects_or_prompts(self):
        with patch("netmiko.ConnectHandler", side_effect=AssertionError("network forbidden")), patch("main.getpass", side_effect=AssertionError("prompt forbidden")), patch("builtins.input", side_effect=AssertionError("prompt forbidden")), contextlib.redirect_stdout(io.StringIO()) as terminal:
            self.assertEqual(main(["--demo", "--output-dir", str(self.directory)]), 0)
        self.assertIn("No issues found by implemented checks", terminal.getvalue())
        csv_path = next(self.directory.rglob("audit.csv"))
        content = csv_path.read_text()
        self.assertNotIn("DEMO_ONLY", content)
        self.assertIn("DEFAULT_USERNAME,potential", content)
        self.assertEqual(len(list(self.directory.rglob("*.cfg"))), 3)


if __name__ == "__main__":
    unittest.main()
