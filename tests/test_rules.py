import unittest
from pathlib import Path

from audit.rules import analyze

DEMO = Path(__file__).resolve().parents[1] / "demo"


class RuleTests(unittest.TestCase):
    def test_secure_fixture(self):
        self.assertEqual(analyze((DEMO / "secure.cfg").read_text()), [])

    def test_insecure_fixture_counts_and_redaction(self):
        findings = analyze((DEMO / "insecure.cfg").read_text())
        ids = [f.rule_id for f in findings]
        self.assertEqual(ids.count("VTY_TELNET"), 2)
        self.assertEqual(ids.count("PASSWORD_PLAINTEXT"), 3)
        self.assertEqual(ids.count("PASSWORD_TYPE7"), 1)
        self.assertEqual(ids.count("DEFAULT_USERNAME"), 1)
        self.assertNotIn("DEMO_ONLY", repr(findings))

    def test_ambiguous_fixture(self):
        findings = analyze((DEMO / "ambiguous.cfg").read_text())
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(f.severity == "review" for f in findings))

    def test_telnet_is_scoped_to_vty(self):
        config = '''hostname LAB
banner motd ^C
username admin password 0 SECRET_IN_BANNER
line vty 0 99
 transport input telnet
^C
interface GigabitEthernet0/1
 description telnet username admin password 0 SECRET_IN_DESCRIPTION
 transport input telnet
line con 0
 transport input all
line vty 0 4
 transport input ssh
end
'''
        self.assertEqual(analyze(config), [])

    def test_explicit_telnet_and_all(self):
        for setting in ("telnet", "all", "ssh telnet"):
            with self.subTest(setting=setting):
                findings = analyze(f"line vty 0 4\n transport input {setting}\n")
                self.assertEqual([f.rule_id for f in findings], ["VTY_TELNET"])

    def test_missing_conflicting_unknown_transports(self):
        for config in ("hostname LAB", "line vty 0 4\n login local", "line vty 0 4\n transport input ssh\n transport input none", "line vty 0 4\n transport input rlogin"):
            with self.subTest(config=config):
                self.assertIn("VTY_REVIEW", [f.rule_id for f in analyze(config)])

    def test_credentials_formats_and_no_leaks(self):
        prefix = "line vty 0 4\n transport input ssh\n!\n"
        for command, rule in (("username ADMIN password 0 TOP_SECRET", "PASSWORD_PLAINTEXT"),
                              ("username person secret TOP_SECRET", "PASSWORD_PLAINTEXT"),
                              ("enable password level 15 7 TOP_SECRET", "PASSWORD_TYPE7"),
                              ("enable secret 8 TOP_SECRET", None),
                              ("username person secret 9 TOP_SECRET", None),
                              ("username person password 6 TOP_SECRET", "PASSWORD_REVIEW"),
                              ("username person", "PASSWORD_REVIEW"),
                              ("username person secret", "PASSWORD_REVIEW")):
            with self.subTest(command=command):
                findings = analyze(prefix + command)
                self.assertNotIn("TOP_SECRET", repr(findings))
                self.assertEqual(rule in [f.rule_id for f in findings] if rule else not findings, True)

    def test_incomplete_explicit_password_types_need_review(self):
        for kind in ("0", "7", "9"):
            findings = analyze(f"enable password {kind}\nline vty 0 4\n transport input ssh")
            self.assertEqual([f.rule_id for f in findings], ["PASSWORD_REVIEW"])


if __name__ == "__main__":
    unittest.main()
