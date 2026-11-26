import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from gamai_plugins.cli import call


class Allowlist(unittest.TestCase):
    def test_shell_wrappers_cannot_hide_a_denied_program(self):
        from gamai_plugins.plugins.protean import run as protean
        for command in ("sh -c 'rm -rf /'", "( env )", "echo $(rm -rf /)",
                        "bash -c 'curl http://x'"):
            ok, _why = protean.check_tool(command)
            self.assertFalse(ok, command)

    def test_an_allowed_program_inside_a_wrapper_is_fine(self):
        from gamai_plugins.plugins.protean import run as protean
        for command in ("sh -c 'ls /'", "if true; then ls; fi", "echo hi"):
            ok, why = protean.check_tool(command)
            self.assertTrue(ok, (command, why))

    def test_network_is_refused_even_at_low_risk(self):
        from gamai_plugins.plugins.protean import run as protean
        parsed, error = protean.parse_args(
            {"cmd": "ls", "risk": "low", "net": True, "timeout_s": 5})
        self.assertIsNone(parsed)
        self.assertIn("mrezu", error)


class ProteanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {"PROTEAN_HOME": self.tmp.name}

    def tearDown(self):
        self.tmp.cleanup()

    @unittest.skipUnless(shutil.which("bwrap"), "bubblewrap is not installed")
    def test_low_risk_runs_and_writes_evidence(self):
        with patch.dict(os.environ, self.env, clear=False):
            r = call("protean", "run", {"cmd": "echo hi", "risk": "low", "timeout_s": 5})
        self.assertTrue(r.get("ok"), r)
        self.assertEqual(r.get("out"), "hi\n")
        self.assertTrue(os.path.isfile(os.path.join(self.tmp.name, "lease.key")))
        self.assertTrue(os.path.isfile(r["evidence"]))

    @unittest.skipUnless(shutil.which("bwrap"), "bubblewrap is not installed")
    def test_low_does_not_expose_host_secrets(self):
        with patch.dict(os.environ, self.env, clear=False):
            r = call("protean", "run", {"cmd": "head -c 20 /etc/shadow", "risk": "low", "timeout_s": 5})
        self.assertNotIn("root:", r.get("out", ""))

    def test_critical_without_remote_is_denied(self):
        with patch.dict(os.environ, self.env, clear=False):
            r = call("protean", "run", {"cmd": "echo hi", "risk": "critical", "timeout_s": 5})
        self.assertFalse(r.get("ok"), r)
        self.assertIn("remote", (r.get("err") or "").lower())

    def test_unknown_risk_is_denied(self):
        with patch.dict(os.environ, self.env, clear=False):
            r = call("protean", "run", {"cmd": "echo hi", "risk": "insane", "timeout_s": 5})
        self.assertFalse(r.get("ok"), r)


if __name__ == "__main__":
    unittest.main()


class ProteanOutputTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("bwrap"), "bubblewrap is not installed")
    def test_large_output_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"PROTEAN_HOME": tmp}
            with patch.dict(os.environ, env, clear=False):
                r = call("protean", "run", {
                    "cmd": "python3 -c \"print('x' * 1000000)\"",
                    "risk": "low", "timeout_s": 5,
                })
        self.assertTrue(r.get("ok"), r)
        self.assertLessEqual(len(r.get("out", "")), 9000)


class ProteanMountTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("bwrap"), "bubblewrap is not installed")
    def test_etc_allowlist_hides_nginx_and_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"PROTEAN_HOME": tmp}
            with patch.dict(os.environ, env, clear=False):
                nginx = call("protean", "run", {"cmd": "ls /etc/nginx", "risk": "low", "timeout_s": 5})
                run = call("protean", "run", {"cmd": "ls /run", "risk": "low", "timeout_s": 5})
                tmpfs = call("protean", "run", {"cmd": "df -h /tmp | tail -1", "risk": "low", "timeout_s": 5})
        self.assertFalse(nginx.get("ok"))
        self.assertFalse(run.get("ok"))
        self.assertIn("32M", tmpfs.get("out", ""))
