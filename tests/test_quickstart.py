"""Quickstart guarantees for gamai-plugins: deny wins, missing policy fails closed."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

POLICY = {
    "version": 1,
    "default": "deny",
    "allow": {"tools": ["shell"]},
    "deny": {"commands": ["rm -rf*", r"re:^\s*sudo\b"]},
}


def decide(command: str, policy_path: str) -> tuple[dict, int]:
    payload = json.dumps({"action": "check", "tool": "shell", "command": command})
    env = dict(os.environ, GAMAI_POLICY=policy_path)
    p = subprocess.run([sys.executable, "-m", "gamai_plugins.cli", "call", "trust",
                        "managed_policy", payload],
                       capture_output=True, text=True, env=env, timeout=60)
    return json.loads(p.stdout), p.returncode


class PolicyQuickstart(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(POLICY, self.tmp)
        self.tmp.close()

    def tearDown(self) -> None:
        os.unlink(self.tmp.name)

    def test_allow_then_deny(self) -> None:
        d, rc = decide("ls -la", self.tmp.name)
        self.assertEqual(d["decision"], "allow")
        self.assertEqual(rc, 0)

        d, rc = decide("rm -rf /", self.tmp.name)
        self.assertEqual(d["decision"], "deny")
        self.assertIn("commands:rm -rf*", d["matched"])
        self.assertEqual(rc, 1, "deny must be a non-zero exit code for CI use")

    def test_regex_deny(self) -> None:
        d, _ = decide("sudo rm -rf /tmp/x", self.tmp.name)
        self.assertEqual(d["decision"], "deny")

    def test_missing_policy_fails_closed(self) -> None:
        d, rc = decide("ls", "/nonexistent/policy.json")
        self.assertEqual(d["decision"], "deny")
        self.assertTrue(d.get("reason", "").startswith("fail_closed"), d)
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
