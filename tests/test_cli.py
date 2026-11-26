import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from gamai_plugins.cli import call, main, trust_main


class CliTests(unittest.TestCase):
    def test_unicode_goal_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"GAMAI_TEAM_STATE_DIR": os.path.join(tmp, "state"),
                   "GAMAI_TEAM_WORKTREES": os.path.join(tmp, "work")}
            with patch.dict(os.environ, env, clear=False):
                r = call("team", "team_create", {"goal": "provjeri čćžšđ", "agents": 2})
        self.assertTrue(r.get("ok"), r)
        self.assertIn("čćžšđ", r.get("goal", ""))

    def test_malformed_json_is_clean_error(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = main(["call", "trust", "managed_policy", "{bad"])
        self.assertEqual(rc, 2)
        self.assertIn("invalid json", out.getvalue())

    def test_deny_returns_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = os.path.join(tmp, "policy.json")
            audit = os.path.join(tmp, "audit.jsonl")
            with open(policy, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "default": "deny"}, fh)
            out = io.StringIO()
            with patch.dict(os.environ, {"GAMAI_POLICY": policy, "GAMAI_AUDIT": audit}, clear=False), \
                 redirect_stdout(out):
                rc = trust_main(["managed_policy", '{"action":"check","tool":"shell"}'])
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out.getvalue())["decision"], "deny")
