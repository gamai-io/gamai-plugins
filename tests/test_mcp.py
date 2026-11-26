import json
import subprocess
import sys
import unittest


class McpTests(unittest.TestCase):
    def test_selftest_lists_six_tools(self):
        p = subprocess.run(
            [sys.executable, "-m", "gamai_plugins.mcp", "--selftest"],
            text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["tools"], 6)
        self.assertIn("trust_managed_policy", data["names"])
        self.assertIn("protean_run", data["names"])
        self.assertIn("team_create", data["names"])


if __name__ == "__main__":
    unittest.main()
