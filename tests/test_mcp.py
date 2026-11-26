import json
import subprocess
import sys
import unittest


class McpTests(unittest.TestCase):
    def test_selftest_lists_the_tools(self):
        p = subprocess.run(
            [sys.executable, "-m", "gamai_plugins.mcp", "--selftest"],
            text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["tools"], 7)
        self.assertIn("trust_managed_policy", data["names"])
        self.assertIn("protean_run", data["names"])
        self.assertIn("team_create", data["names"])
        self.assertIn("protean_verify-evidence", data["names"])


if __name__ == "__main__":
    unittest.main()


class ParamsShape(unittest.TestCase):
    def test_a_list_params_is_an_error_not_a_crash(self):
        from gamai_plugins import mcp
        reply = mcp.handle({"jsonrpc": "2.0", "id": 1,
                                "method": "tools/call", "params": [1]})
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)
