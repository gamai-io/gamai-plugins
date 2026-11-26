import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from gamai_plugins.cli import call


class TeamTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {
            "GAMAI_TEAM_STATE_DIR": os.path.join(self.tmp.name, "state"),
            "GAMAI_TEAM_WORKTREES": os.path.join(self.tmp.name, "work"),
            "GAMAI_LLM_URL": "",
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_create_dispatch_status_with_deterministic_fallback(self):
        with patch.dict(os.environ, self.env, clear=False):
            created = call("team", "team_create", {"goal": "napravi test", "agents": 2})
            self.assertTrue(created.get("ok"), created)
            team_id = created["team_id"]
            dispatched = call("team", "team_dispatch", {"team_id": team_id, "task": "t1"})
            self.assertTrue(dispatched.get("ok"), dispatched)
            self.assertEqual(dispatched.get("assignee"), "agent-1")
            self.assertTrue(str(dispatched.get("engine", "")).startswith("fallback"))
            status = call("team", "team_status", {"team_id": team_id})
        self.assertTrue(status.get("ok"), status)
        self.assertEqual(status.get("team_id"), team_id)
        self.assertGreaterEqual(len(status.get("tasks") or []), 1)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(status["state_path"]).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(status["worktree"]).st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()


class LlmHttpTests(unittest.TestCase):
    def setUp(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gamai_plugins", "plugins", "team"))
        import team_core
        self.TC = team_core

    def test_redirects_are_not_followed_and_token_is_not_forwarded(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading
        from unittest.mock import patch

        seen = {"token": None, "posts": 0}

        class Target(BaseHTTPRequestHandler):
            def do_POST(self):
                seen["token"] = self.headers.get("X-Token")
                seen["posts"] += 1
                body = b'{"out":"OK","engine":"mock"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        target = HTTPServer(("127.0.0.1", 0), Target)

        class Redirect(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:%d/" % target.server_port)
                self.end_headers()

            def log_message(self, *args):
                pass

        redirect = HTTPServer(("127.0.0.1", 0), Redirect)
        threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (target, redirect)]
        for t in threads:
            t.start()
        try:
            with patch.object(self.TC, "LLM_URL", "http://127.0.0.1:%d/" % redirect.server_port), \
                 patch.dict(os.environ, {"GAMAI_LLM_TOKEN": "secret"}, clear=False):
                result = self.TC._llm_http("hi", "agent", timeout=3)
            self.assertEqual(result[0], "")
            self.assertEqual(seen["posts"], 0)
            self.assertIsNone(seen["token"])
        finally:
            for s in (target, redirect):
                s.shutdown()
                s.server_close()

    def test_plain_http_to_public_host_is_rejected(self):
        from unittest.mock import patch
        with patch.object(self.TC, "LLM_URL", "http://example.com/v1"):
            result = self.TC._llm_http("hi", "agent", timeout=1)
        self.assertEqual(result, ("", "fallback:insecure-url"))


class TeamIsolationTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX hook test")
    def test_untrusted_repo_hooks_are_not_executed(self):
        import subprocess
        import tempfile
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gamai_plugins", "plugins", "team"))
        import team_core

        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            os.makedirs(repo)
            subprocess.run(["git", "init", "-q", repo], check=True)
            with open(os.path.join(repo, "a.txt"), "w", encoding="utf-8") as fh:
                fh.write("a\n")
            subprocess.run(["git", "-C", repo, "add", "a.txt"], check=True)
            subprocess.run(["git", "-C", repo, "-c", "user.email=t@example.com",
                            "-c", "user.name=T", "commit", "-q", "-m", "init"], check=True)
            marker = os.path.join(tmp, "hook-ran")
            hook = os.path.join(repo, ".git", "hooks", "post-checkout")
            with open(hook, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\necho yes > %s\n" % marker)
            os.chmod(hook, 0o755)

            old = (team_core.TEAMS_DIR, team_core.WORKTREES_DIR)
            team_core.TEAMS_DIR = os.path.join(tmp, "state")
            team_core.WORKTREES_DIR = os.path.join(tmp, "work")
            try:
                c = team_core.create("review this repo", agents=2, repo=repo)
            finally:
                team_core.TEAMS_DIR, team_core.WORKTREES_DIR = old
            self.assertTrue(c.get("ok"), c)
            self.assertFalse(os.path.exists(marker))
            subprocess.run(["git", "-C", c["isolation"]["path"], "checkout", "-q", "HEAD"],
                           check=False, capture_output=True, text=True)
            self.assertFalse(os.path.exists(marker))


class TeamEdgeTests(unittest.TestCase):
    def setUp(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gamai_plugins", "plugins", "team"))
        import team_core
        self.TC = team_core
        self.tmp = tempfile.TemporaryDirectory()
        self.old = (team_core.TEAMS_DIR, team_core.WORKTREES_DIR)
        team_core.TEAMS_DIR = os.path.join(self.tmp.name, "state")
        team_core.WORKTREES_DIR = os.path.join(self.tmp.name, "work")

    def tearDown(self):
        self.TC.TEAMS_DIR, self.TC.WORKTREES_DIR = self.old
        self.tmp.cleanup()

    def test_multiline_goal_splits_before_cleaning(self):
        parts = self.TC.split_goal("analiza ponude\nprovjeri cijene\nnapisi izvjestaj", 3)
        self.assertEqual(len(parts), 3)
        self.assertIn("provjeri cijene", parts)

    def test_new_task_after_done_is_not_swallowed(self):
        c = self.TC.create("analiza ponude; provjeri cijene", agents=2)
        self.TC.dispatch(c["team_id"], "t1", llm=lambda p, a, t: ("x", "stub"))
        self.TC.dispatch(c["team_id"], "t2", llm=lambda p, a, t: ("y", "stub"))
        r = self.TC.dispatch(c["team_id"], "novi zadatak posle zavrsetka",
                             llm=lambda p, a, t: ("z", "stub"))
        self.assertTrue(r["ok"])
        self.assertEqual(r["task_id"], "t3")
        self.assertEqual(r["results_done"], "3/3")

    def test_reserved_windows_id_is_rejected(self):
        r = self.TC.create("test goal", team_id="con")
        self.assertFalse(r["ok"])

    def test_state_is_saved_before_isolation(self):
        from unittest.mock import patch
        with patch.object(self.TC, "isolate", side_effect=RuntimeError("boom")):
            c = self.TC.create("test goal")
        self.assertTrue(c["ok"])
        self.assertTrue(os.path.isfile(c["state_path"]))
        self.assertEqual(c["isolation"]["mode"], "error")


class TeamProxyTests(unittest.TestCase):
    def test_proxy_environment_is_ignored(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gamai_plugins", "plugins", "team"))
        import team_core
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading
        from unittest.mock import patch

        seen = {}

        class Target(BaseHTTPRequestHandler):
            def do_POST(self):
                seen["direct"] = True
                body = b'{"out":"OK"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Target)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            with patch.object(team_core, "LLM_URL", "http://127.0.0.1:%d/" % server.server_port), \
                 patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:1", "no_proxy": ""}, clear=False):
                result = team_core._llm_http("hi", "agent", timeout=3)
            self.assertEqual(result[0], "OK")
            self.assertTrue(seen.get("direct"))
        finally:
            server.shutdown()
            server.server_close()
