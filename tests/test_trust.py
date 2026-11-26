import hashlib
import json
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from gamai_plugins.cli import call


class TrustTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.policy = os.path.join(self.tmp.name, "policy.json")
        self.audit = os.path.join(self.tmp.name, "audit.jsonl")
        self.env = {"GAMAI_POLICY": self.policy, "GAMAI_AUDIT": self.audit}

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_policy_is_fail_closed(self):
        with patch.dict(os.environ, self.env, clear=False):
            r = call("trust", "managed_policy", {"action": "check", "tool": "read"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["decision"], "deny")
        self.assertIn("fail_closed", r["reason"])

    def test_allow_deny_and_default(self):
        with open(self.policy, "w", encoding="utf-8") as fh:
            json.dump({
                "version": 1,
                "default": "deny",
                "allow": {"tools": ["read"], "commands": ["re:^rm "]},
                "deny": {"commands": ["re:^rm -rf"]},
                "audit": True,
            }, fh)
        with patch.dict(os.environ, self.env, clear=False):
            allow = call("trust", "managed_policy", {"action": "check", "tool": "read"})
            default_deny = call("trust", "managed_policy", {"action": "check", "tool": "write"})
            deny_rule = call("trust", "managed_policy", {"action": "check", "command": "rm -rf /"})
            listed = call("trust", "managed_policy", {"action": "list"})
        self.assertEqual(allow["decision"], "allow")
        self.assertEqual(default_deny["decision"], "deny")
        self.assertEqual(default_deny["reason"], "policy_default")
        self.assertEqual(deny_rule["decision"], "deny")
        self.assertEqual(deny_rule["reason"], "deny_rule")
        self.assertIsInstance(listed["audit_tail"], list)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(self.audit).st_mode), 0o600)

    def test_marketplace_manifest_is_unsigned_but_ok(self):
        root = os.path.join(self.tmp.name, "pkg")
        os.makedirs(root)
        body = b"hello\n"
        with open(os.path.join(root, "a.txt"), "wb") as fh:
            fh.write(body)
        digest = hashlib.sha256(body).hexdigest()
        with open(os.path.join(root, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"name": "demo", "version": "1.0.0", "files": {"a.txt": digest}}, fh)
        with patch.dict(os.environ, self.env, clear=False):
            r = call("trust", "marketplace_verify", {"path": root})
        self.assertTrue(r["ok"])
        self.assertEqual(r["status"], "unsigned")
        self.assertTrue(r["hashes_ok"])
        self.assertEqual(r["missing"], [])
        self.assertEqual(r["mismatch"], [])


if __name__ == "__main__":
    unittest.main()


class TrustAuditTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "/dev/full is POSIX-only")
    def test_audit_failure_denies_when_policy_requires_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = os.path.join(tmp, "policy.json")
            with open(policy, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "default": "allow", "audit": True}, fh)
            env = {
                "GAMAI_POLICY": policy,
                "GAMAI_AUDIT": "/dev/full",
                "GAMAI_STATE": "/proc/gamai-no-such-state",
            }
            with patch.dict(os.environ, env, clear=False):
                r = call("trust", "managed_policy", {"action": "check", "tool": "read"})
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "audit_failed")
        self.assertFalse(r["allowed"])

    def test_audit_redacts_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = os.path.join(tmp, "policy.json")
            audit = os.path.join(tmp, "audit.jsonl")
            with open(policy, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "default": "allow", "audit": True}, fh)
            env = {"GAMAI_POLICY": policy, "GAMAI_AUDIT": audit}
            with patch.dict(os.environ, env, clear=False):
                r = call("trust", "managed_policy", {
                    "action": "check",
                    "command": 'curl -H "Authorization: Bearer supersecret" --password hunter2',
                })
            self.assertTrue(r["ok"])
            with open(audit, encoding="utf-8") as fh:
                text = fh.read()
            self.assertNotIn("supersecret", text)
            self.assertNotIn("hunter2", text)
            self.assertIn("[REDACTED]", text)


class TrustManifestTests(unittest.TestCase):
    def _pkg(self, tmp, extra=False):
        root = os.path.join(tmp, "pkg")
        os.makedirs(root)
        body = b"hello\n"
        with open(os.path.join(root, "a.txt"), "wb") as fh:
            fh.write(body)
        digest = hashlib.sha256(body).hexdigest()
        manifest = {"name": "demo", "version": "1.0.0",
                    "files": {"a.txt": digest}}
        if extra:
            with open(os.path.join(root, "extra.sh"), "w", encoding="utf-8") as fh:
                fh.write("echo bad\n")
        with open(os.path.join(root, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        return root, manifest

    def test_no_manifest_is_unverified_not_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "pkg")
            os.makedirs(root)
            with open(os.path.join(root, "a.txt"), "w", encoding="utf-8") as fh:
                fh.write("a\n")
            r = call("trust", "marketplace_verify", {"path": root})
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], "unverified")
        self.assertFalse(r["integrity_ok"])

    def test_unexpected_file_fails_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._pkg(tmp, extra=True)
            r = call("trust", "marketplace_verify", {"path": root})
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], "failed")
        self.assertIn("extra.sh", r["unexpected"])
        self.assertFalse(r["integrity_ok"])

    def test_self_signed_is_not_trusted(self):
        import base64
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        with tempfile.TemporaryDirectory() as tmp:
            root, manifest = self._pkg(tmp)
            key = ed25519.Ed25519PrivateKey.generate()
            payload = {k: v for k, v in manifest.items()}
            msg = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), default=str).encode()
            sig = key.sign(msg)
            pub = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            manifest["signature"] = {"alg": "ed25519",
                                     "value": base64.b64encode(sig).decode()}
            manifest["public_key"] = base64.b64encode(pub).decode()
            with open(os.path.join(root, "manifest.json"), "w", encoding="utf-8") as fh:
                json.dump(manifest, fh)
            r = call("trust", "marketplace_verify", {"path": root})
        self.assertEqual(r["status"], "self_signed")
        self.assertFalse(r["trusted"])
        self.assertFalse(r["ok"])
        self.assertTrue(r["signature"]["valid"])

    def test_pinned_key_is_trusted(self):
        import base64
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        with tempfile.TemporaryDirectory() as tmp:
            root, manifest = self._pkg(tmp)
            key = ed25519.Ed25519PrivateKey.generate()
            msg = json.dumps(manifest, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), default=str).encode()
            sig = key.sign(msg)
            pub = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            manifest["signature"] = {"alg": "ed25519",
                                     "value": base64.b64encode(sig).decode()}
            with open(os.path.join(root, "manifest.json"), "w", encoding="utf-8") as fh:
                json.dump(manifest, fh)
            r = call("trust", "marketplace_verify",
                     {"path": root, "public_key": base64.b64encode(pub).decode()})
        self.assertEqual(r["status"], "verified")
        self.assertTrue(r["trusted"])
        self.assertTrue(r["ok"])


class TrustPolicyEdgeTests(unittest.TestCase):
    def test_missing_default_is_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = os.path.join(tmp, "policy.json")
            audit = os.path.join(tmp, "audit.jsonl")
            with open(policy, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "allow": {"commands": ["ls"]}}, fh)
            with patch.dict(os.environ, {"GAMAI_POLICY": policy, "GAMAI_AUDIT": audit}, clear=False):
                r = call("trust", "managed_policy", {"action": "check", "command": "rm -rf /tmp/x"})
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["reason"], "policy_default")

    def test_path_is_normalized_before_matching(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = os.path.join(tmp, "policy.json")
            audit = os.path.join(tmp, "audit.jsonl")
            with open(policy, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "default": "allow",
                           "deny": {"paths": ["/etc/*"]}}, fh)
            with patch.dict(os.environ, {"GAMAI_POLICY": policy, "GAMAI_AUDIT": audit}, clear=False):
                r = call("trust", "managed_policy", {"action": "check", "path": "/tmp/../etc/shadow"})
        self.assertEqual(r["decision"], "deny")

    def test_multiline_command_segments_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = os.path.join(tmp, "policy.json")
            audit = os.path.join(tmp, "audit.jsonl")
            with open(policy, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "default": "allow",
                           "deny": {"commands": ["re:^rm -rf"]}}, fh)
            with patch.dict(os.environ, {"GAMAI_POLICY": policy, "GAMAI_AUDIT": audit}, clear=False):
                r = call("trust", "managed_policy", {"action": "check", "command": "echo hi\nrm -rf /"})
        self.assertEqual(r["decision"], "deny")


class TrustAuditIsolationTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "symlink/audit test is POSIX-only")
    def test_symlink_audit_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = os.path.join(tmp, "policy.json")
            target = os.path.join(tmp, "target.txt")
            audit = os.path.join(tmp, "audit.jsonl")
            with open(policy, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "default": "allow", "audit": True}, fh)
            with open(target, "w", encoding="utf-8") as fh:
                fh.write("unchanged\n")
            os.symlink(target, audit)
            env = {"GAMAI_POLICY": policy, "GAMAI_AUDIT": audit,
                   "GAMAI_STATE": "/proc/gamai-no-such-state"}
            with patch.dict(os.environ, env, clear=False):
                r = call("trust", "managed_policy", {"action": "check", "tool": "read"})
            with open(target, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "unchanged\n")
        self.assertEqual(r["decision"], "deny")

    def test_audit_disable_does_not_bypass_required_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = os.path.join(tmp, "policy.json")
            audit = os.path.join(tmp, "audit.jsonl")
            with open(policy, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "default": "allow", "audit": True}, fh)
            env = {"GAMAI_POLICY": policy, "GAMAI_AUDIT": audit,
                   "GAMAI_AUDIT_DISABLE": "1"}
            with patch.dict(os.environ, env, clear=False):
                r = call("trust", "managed_policy", {"action": "check", "tool": "read"})
            self.assertEqual(r["decision"], "allow")
            self.assertTrue(os.path.isfile(audit))
