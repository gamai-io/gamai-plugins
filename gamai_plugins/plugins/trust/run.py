#!/usr/bin/env python3
"""trust plugin - managed/enterprise policy + marketplace integrity (no core changes).

Runtime contract (PLUGIN_LOADER_V1):
  argv[1] = tool name, stdin = one JSON object, stdout = one JSON object, exit 0.
  Never executes package code, never prints secrets.

Tools
  managed_policy(action=load|check|list)
      reads GAMAI_POLICY (default ~/.config/gamai/trust/policy.json).
      deny has priority; missing/unreadable/invalid policy => deny (fail-closed).
      check writes one audit line to GAMAI_AUDIT (default ~/.local/state/gamai/trust/audit.jsonl)
      (override GAMAI_AUDIT; GAMAI_AUDIT_DISABLE=1 disables).

  marketplace_verify(path)
      SHA256 over files, manifest (manifest.json | TRUST.json | trust.json) with
      {"files": {relpath: sha256}}, optional ed25519 signature (cryptography),
      detects missing / mismatch / unexpected files. Read-only.

Policy format (all rule sections optional):
  {
    "version": 1,
    "default": "allow" | "deny",          # only used when policy is valid
    "audit": true,
    "deny":  {"tools": [...], "commands": [...], "paths": [...]},
    "allow": {"tools": [...], "commands": [...], "paths": [...]}
  }
  Pattern = case-insensitive glob, or regex when prefixed with "re:".
"""
import base64
import binascii
import fnmatch
import hashlib
import json
import os
import re
import stat
import sys
import time

for _stream in (sys.stdin, sys.stdout):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

TOOL = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
DEFAULT_HOME = os.path.expanduser(os.environ.get("GAMAI_HOME", "~/.config/gamai"))
DEFAULT_STATE = os.path.expanduser(os.environ.get("GAMAI_STATE", "~/.local/state/gamai"))
POLICY_PATH = os.environ.get("GAMAI_POLICY", os.path.join(DEFAULT_HOME, "trust", "policy.json"))
AUDIT_PATH = os.environ.get("GAMAI_AUDIT", os.path.join(DEFAULT_STATE, "trust", "audit.jsonl"))
AUDIT_FALLBACK = os.path.join(DEFAULT_STATE, "trust", "audit.jsonl")
MANIFEST_NAMES = ("manifest.json", "TRUST.json", "trust.json")
MAX_FILES = 5000
MAX_FILE_BYTES = 64 * 1024 * 1024
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".mypy_cache"}
SIGN_EXCLUDE = {"signature", "signatures", "public_key", "sig_alg", "signature_alg"}
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_REDACT_RES = (
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)(authorization)\s*[=:]\s*[^\s,;]+(?:\s+[^\s,;]+)?"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)([A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*[=:]\s*[^\s,;]+"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)(--?(?:password|passwd|pwd|token|secret|api[_-]?key|access-key)\s+)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1[REDACTED]"),
)


def redact(value, limit=500):
    if value is None:
        return None
    text = str(value)
    for pattern, repl in _REDACT_RES:
        text = pattern.sub(repl, text)
    if len(text) > limit:
        text = text[:limit] + "...[truncated]"
    return text


# ------------------------------------------------------------------ basics
def emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, default=str))
    sys.stdout.write("\n")
    return 0


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def err(code, message):
    return {"ok": False, "err": code, "detail": message, "ts": now()}


def read_stdin():
    try:
        data = json.load(sys.stdin)
    except Exception as exc:
        return None, "nevalidan JSON na stdin: %s" % exc
    if not isinstance(data, dict):
        return None, "ocekivan JSON objekat"
    return data, None


def canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def sha256_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                raise ValueError("fajl veci od %d B" % MAX_FILE_BYTES)
            digest.update(chunk)
    return digest.hexdigest()


# ------------------------------------------------------------ managed policy
def load_policy():
    """Return (policy, error). Never raises. Missing/invalid => fail-closed."""
    if not os.path.isfile(POLICY_PATH):
        return None, "policy_missing"
    try:
        with open(POLICY_PATH, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        policy = json.loads(raw)
    except (OSError, ValueError) as exc:
        return None, "policy_invalid: %s" % exc
    if not isinstance(policy, dict):
        return None, "policy_invalid: root nije objekat"
    version = policy.get("version", 1)
    if version not in (1, "1"):
        return None, "policy_invalid: nepodrzana verzija %r" % (version,)
    default = policy.get("default", "deny")
    if default not in ("allow", "deny"):
        return None, "policy_invalid: default mora biti allow|deny"
    for section in ("allow", "deny"):
        rules = policy.get(section, {})
        if rules is None:
            rules = {}
        if not isinstance(rules, dict):
            return None, "policy_invalid: %s nije objekat" % section
        for key in ("tools", "commands", "paths"):
            values = rules.get(key, [])
            if values is None:
                continue
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                return None, "policy_invalid: %s.%s mora biti lista stringova" % (section, key)
            for pattern in values:
                body = pattern[3:] if pattern.lower().startswith("re:") else None
                if body is not None:
                    try:
                        re.compile(body, re.I)
                    except re.error as exc:
                        return None, "policy_invalid: regex %r: %s" % (pattern, exc)
    return policy, None


def matches(pattern, value):
    if value is None:
        return False
    value = str(value)
    if pattern.lower().startswith("re:"):
        return re.search(pattern[3:], value, re.I) is not None
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


_SHELL_SPLIT_RE = re.compile(r"(?:\r?\n|;|&&|\|\||\||&|\$\(|\)|`|\{|\}|\(|\))")


def _command_segments(command):
    if not command:
        return [None]
    parts = [p.strip() for p in _SHELL_SPLIT_RE.split(command) if p.strip()]
    return parts or [None]


def rule_hits(rules, tool, command, path):
    hits = []
    for key, value in (("tools", tool), ("commands", command), ("paths", path)):
        for pattern in (rules.get(key) or []):
            if matches(pattern, value):
                hits.append("%s:%s" % (key, pattern))
    return hits


def rule_hits_all(rules, tool, command, path):
    hits = rule_hits(rules, tool, command, path)
    for segment in _command_segments(command):
        hits += rule_hits(rules, tool, segment, path)
    return list(dict.fromkeys(hits))


def audit_paths():
    if AUDIT_PATH != AUDIT_FALLBACK:
        return [AUDIT_PATH, AUDIT_FALLBACK]
    return [AUDIT_PATH]


MAX_AUDIT_BYTES = 10 * 1024 * 1024


def _rotate_audit(path):
    try:
        if os.path.getsize(path) < MAX_AUDIT_BYTES:
            return
    except FileNotFoundError:
        return
    except OSError:
        raise
    if os.path.islink(path):
        raise OSError("audit path is a symlink")
    os.replace(path, path + ".1")


def audit(record, force=False):
    """Best-effort append; returns (path_used, error). Never raises."""
    if not force and os.environ.get("GAMAI_AUDIT_DISABLE", "").strip() in ("1", "true", "yes"):
        return None, None
    line = canon(record) + "\n"
    last_error = None
    for path in audit_paths():
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, mode=0o700, exist_ok=True)
            if os.path.islink(path):
                raise OSError("audit path is a symlink")
            _rotate_audit(path)
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            flags |= getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError("audit path is not a regular file")
                with os.fdopen(fd, "a", encoding="utf-8") as fh:
                    fh.write(line)
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return path, None
        except OSError as exc:
            last_error = str(exc)
    return None, last_error


def active_audit_path():
    for path in audit_paths():
        if os.path.exists(path):
            return path
    return audit_paths()[0]


def audit_tail(limit=20):
    rows = []
    for path in audit_paths():
        try:
            if os.path.islink(path):
                continue
            with open(path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 256 * 1024))
                data = fh.read().decode("utf-8", "replace")
            for line in data.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    rows.append({"_unparsable": line[:200]})
            break
        except OSError:
            continue
    return rows[-limit:]


def policy_summary(policy, error):
    if policy is None:
        return {"path": POLICY_PATH, "loaded": False, "error": error,
                "fail_closed": True, "rules": {"allow": 0, "deny": 0}}
    counts = {"allow": 0, "deny": 0}
    for section in ("allow", "deny"):
        rules = policy.get(section) or {}
        counts[section] = sum(len(rules.get(k) or []) for k in ("tools", "commands", "paths"))
    default = policy.get("default", "deny")
    return {"path": POLICY_PATH, "loaded": True, "error": None,
            "version": policy.get("version", 1), "default": default,
            "audit": bool(policy.get("audit", True)), "rules": counts,
            "fail_closed": default == "deny"}


def tool_managed_policy(args):
    action = str(args.get("action", "")).strip().lower()
    if action not in ("load", "check", "list"):
        return err("bad_action", "action mora biti load|check|list")

    policy, error = load_policy()
    summary = policy_summary(policy, error)

    if action == "load":
        return {"ok": True, "policy": summary, "ts": now()}

    if action == "list":
        return {"ok": True, "policy": summary, "audit_path": active_audit_path(),
                "audit_tail": audit_tail(), "ts": now()}

    tool = args.get("tool")
    command = args.get("command")
    path = args.get("path")
    tool = str(tool) if tool is not None else None
    command = str(command) if command is not None else None
    path = str(path) if path is not None else None
    if not any(v not in (None, "") for v in (tool, command, path)):
        return err("no_subject", "check trazi barem jedno od: tool, command, path")

    match_path = os.path.normpath(path).replace("\\", "/") if path else None
    if policy is None:
        decision, reason, hits = "deny", "fail_closed:%s" % error, []
    else:
        deny_hits = rule_hits_all(policy.get("deny") or {}, tool, command, match_path)
        allow_hits = rule_hits_all(policy.get("allow") or {}, tool, command, match_path)
        if deny_hits:
            decision, reason, hits = "deny", "deny_rule", deny_hits
        elif allow_hits:
            decision, reason, hits = "allow", "allow_rule", allow_hits
        else:
            decision = policy.get("default", "deny")
            reason, hits = "policy_default", []

    record = {"ts": now(), "action": "check",
              "tool": redact(tool, 200), "command": redact(command, 1000),
              "path": redact(path, 500), "decision": decision, "reason": reason,
              "matched": hits, "policy": summary["path"]}
    audit_required = True if policy is None else bool(policy.get("audit", True))
    audit_used, audit_error = (None, None)
    if audit_required:
        audit_used, audit_error = audit(record, force=True)
        if audit_error:
            decision, reason, hits = "deny", "audit_failed", []

    out = {"ok": True, "decision": decision, "allowed": decision == "allow",
           "reason": reason, "matched": hits, "policy": summary, "ts": record["ts"]}
    if audit_used:
        out["audit_path"] = audit_used
    if audit_error:
        out["audit_error"] = audit_error
    if audit_required:
        out["audit_required"] = True
    return out


# -------------------------------------------------------- marketplace verify
def collect_files(root):
    """Return ({relpath: abspath}, symlinks_skipped, truncated, errors)."""
    files = {}
    skipped_symlinks = 0
    skipped_content = False
    truncated = False
    errors = []
    if os.path.isfile(root):
        return {os.path.basename(root): root}, 0, False, False, errors

    def onerror(exc):
        errors.append(str(exc))

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=onerror):
        keep = []
        for d in dirnames:
            if d in SKIP_DIRS:
                # hashing nothing here and calling the package complete would
                # say "verified" about files nobody looked at
                for _dirpath, _dirnames, names in os.walk(os.path.join(dirpath, d)):
                    if names:
                        skipped_content = True
                        break
                continue
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                skipped_symlinks += 1
                continue
            keep.append(d)
        dirnames[:] = sorted(keep)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full):
                skipped_symlinks += 1
                continue
            if not os.path.isfile(full):
                continue
            if len(files) >= MAX_FILES:
                truncated = True
                break
            files[rel] = full
        if truncated:
            break
    return files, skipped_symlinks, truncated, skipped_content, errors


def find_manifest(root, files):
    if os.path.isfile(root):
        return None, None
    for name in MANIFEST_NAMES:
        if name in files:
            return name, files[name]
    return None, None


MAX_MANIFEST_BYTES = 10 * 1024 * 1024


def load_manifest(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            return None, "manifest_too_large", None
        data = json.loads(raw.decode("utf-8", "replace"))
    except (OSError, ValueError) as exc:
        return None, "manifest_invalid: %s" % exc, None
    if not isinstance(data, dict):
        return None, "manifest_invalid: root nije objekat", raw
    expected = data.get("files")
    if not isinstance(expected, dict):
        return None, "manifest_invalid: nedostaje files{}", raw
    clean = {}
    for rel, digest in expected.items():
        if not isinstance(rel, str) or not isinstance(digest, str):
            return None, "manifest_invalid: files mora biti {string: sha256}", raw
        rel = rel.replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        if rel.startswith("/") or ".." in rel.split("/"):
            return None, "manifest_invalid: nelegalna putanja %r" % rel, raw
        if not HEX64_RE.match(digest.lower()):
            return None, "manifest_invalid: nelegalan sha256 za %r" % rel, raw
        clean[rel] = digest.lower()
    data["files"] = clean
    if "ignore" in data:
        ignore = data.get("ignore")
        if ignore is None:
            ignore = []
        if not isinstance(ignore, list) or not all(isinstance(x, str) for x in ignore):
            return None, "manifest_invalid: ignore mora biti lista stringova", raw
        for pattern in ignore:
            body = pattern[3:] if pattern.lower().startswith("re:") else None
            if body is not None:
                try:
                    re.compile(body, re.I)
                except re.error as exc:
                    return None, "manifest_invalid: ignore regex %r: %s" % (pattern, exc), raw
        data["ignore"] = ignore
    return data, None, raw


def b64decode_any(value):
    try:
        return base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError):
        try:
            return base64.urlsafe_b64decode(value.strip() + "===")
        except Exception:
            return None


def decode_public_key(value):
    if not isinstance(value, str) or not value.strip():
        return None, "public_key_missing"
    text = value.strip()
    if "BEGIN PUBLIC KEY" in text:
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            return load_pem_public_key(text.encode("utf-8")), None
        except Exception as exc:
            return None, "public_key_invalid: %s" % exc
    raw = None
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        raw = bytes.fromhex(text)
    else:
        raw = b64decode_any(text)
    if not raw or len(raw) != 32:
        return None, "public_key_invalid: ocekivan 32B ed25519 kljuc"
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception:
        return None, "ed25519_unavailable"
    try:
        return Ed25519PublicKey.from_public_bytes(raw), None
    except Exception as exc:
        return None, "public_key_invalid: %s" % exc


def verify_signature(manifest, pinned_key=None):
    """Return dict {present, valid, pinned, alg, error}. Never raises."""
    sig = manifest.get("signature", manifest.get("signatures"))
    pub = pinned_key or manifest.get("public_key")
    if isinstance(sig, dict):
        if not pinned_key:
            pub = sig.get("public_key", pub)
        alg = str(sig.get("alg", "ed25519")).lower()
        value = sig.get("value")
    else:
        alg = str(manifest.get("sig_alg", manifest.get("signature_alg", "ed25519"))).lower()
        value = sig
    pinned = bool(pinned_key)
    if not value:
        return {"present": False, "valid": False, "pinned": pinned,
                "alg": alg or "ed25519", "error": "unsigned"}
    if alg != "ed25519":
        return {"present": True, "valid": False, "pinned": pinned,
                "alg": alg, "error": "unsupported_alg"}
    key, key_err = decode_public_key(pub)
    if key is None:
        return {"present": True, "valid": False, "pinned": pinned,
                "alg": alg, "error": key_err}
    signature = value if isinstance(value, str) else None
    raw_sig = b64decode_any(signature) if signature else None
    if not raw_sig or len(raw_sig) != 64:
        return {"present": True, "valid": False, "pinned": pinned,
                "alg": alg, "error": "signature_invalid_b64"}
    payload = {k: v for k, v in manifest.items() if k not in SIGN_EXCLUDE}
    message = canon(payload).encode("utf-8")
    try:
        key.verify(raw_sig, message)
    except Exception as exc:
        return {"present": True, "valid": False, "pinned": pinned, "alg": alg,
                "error": "signature_mismatch: %s" % type(exc).__name__}
    return {"present": True, "valid": True, "pinned": pinned, "alg": alg, "error": None}


def trust_score(hashes_ok, sig, manifest_ok, unexpected, named):
    score = 0
    if manifest_ok:
        score += 20
    if hashes_ok:
        score += 30
    if sig.get("valid"):
        score += 30 if sig.get("pinned") else 15
    if not unexpected:
        score += 10
    if named:
        score += 10
    if not hashes_ok:
        score = min(score, 15)
    return max(0, min(100, score))


def tool_marketplace_verify(args):
    raw_path = args.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        return err("bad_path", "path je obavezan")
    root = os.path.abspath(os.path.expanduser(raw_path.strip()))
    if not os.path.exists(root):
        return err("path_missing", "putanja ne postoji: %s" % root)

    files, skipped_symlinks, truncated, skipped_content, scan_errors = collect_files(root)
    if not files:
        return err("no_files", "nema regularnih fajlova za provjeru")

    manifest_name, manifest_path = find_manifest(root, files)
    manifest = None
    manifest_error = None
    manifest_raw = None
    if manifest_path:
        manifest, manifest_error, manifest_raw = load_manifest(manifest_path)

    pinned_key = args.get("public_key")
    if not isinstance(pinned_key, str) or not pinned_key.strip():
        pinned_key = os.environ.get("GAMAI_TRUST_PUBKEY", "")
    signature = {"present": False, "valid": False, "pinned": False,
                 "alg": "ed25519", "error": "unsigned"}
    if manifest:
        signature = verify_signature(manifest, pinned_key or None)
    ignore = []
    if manifest and signature.get("valid") and signature.get("pinned"):
        ignore = [str(x).replace("\\", "/") for x in (manifest.get("ignore") or [])]
    ignore.append(manifest_name or "")

    def ignored(rel):
        return rel in ignore or any(matches(p, rel) for p in ignore if p)

    actual = {}
    hash_errors = []
    for rel, full in sorted(files.items()):
        try:
            actual[rel] = sha256_file(full)
        except (OSError, ValueError) as exc:
            hash_errors.append({"file": rel, "error": str(exc)})

    computed_sha256 = sha256_bytes(canon(actual).encode("utf-8"))
    manifest_sha256 = sha256_bytes(manifest_raw) if manifest_raw else None

    missing, mismatch, unexpected = [], [], []
    hashes_ok = False
    if manifest:
        expected = manifest["files"]
        for rel, digest in sorted(expected.items()):
            if rel not in actual:
                missing.append(rel)
            elif actual[rel] != digest:
                mismatch.append({"file": rel, "expected": digest,
                                 "actual": actual[rel]})
        unexpected = sorted(rel for rel in actual if rel not in expected and not ignored(rel))
        hashes_ok = not missing and not mismatch and not hash_errors
    elif manifest_path:
        manifest_error = manifest_error or "manifest_invalid"
    else:
        manifest_error = manifest_error or "manifest_missing"

    complete = bool(manifest) and hashes_ok and not unexpected and not truncated \
        and not skipped_symlinks and not skipped_content and not scan_errors
    sig = signature
    named = bool(manifest and manifest.get("name") and manifest.get("version"))
    score = trust_score(complete, sig, bool(manifest), unexpected, named)

    if complete and sig.get("valid") and sig.get("pinned"):
        status = "verified"
    elif complete and sig.get("valid"):
        status = "self_signed"
    elif complete and not sig.get("present"):
        status = "unsigned"
    elif manifest_path:
        status = "failed"
    else:
        status = "unverified"

    return {
        "ok": status in ("verified", "unsigned"),
        "status": status,
        "trusted": status == "verified",
        "integrity_ok": complete,
        "path": root,
        "mode": "file" if os.path.isfile(root) else "dir",
        "manifest": manifest_name,
        "manifest_sha256": manifest_sha256,
        "computed_sha256": computed_sha256,
        "files_total": len(actual),
        "hashes_ok": hashes_ok,
        "signature": sig,
        "missing": missing,
        "mismatch": mismatch,
        "unexpected": unexpected,
        "hash_errors": hash_errors,
        "skipped_symlinks": skipped_symlinks,
        "skipped_content": skipped_content,
        "scan_errors": scan_errors,
        "truncated": truncated,
        "complete": complete,
        "manifest_error": manifest_error,
        "trust_score": score,
        "ts": now(),
    }


# ------------------------------------------------------------------- main
def main():
    data, stdin_error = read_stdin()
    if TOOL == "managed_policy":
        if data is None:
            return emit(err("bad_input", stdin_error))
        return emit(tool_managed_policy(data))
    if TOOL == "marketplace_verify":
        if data is None:
            return emit(err("bad_input", stdin_error))
        return emit(tool_marketplace_verify(data))
    return emit(err("unknown_tool", "nepoznat alat: %r" % TOOL))


if __name__ == "__main__":
    sys.exit(main())
