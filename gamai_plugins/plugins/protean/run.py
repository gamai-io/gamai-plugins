#!/usr/bin/env python3
"""PROTEAN sandbox runner (stdin=args JSON, stdout=JSON).

Chain: genome -> signed lease (HMAC-SHA256, TTL, genome+cmd binding) -> policy
gate -> substrate -> evidence. Fail-closed on unknown risk/substrate, invalid
or expired lease, TTL overflow, unsupported network request, and executables
outside the genome allowlist.

Substrates:
  low      bwrap (user/pid/net/uts/ipc/cgroup namespaces, ro-root, tmpfs /tmp)
  medium   Docker runc (--network=none, cap-drop ALL, no-new-privileges,
           read-only root, tmpfs /tmp, pids/mem/cpu limits, uid 65534)
  high     Docker runc + default-deny seccomp allowlist
  critical denied locally (no /dev/kvm); remote=true -> SSH to a configured
           remote host and run under gVisor (runsc) if it is reachable and ready
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

BASE = os.path.expanduser(os.environ.get("PROTEAN_HOME", "~/.config/gamai/protean"))
os.makedirs(BASE, mode=0o700, exist_ok=True)
try:
    os.chmod(BASE, 0o700)
except OSError:
    pass
LEASE_KEY_PATH = os.path.join(BASE, "lease.key")
SECCOMP_PATH = os.path.join(BASE, "seccomp.json")
if not os.path.isfile(SECCOMP_PATH):
    bundled = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seccomp.json")
    if os.path.isfile(bundled):
        shutil.copyfile(bundled, SECCOMP_PATH)
RUNS_DIR = os.path.join(BASE, "runs")

# Putanje s tajnama koje sandboxirana komanda NE smije citati.
# Maskiraju se unutar bwrap sandboxa (protean sam ih i dalje vidi na hostu).
SECRET_MASKS = (
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh",
    "/etc/ssl/private",
    "/etc/pki/private",
    "/etc/security/opasswd",
    os.path.expanduser("~/.ssh"),
    os.path.expanduser("~/.aws"),
    os.path.expanduser("~/.config/gamai"),
    os.path.join(BASE, "lease.key"),
)
BWRAP_ROOTS = ("/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/share",
               "/bin", "/sbin", "/lib", "/lib64")
BWRAP_ETC_ALLOW = (
    "/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/hosts",
    "/etc/hostname", "/etc/localtime", "/etc/timezone", "/etc/services",
    "/etc/protocols", "/etc/ssl/certs", "/etc/ssl/openssl.cnf",
    "/etc/ca-certificates", "/etc/ca-certificates.conf", "/etc/ld.so.cache",
    "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
    "/etc/mime.types", "/etc/gitconfig",
)
BWRAP_TMPFS_SIZE = 32 * 1024 * 1024
TOTAL_BUDGET_S = 56.0  # manifest timeout_s=60; ostatak je rezerva za evidenciju
EMPTY_MASK_FILE = os.path.join(BASE, ".empty_mask")

IMAGE = os.environ.get("PROTEAN_IMAGE", "python:3.12-alpine")
REMOTE_HOST = os.environ.get("PROTEAN_REMOTE_HOST", "")
REMOTE_PORT = os.environ.get("PROTEAN_REMOTE_PORT", "22")
REMOTE_KEY = os.environ.get("PROTEAN_REMOTE_KEY", "")
REMOTE_USER = os.environ.get("PROTEAN_REMOTE_USER", "root")
KNOWN_HOSTS = os.path.expanduser(os.environ.get("PROTEAN_KNOWN_HOSTS", "~/.ssh/known_hosts"))
SSH_STRICT = os.environ.get("PROTEAN_SSH_STRICT", "accept-new")
if SSH_STRICT not in ("yes", "accept-new", "no"):
    SSH_STRICT = "accept-new"
HIGH_REMOTE = os.environ.get("PROTEAN_HIGH_REMOTE", "0") == "1"
PATH_ENV = os.environ.get(
    "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)
CLEAN_ENV = {"PATH": PATH_ENV, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/tmp"}

ALLOWED_RISKS = ("low", "medium", "high", "critical")
TTL_MAX = 50
TIMEOUT_MAX = 45
CMD_MAX = 4096
OUT_CLIP = 8000
CAPTURE_LIMIT = 64 * 1024

TOOLS = {
    "sh", "dash", "bash", "cat", "echo", "printf", "ls", "id", "uname",
    "head", "tail", "wc", "sleep", "true", "false", "date", "whoami",
    "pwd", "grep", "sed", "awk", "cut", "tr", "sort", "uniq", "find",
    "test", "[", "stat", "readlink", "realpath", "dirname", "basename",
    "seq", "hostname", "mktemp", "touch", "df", "du", "ps", "timeout",
    "base64", "sha256sum", "md5sum", "tar", "gzip", "gunzip", "node",
    "python3", "python", "git",
}
SHELL_KEYWORDS = {
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do",
    "done", "case", "esac", "function", "select", "time", "!", "{", "(",
}
FIRST_TOKEN_RE = re.compile(
    r"^\s*((?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|\"[^\"]*\"|\S*)\s+)*)"
    r"([^\s;|&<>`]+)"
)


def emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, sort_keys=True))
    sys.stdout.write("\n")
    return 0


def _read_capped(stream, sink):
    total = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        if total < CAPTURE_LIMIT:
            take = chunk[:CAPTURE_LIMIT - total]
            sink.append(take)
            total += len(take)


def run_limited(argv, timeout, env=None, cwd=None):
    """Run a process with bounded stdout/stderr capture (memory-safe)."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, cwd=cwd)
    out_chunks, err_chunks = [], []
    readers = [
        threading.Thread(target=_read_capped, args=(proc.stdout, out_chunks), daemon=True),
        threading.Thread(target=_read_capped, args=(proc.stderr, err_chunks), daemon=True),
    ]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        try:
            rc = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            rc = None
    for reader in readers:
        reader.join(timeout=2)
    for stream in (proc.stdout, proc.stderr):
        try:
            stream.close()
        except Exception:
            pass
    return rc, b"".join(out_chunks), b"".join(err_chunks), timed_out


def clip(text, limit=OUT_CLIP):
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[skraceno %d znakova]" % (len(text) - limit)


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def load_lease_key():
    try:
        with open(LEASE_KEY_PATH, "rb") as fh:
            key = fh.read()
    except FileNotFoundError:
        key = secrets.token_bytes(32)
        try:
            fd = os.open(LEASE_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
        except FileExistsError:
            with open(LEASE_KEY_PATH, "rb") as fh:
                key = fh.read()
    if len(key) < 32:
        raise RuntimeError("lease.key je prekratak")
    try:
        os.chmod(LEASE_KEY_PATH, 0o600)
    except OSError:
        pass
    return key


def genome_for(risk, net, timeout_s, substrate):
    ttl = min(max(int(timeout_s) + 5, 10), TTL_MAX)
    if risk == "low":
        fs_read, fs_write = list(BWRAP_ROOTS), ["/tmp"]
        cpu, mem_mb, pids = 0, 0, 0
    elif risk in ("medium", "high"):
        fs_read, fs_write = ["/"], ["/tmp"]
        cpu, mem_mb, pids = 1, 256, 128
    else:
        fs_read, fs_write = ["/"], ["/tmp"]
        cpu, mem_mb, pids = 1, 256, 128
    return {
        "version": 1,
        "risk": risk,
        "substrate": substrate,
        "fs_read": fs_read,
        "fs_write": fs_write,
        "net": bool(net),
        "tools": sorted(TOOLS),
        "cpu": cpu,
        "mem_mb": mem_mb,
        "pids": pids,
        "ttl": ttl,
    }


def cmd_hash(cmd):
    return sha256_hex(cmd.encode("utf-8"))


def mint_lease(genome, risk, cmd, now=None):
    now = int(time.time() if now is None else now)
    payload = {
        "v": 1,
        "lease_id": "pl_" + secrets.token_hex(12),
        "risk": risk,
        "genome": genome,
        "genome_hash": sha256_hex(canon(genome)),
        "cmd_hash": cmd_hash(cmd),
        "issued_at": now,
        "expires_at": now + int(genome["ttl"]),
        "nonce": secrets.token_hex(16),
    }
    key = load_lease_key()
    payload["hmac"] = hmac.new(
        key, canon(payload).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return payload


def verify_lease(lease, genome, risk, cmd, now=None):
    now = int(time.time() if now is None else now)
    if not isinstance(lease, dict):
        return False, "lease nije objekat"
    required = (
        "v", "lease_id", "risk", "genome", "genome_hash", "cmd_hash",
        "issued_at", "expires_at", "nonce", "hmac",
    )
    for field in required:
        if field not in lease:
            return False, "lease nema polje %s" % field
    if lease.get("v") != 1:
        return False, "nepoznata verzija lease-a"
    if not re.match(r"^pl_[0-9a-f]{24}$", str(lease.get("lease_id"))):
        return False, "nevalidan lease_id"
    if lease.get("risk") != risk:
        return False, "lease risk se ne poklapa"
    if lease.get("genome") != genome:
        return False, "lease genom se ne poklapa"
    expected_genome = sha256_hex(canon(genome))
    if not hmac.compare_digest(str(lease.get("genome_hash")), expected_genome):
        return False, "genome_hash se ne poklapa"
    if not hmac.compare_digest(str(lease.get("cmd_hash")), cmd_hash(cmd)):
        return False, "cmd_hash se ne poklapa"
    try:
        issued = int(lease.get("issued_at"))
        expires = int(lease.get("expires_at"))
        ttl = int(genome.get("ttl"))
    except (TypeError, ValueError):
        return False, "nevalidan TTL"
    if expires - issued != ttl or ttl < 1 or ttl > TTL_MAX:
        return False, "nevalidan TTL u lease-u"
    if now < issued - 5:
        return False, "lease jos nije vazeci"
    if now >= expires:
        return False, "lease je istekao (TTL %ds)" % ttl
    signature = str(lease.get("hmac"))
    if not re.match(r"^[0-9a-f]{64}$", signature):
        return False, "nevalidan potpis"
    payload = {k: v for k, v in lease.items() if k != "hmac"}
    expected = hmac.new(
        load_lease_key(), canon(payload).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False, "HMAC potpis nije validan"
    return True, ""


def parse_args(raw):
    if not isinstance(raw, dict):
        return None, "args moraju biti JSON objekat"
    cmd = raw.get("cmd")
    risk = raw.get("risk")
    if not isinstance(cmd, str) or not cmd.strip():
        return None, "cmd mora biti neprazan string"
    if len(cmd) > CMD_MAX:
        return None, "cmd je predug (max %d)" % CMD_MAX
    if "\x00" in cmd:
        return None, "cmd sadrzi NUL"
    if risk not in ALLOWED_RISKS:
        return None, "nepoznat risk (dozvoljeno: %s)" % ", ".join(ALLOWED_RISKS)
    net = raw.get("net", False)
    if not isinstance(net, bool):
        return None, "net mora biti boolean"
    remote = raw.get("remote", False)
    if not isinstance(remote, bool):
        return None, "remote mora biti boolean"
    timeout_s = raw.get("timeout_s", 20)
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, int):
        return None, "timeout_s mora biti cijeli broj"
    if not 1 <= timeout_s <= TIMEOUT_MAX:
        return None, "timeout_s mora biti 1..%d" % TIMEOUT_MAX
    workdir = raw.get("workdir")
    if workdir is not None:
        if not isinstance(workdir, str) or not workdir.startswith("/"):
            return None, "workdir mora biti apsolutna putanja ili null"
        if ".." in workdir.split("/") or len(workdir) > 256:
            return None, "nevalidan workdir"
    if net and risk != "low":
        return None, "net=true nije dozvoljen za risk=%s (mreza je iskljucena)" % risk
    if remote and risk != "critical":
        return None, "remote=true je dozvoljen samo za risk=critical"
    ok, err = check_tool(cmd)
    if not ok:
        return None, err
    return {
        "cmd": cmd,
        "risk": risk,
        "net": net,
        "remote": remote,
        "timeout_s": timeout_s,
        "workdir": workdir or "/tmp",
    }, ""


def check_tool(cmd):
    stripped = cmd.lstrip()
    if not stripped:
        return False, "prazna komanda"
    first_char = stripped[0]
    if first_char == "$":
        return False, "komanda ne smije pocinjati promjenljivom"
    match = FIRST_TOKEN_RE.match(cmd)
    if not match:
        if first_char in "({!":
            return True, ""
        return False, "ne mogu odrediti izvrsni program"
    token = match.group(2)
    if token in SHELL_KEYWORDS:
        return True, ""
    base = os.path.basename(token)
    if base not in TOOLS:
        return False, "izvrsni program nije u genome allowlisti: %s" % base[:64]
    return True, ""


def docker_available():
    return bool(shutil.which("docker")) and os.path.exists("/var/run/docker.sock")


def resolve_substrate(risk, remote):
    if risk == "low":
        if not shutil.which("bwrap"):
            return None, "bwrap nije instaliran"
        return "bwrap", ""
    if risk == "medium":
        if not docker_available():
            return None, "Docker nije dostupan"
        return "docker-runc", ""
    if risk == "high":
        if shutil.which("runsc") and docker_available():
            return "docker-gvisor", ""
        if HIGH_REMOTE:
            ready, reason = remote_ready()
            if ready:
                return "remote-gvisor", ""
            return None, "remote gVisor nije spreman: %s" % reason
        if not docker_available():
            return None, "Docker nije dostupan"
        if not os.path.isfile(SECCOMP_PATH):
            return None, "seccomp profil nedostaje"
        return "docker-seccomp", ""
    if not remote:
        return None, (
            "critical se odbija lokalno: potreban je remote gVisor; "
            "postavi remote=true uz PROTEAN_REMOTE_HOST (SSH %s:%s)" % (REMOTE_HOST or "?", REMOTE_PORT)
        )
    ready, reason = remote_ready()
    if not ready:
        return None, "remote sandbox nije spreman: %s" % reason
    return "remote-gvisor", ""


def ssh_base():
    try:
        parent = os.path.dirname(KNOWN_HOSTS)
        if parent:
            os.makedirs(parent, mode=0o700, exist_ok=True)
    except OSError:
        pass
    return [
        "ssh", "-i", REMOTE_KEY, "-p", REMOTE_PORT, "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=6", "-o", "StrictHostKeyChecking=" + SSH_STRICT,
        "-o", "UserKnownHostsFile=" + KNOWN_HOSTS,
        "%s@%s" % (REMOTE_USER, REMOTE_HOST), "--",
    ]


def remote_ready():
    if not REMOTE_HOST:
        return False, "remote host nije konfigurisan (PROTEAN_REMOTE_HOST)"
    if not shutil.which("ssh"):
        return False, "ssh klijent nedostaje"
    if not REMOTE_KEY or not os.path.isfile(REMOTE_KEY):
        return False, "SSH kljuc nedostaje"
    script = (
        "test -e /dev/kvm && command -v runsc >/dev/null 2>&1 && "
        "command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && "
        "echo PROTEAN_READY"
    )
    try:
        proc = subprocess.run(
            ssh_base() + [script], capture_output=True, timeout=9, env=CLEAN_ENV
        )
    except subprocess.TimeoutExpired:
        return False, "SSH timeout"
    except OSError as exc:
        return False, "SSH greska: %s" % exc
    out = (proc.stdout or b"").decode("utf-8", "replace")
    if proc.returncode == 0 and "PROTEAN_READY" in out:
        return True, ""
    err = (proc.stderr or b"").decode("utf-8", "replace").strip().splitlines()
    return False, (err[-1] if err else "runsc/KVM nije dostupan")[:160]


def docker_argv(substrate, workdir, cmd):
    name = "protean-" + secrets.token_hex(12)
    argv = [
        "docker", "run", "--rm", "--name", name, "--network=none",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m",
        "--pids-limit", "128", "--memory", "256m", "--memory-swap", "256m",
        "--cpus", "1", "--user", "65534:65534", "-w", workdir,
    ]
    if substrate == "docker-gvisor":
        argv.append("--runtime=runsc")
    if substrate == "docker-seccomp":
        argv += ["--security-opt", "seccomp=" + SECCOMP_PATH]
    argv += [IMAGE, "sh", "-c", cmd]
    return name, argv


def _empty_mask_file():
    """Prazan regularni fajl za maskiranje (cita se kao ""), lazy + fail-open."""
    try:
        if not os.path.exists(EMPTY_MASK_FILE):
            fd = os.open(EMPTY_MASK_FILE, os.O_WRONLY | os.O_CREAT, 0o644)
            os.close(fd)
        return EMPTY_MASK_FILE
    except OSError:
        return ""


def _in_sandbox(path):
    roots = BWRAP_ROOTS + ("/etc",)
    return any(path == root or path.startswith(root + os.sep) for root in roots)


def secret_mask_args():
    """Mask known secrets inside bwrap; fail closed if a mask file is unavailable."""
    out = []
    empty = ""
    for path in SECRET_MASKS:
        if not _in_sandbox(path):
            continue
        try:
            if os.path.isdir(path):
                out += ["--tmpfs", path]
            elif os.path.isfile(path):
                if not empty:
                    empty = _empty_mask_file()
                if not empty:
                    return None, "mask_unavailable: %s" % path
                out += ["--ro-bind", empty, path]
        except OSError as exc:
            return None, "mask_error: %s" % exc
    return out, None


def run_local_bwrap(args, timeout_s):
    wd = args["workdir"]
    if not os.path.isdir(wd):
        return {
            "ok": False, "rc": None, "out": "", "err": "workdir ne postoji: %s" % wd,
            "timed_out": False,
        }
    argv = [
        "bwrap", "--die-with-parent", "--new-session",
        "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
        "--unshare-cgroup",
    ]
    if not args["net"]:
        argv.append("--unshare-net")
    argv += ["--cap-drop", "ALL"]
    for root in BWRAP_ROOTS:
        if os.path.exists(root):
            argv += ["--ro-bind", root, root]
    argv += ["--tmpfs", "/etc"]
    for path in BWRAP_ETC_ALLOW:
        if not os.path.exists(path):
            continue
        parent = os.path.dirname(path)
        while parent and parent != "/etc":
            argv += ["--dir", parent]
            parent = os.path.dirname(parent)
        argv += ["--ro-bind", path, path]
    # Bind only the resolv.conf file (never its parent directory: /run may
    # contain sockets such as docker.sock).
    resolv = "/etc/resolv.conf"
    if os.path.exists(resolv):
        target = os.path.realpath(resolv)
        if os.path.isfile(target):
            argv += ["--ro-bind", target, resolv]
    argv += ["--dev", "/dev", "--proc", "/proc"]
    masks, mask_err = secret_mask_args()
    if mask_err:
        return {
            "ok": False, "rc": None, "out": "", "err": mask_err,
            "timed_out": False,
        }
    argv += masks
    exec_cmd = ["sh", "-c", args["cmd"]]
    prlimit = shutil.which("prlimit")
    if prlimit and any(prlimit.startswith(r + os.sep) for r in BWRAP_ROOTS):
        exec_cmd = [prlimit, "--as=536870912", "--nproc=1024",
                    "--core=0", "--"] + exec_cmd
    else:
        exec_cmd = ["sh", "-c",
                    'ulimit -v 524288 2>/dev/null; ulimit -c 0 2>/dev/null; exec sh -c "$1"',
                    "sh", args["cmd"]]
    argv += [
        "--size", str(BWRAP_TMPFS_SIZE), "--tmpfs", "/tmp", "--clearenv",
        "--setenv", "PATH", PATH_ENV, "--setenv", "HOME", "/tmp",
        "--setenv", "LANG", "C.UTF-8", "--chdir", wd, "--",
    ] + exec_cmd
    try:
        rc, raw_out, raw_err, timed_out = run_limited(
            argv, timeout_s, env=CLEAN_ENV
        )
    except OSError as exc:
        return {"ok": False, "rc": None, "out": "", "err": str(exc), "timed_out": False}
    out = raw_out.decode("utf-8", "replace")
    err = raw_err.decode("utf-8", "replace")
    if timed_out:
        err = (err + "\ntimeout (%ds)" % timeout_s).strip()
    return {
        "ok": (not timed_out) and rc == 0, "rc": rc, "out": out,
        "err": err, "timed_out": timed_out,
    }


def run_local_docker(substrate, args, timeout_s):
    name, argv = docker_argv(substrate, args["workdir"], args["cmd"])
    timed_out = False
    try:
        rc, raw_out, raw_err, timed_out = run_limited(
            argv, timeout_s + 4, env=CLEAN_ENV
        )
        if timed_out:
            subprocess.run(
                ["docker", "kill", name], capture_output=True, timeout=8,
                env=CLEAN_ENV,
            )
    except OSError as exc:
        return {"ok": False, "rc": None, "out": "", "err": str(exc), "timed_out": False}
    finally:
        subprocess.run(
            ["docker", "rm", "-f", name], capture_output=True, timeout=8,
            env=CLEAN_ENV,
        )
    out = raw_out.decode("utf-8", "replace")
    err = raw_err.decode("utf-8", "replace")
    if timed_out:
        err = (err + "\ntimeout (%ds)" % timeout_s).strip()
    return {
        "ok": (not timed_out) and rc == 0, "rc": rc, "out": out,
        "err": err, "timed_out": timed_out,
    }


def run_remote_gvisor(args, timeout_s):
    name = "protean-" + secrets.token_hex(12)
    docker_cmd = [
        "docker", "run", "--rm", "--name", name, "--runtime=runsc",
        "--network=none", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m", "--pids-limit", "128",
        "--memory", "256m", "--cpus", "1", "--user", "65534:65534",
        "-w", args["workdir"], IMAGE, "sh", "-c", args["cmd"],
    ]
    remote_cmd = " ".join(shlex.quote(part) for part in docker_cmd)
    remote_cmd = "timeout -k 2 %d %s" % (timeout_s, remote_cmd)
    timed_out = False
    try:
        rc, raw_out, raw_err, timed_out = run_limited(
            ssh_base() + [remote_cmd], timeout_s + 10, env=CLEAN_ENV
        )
        if timed_out:
            subprocess.run(
                ssh_base() + ["docker kill %s >/dev/null 2>&1 || true" % shlex.quote(name)],
                capture_output=True, timeout=8, env=CLEAN_ENV,
            )
    except OSError as exc:
        return {"ok": False, "rc": None, "out": "", "err": str(exc), "timed_out": False}
    out = raw_out.decode("utf-8", "replace")
    err = raw_err.decode("utf-8", "replace")
    if timed_out:
        err = (err + "\nremote timeout (%ds)" % timeout_s).strip()
    return {
        "ok": (not timed_out) and rc == 0, "rc": rc, "out": out,
        "err": err, "timed_out": timed_out,
    }


def execute(substrate, args, timeout_s):
    if substrate == "bwrap":
        return run_local_bwrap(args, timeout_s)
    if substrate in ("docker-runc", "docker-seccomp", "docker-gvisor"):
        return run_local_docker(substrate, args, timeout_s)
    if substrate == "remote-gvisor":
        return run_remote_gvisor(args, timeout_s)
    return {"ok": False, "rc": None, "out": "", "err": "nepoznat substrat",
            "timed_out": False}


MAX_EVIDENCE_RUNS = 200


def _prune_evidence():
    try:
        entries = sorted(os.listdir(RUNS_DIR))
    except OSError:
        return
    for name in entries[:-MAX_EVIDENCE_RUNS]:
        shutil.rmtree(os.path.join(RUNS_DIR, name), ignore_errors=True)


def write_evidence(record):
    os.makedirs(RUNS_DIR, mode=0o700, exist_ok=True)
    _prune_evidence()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    lease = record.get("lease_id") or "nolease"
    subdir = os.path.join(RUNS_DIR, "%s-%s" % (stamp, lease[-6:]))
    os.makedirs(subdir, mode=0o700, exist_ok=True)
    path = os.path.join(subdir, "evidence.jsonl")
    line = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)
    return path


def denied(reason, **extra):
    payload = {"ok": False, "denied": True, "err": reason}
    payload.update(extra)
    return payload


def handle_run(raw):
    started = time.time()
    args, err = parse_args(raw)
    if err:
        return denied(err, stage="args")

    substrate, reason = resolve_substrate(args["risk"], args["remote"])
    if substrate is None:
        genome = genome_for(args["risk"], args["net"], args["timeout_s"], "deny")
        lease = mint_lease(genome, args["risk"], args["cmd"])
        valid, verr = verify_lease(lease, genome, args["risk"], args["cmd"])
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": "run", "risk": args["risk"], "remote": args["remote"],
            "net": args["net"], "cmd_sha": cmd_hash(args["cmd"]),
            "genome_hash": lease["genome_hash"], "lease_id": lease["lease_id"],
            "lease_expires_at": lease["expires_at"], "substrate": "deny",
            "ok": False, "ms": round((time.time() - started) * 1000, 3),
            "out_sha": sha256_hex(b""), "rc": None, "timed_out": False,
            "err": (reason if valid else verr)[:300],
        }
        rec["evidence"] = write_evidence(rec)
        return denied(rec["err"], stage="policy", substrate="deny",
                      lease_id=lease["lease_id"],
                      genome_hash=lease["genome_hash"], evidence=rec["evidence"])

    genome = genome_for(args["risk"], args["net"], args["timeout_s"], substrate)
    lease = mint_lease(genome, args["risk"], args["cmd"])
    valid, verr = verify_lease(lease, genome, args["risk"], args["cmd"])
    if not valid:
        return denied("lease odbijen prije izvrsenja: %s" % verr, stage="lease",
                      substrate=substrate)
    if args["timeout_s"] + 2 > int(genome["ttl"]):
        return denied("timeout_s prelazi TTL lease-a", stage="ttl",
                      substrate=substrate)

    remaining = TOTAL_BUDGET_S - (time.time() - started)
    if remaining < 12.0:
        return denied("vremenski budzet iscrpljen prije izvrsenja",
                      stage="budget", substrate=substrate)
    exec_timeout = int(min(args["timeout_s"], max(1.0, remaining - 10.0)))
    result = execute(substrate, args, exec_timeout)
    elapsed_ms = round((time.time() - started) * 1000, 3)
    out_sha = sha256_hex(
        (result["out"] + result["err"]).encode("utf-8", "replace")
    )
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": "run", "risk": args["risk"], "remote": args["remote"],
        "net": args["net"], "cmd_sha": cmd_hash(args["cmd"]),
        "genome_hash": lease["genome_hash"], "lease_id": lease["lease_id"],
        "lease_expires_at": lease["expires_at"], "substrate": substrate,
        "exec_timeout_s": exec_timeout,
        "ok": bool(result["ok"]), "ms": elapsed_ms, "out_sha": out_sha,
        "rc": result["rc"], "timed_out": bool(result["timed_out"]),
        "err": clip(result["err"], 300),
    }
    rec["evidence"] = write_evidence(rec)

    payload = {
        "ok": bool(result["ok"]),
        "risk": args["risk"],
        "substrate": substrate,
        "net": args["net"],
        "remote": args["remote"],
        "genome_hash": lease["genome_hash"],
        "lease_id": lease["lease_id"],
        "lease_ttl_s": genome["ttl"],
        "exec_timeout_s": exec_timeout,
        "ms": elapsed_ms,
        "rc": result["rc"],
        "timed_out": bool(result["timed_out"]),
        "out": clip(result["out"]),
        "err": clip(result["err"]),
        "out_sha": out_sha,
        "evidence": rec["evidence"],
    }
    return payload


def main(argv):
    tool = argv[1] if len(argv) > 1 else ""
    if tool != "run":
        return emit({"ok": False, "err": "nepoznat alat (ocekivano: run)"})
    try:
        body = sys.stdin.buffer.read(131072).decode("utf-8", "replace")
        raw = json.loads(body or "{}")
    except (ValueError, UnicodeDecodeError) as exc:
        return emit({"ok": False, "err": "nevalidan JSON na stdin: %s" % str(exc)[:120]})
    try:
        return emit(handle_run(raw))
    except Exception as exc:  # fail-closed, no traceback on stdout
        sys.stderr.write("protean internal: %s: %s\n" % (type(exc).__name__, exc))
        return emit({
            "ok": False, "denied": True,
            "err": "internal greska: %s" % type(exc).__name__,
        })


if __name__ == "__main__":
    sys.exit(main(sys.argv))
