#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TEAM_CORE_V1 — koordinator + tim agenata sa trajnim stanjem.

Tok:
  team_create   -> deterministicki razdvoji cilj na podzadatke (BEZ LLM),
                   dodijeli clanovima, napravi izolovani radni prostor.
  team_dispatch -> posalji JEDAN zadatak JEDNOM clanu; jedan LLM poziv kroz
                   configured HTTP LLM endpoint (with deterministic fallback).
  team_status   -> procitaj stanje s diska (prezivljava novu sesiju/proces).

Stanje: <plugin>/teams/<team_id>.json (atomski upis + flock).
Izolacija: GAMAI_TEAM_WORKTREES/<team_id>/ (git worktree, inace clone --shared,
inace obican direktorij).

Bez vanjskih zavisnosti (stdlib only). Svaka funkcija vraca dict, nikad ne baca.
"""
import contextlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEAMS_DIR = os.environ.get("GAMAI_TEAM_STATE_DIR") or os.path.expanduser("~/.local/state/gamai/teams")
WORKTREES_DIR = os.environ.get("GAMAI_TEAM_WORKTREES") or os.path.expanduser("~/.cache/gamai/teams")
LLM_URL = (os.environ.get("GAMAI_LLM_URL") or "").rstrip("/")
DEFAULT_AGENT = os.environ.get("GAMAI_TEAM_AGENT") or "agent"

MAX_GOAL = 4000
MAX_TASK = 4000
MAX_MEMBERS = 8
MAX_TASKS = 32
MAX_RESULT = 4000
MAX_PROMPT = 6000
def _env_int(name, default):
    try:
        return int(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return default


def _env_float(name, default):
    try:
        return float(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return default


DEFAULT_BUDGET = _env_int("GAMAI_TEAM_LLM_BUDGET", 50)
LLM_TIMEOUT = _env_float("GAMAI_TEAM_LLM_TIMEOUT", 40)

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,64}$")
RESERVED_ID_RE = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$", re.I)


def _valid_id(tid):
    return bool(ID_RE.match(str(tid or ""))) and not RESERVED_ID_RE.match(str(tid))
ROLES = ("analiza", "istrazivanje", "izrada", "provjera")
ROLE_HINT = {
    "analiza": "Razlozi zadatak na cinjenice i kriterije; navedi rizike.",
    "istrazivanje": "Navedi provjerljive cinjenice i izvore; ako izvora nema, reci 'bez dokaza'.",
    "izrada": "Napravi konkretan rezultat (tekst, plan ili kod) bez opstih mjesta.",
    "provjera": "Provjeri rezultat, navedi sta je potvrdjeno i sta nedostaje.",
}
_SPLIT_RE = re.compile(r"(?:\r?\n|;|\s\|\s|\s\bpa\b\s|\s\bthen\b\s|\s\bi\b\s|,\s+)", re.I)


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _err(msg, **kw):
    d = {"ok": False, "err": str(msg)[:400]}
    d.update(kw)
    return d


def _clean(text, limit):
    return re.sub(r"\s+", " ", str(text or "")).strip()[:limit]


def _json_safe(v):
    try:
        json.dumps(v)
        return v
    except Exception:
        return str(v)[:2000]


def _safe_dir(path, root):
    root = os.path.realpath(root)
    p = os.path.realpath(path)
    if p != root and not p.startswith(root + os.sep):
        raise ValueError("putanja van %s" % root)
    return p


def _team_path(team_id):
    tid = str(team_id or "").strip()
    if not _valid_id(tid):
        raise ValueError("nevalidan team_id")
    return _safe_dir(os.path.join(TEAMS_DIR, tid + ".json"), TEAMS_DIR)


@contextlib.contextmanager
def _locked(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    if fcntl is None:  # Windows: atomic directory lock (no msvcrt byte-range quirks)
        lockdir = path + ".lockdir"
        deadline = time.time() + max(120.0, LLM_TIMEOUT + 60.0)
        while True:
            try:
                os.mkdir(lockdir, 0o700)
                break
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(lockdir) > 600:
                        os.rmdir(lockdir)
                        continue
                except OSError:
                    pass
                if time.time() >= deadline:
                    raise TimeoutError("team lock timeout: %s" % lockdir)
                time.sleep(0.1)
        try:
            yield
        finally:
            try:
                os.rmdir(lockdir)
            except OSError:
                pass
        return
    fh = open(path + ".lock", "a+b")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


def _atomic_write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = "%s.%d.%s.tmp" % (path, os.getpid(), secrets.token_hex(4))
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        parent = os.path.dirname(path)
        if parent:
            dfd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    except OSError:
        pass
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load(team_id):
    try:
        path = _team_path(team_id)
    except ValueError as e:
        return _err(e)
    try:
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)
    except FileNotFoundError:
        return _err("nema tima '%s'" % team_id)
    except Exception as e:
        return _err("stanje necitljivo: %s" % e)
    if not isinstance(state, dict):
        return _err("stanje nije objekat")
    return {"ok": True, "state": state, "path": path}


def save(state):
    path = _team_path(state.get("id"))
    with _locked(path):
        _atomic_write(path, state)
    return path


# ---------------------------------------------------------------- dodjela
def _members_spec(agents):
    """agents: int (2..8) | list of agent names | single name | None."""
    if agents is None:
        names = [DEFAULT_AGENT, DEFAULT_AGENT]
    elif isinstance(agents, bool):
        names = [DEFAULT_AGENT, DEFAULT_AGENT]
    elif isinstance(agents, int):
        names = [DEFAULT_AGENT] * max(2, min(MAX_MEMBERS, agents))
    elif isinstance(agents, str):
        names = [agents.strip() or DEFAULT_AGENT]
    elif isinstance(agents, (list, tuple)):
        names = [str(x).strip() or DEFAULT_AGENT for x in agents][:MAX_MEMBERS]
    else:
        names = [DEFAULT_AGENT, DEFAULT_AGENT]
    if len(names) < 2:
        names = names + [DEFAULT_AGENT]
    return [{"name": "agent-%d" % (i + 1), "agent": n, "role": ROLES[i % len(ROLES)]}
            for i, n in enumerate(names)]


def split_goal(goal, n):
    """Deterministicki razdvoji cilj na podzadatke (bez LLM)."""
    raw = str(goal or "")[:MAX_GOAL]
    parts = [p.strip(" .,:;") for p in _SPLIT_RE.split(raw) if p.strip(" .,:;")]
    parts = [_clean(p, MAX_TASK) for p in parts]
    parts = [p for p in parts if len(p) >= 3][:MAX_TASKS]
    if not parts:
        parts = [_clean(raw, MAX_GOAL) or "obradi cilj"]
    n = max(2, min(MAX_MEMBERS, int(n or 2)))
    while len(parts) < n:
        role = ROLES[len(parts) % len(ROLES)]
        parts.append("%s cilja: %s" % (role, _clean(raw, 160)))
    return parts[:MAX_TASKS]


def _tasks(parts, members):
    out = []
    for i, title in enumerate(parts):
        m = members[i % len(members)]
        out.append({
            "id": "t%d" % (i + 1),
            "index": i,
            "title": title,
            "role": m["role"],
            "assignee": m["name"],
            "status": "pending",
            "engine": "",
            "result": "",
            "ms": 0,
            "created_at": _now(),
        })
    return out


# ---------------------------------------------------------------- izolacija
def _is_git_repo(path):
    try:
        r = subprocess.run(["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=8)
        return r.returncode == 0 and r.stdout.strip() == "true"
    except Exception:
        return False


def isolate(team_id, repo=None):
    """Napravi izolovan radni prostor. Vrati {path, mode, repo}."""
    dest = _safe_dir(os.path.join(WORKTREES_DIR, team_id), WORKTREES_DIR)
    os.makedirs(WORKTREES_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(WORKTREES_DIR, 0o700)
    except OSError:
        pass
    nohooks = os.path.join(WORKTREES_DIR, ".nohooks")
    os.makedirs(nohooks, mode=0o700, exist_ok=True)
    src = _clean(repo or os.environ.get("GAMAI_TEAM_REPO") or "", 500)
    if src and os.path.isdir(src) and _is_git_repo(src):
        src = os.path.abspath(src)
        if os.path.isdir(dest):
            shutil.rmtree(dest, ignore_errors=True)
        # Clone-first: a clone has its own config, so hooks can be disabled
        # persistently without touching the source repository.
        try:
            shutil.rmtree(dest, ignore_errors=True)
            r = subprocess.run(["git", "-c", "core.hooksPath=" + nohooks,
                                "clone", "-q", "--shared", "--no-hardlinks", src, dest],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=60)
            if r.returncode == 0 and os.path.isdir(os.path.join(dest, ".git")):
                subprocess.run(["git", "-C", dest, "config", "core.hooksPath", nohooks],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=10)
                return {"path": dest, "mode": "clone", "repo": src}
            shutil.rmtree(dest, ignore_errors=True)
        except Exception:
            shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest, mode=0o700, exist_ok=True)
    try:
        os.chmod(dest, 0o700)
    except OSError:
        pass
    try:
        with open(os.path.join(dest, ".team_isolated"), "w", encoding="utf-8") as f:
            f.write("%s\n%s\n" % (team_id, _now()))
    except Exception:
        pass
    return {"path": dest, "mode": "dir", "repo": src or ""}


# ---------------------------------------------------------------- LLM
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_LLM_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _NoRedirect()
)


def _llm_token():
    return os.environ.get("GAMAI_LLM_TOKEN") or ""


def _is_loopback(host):
    return host in ("localhost", "127.0.0.1", "::1")


def _llm_http(prompt, agent, timeout=None):
    """One optional HTTP LLM call. Returns (text, engine), or fallback text."""
    if not LLM_URL:
        return "", "fallback:no-llm"
    parsed = urlparse(LLM_URL)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return "", "fallback:bad-url"
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname or ""):
        return "", "fallback:insecure-url"
    tok = _llm_token()
    body = json.dumps({"task": prompt, "agent": agent}, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if tok:
        headers["X-Token"] = tok
    req = urllib.request.Request(LLM_URL, data=body, method="POST", headers=headers)
    try:
        with _LLM_OPENER.open(req, timeout=float(timeout or LLM_TIMEOUT)) as r:
            raw = r.read(1_000_001)
        if len(raw) > 1_000_000:
            return "", "fallback:response-too-large"
        d = json.loads(raw.decode("utf-8", "replace") or "{}")
        if not isinstance(d, dict):
            return "", "fallback:bad-response"
    except Exception:
        return "", "fallback:http-error"
    out = _clean(d.get("out") or d.get("say") or "", MAX_RESULT)
    if d.get("ok") is False or not out:
        return "", "fallback:%s" % _clean(d.get("err") or "prazan odgovor", 80)
    return out[:MAX_RESULT], _clean(d.get("engine") or agent, 40)


def _fallback_text(state, task):
    return ("Deterministicki rezultat (LLM nedostupan): zadatak '%s' obradjen u ulozi '%s'. "
            "Cilj: %s." % (task.get("title") or "", task.get("role") or "",
                           _clean(state.get("goal") or "", 300)))[:MAX_RESULT]


# ---------------------------------------------------------------- alati
def create(goal, agents=2, repo=None, team_id=None):
    raw_goal = str(goal or "")[:MAX_GOAL]
    goal = _clean(raw_goal, MAX_GOAL)
    if len(goal) < 3:
        return _err("goal je prekratak (min 3 znaka)")
    os.makedirs(TEAMS_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(TEAMS_DIR, 0o700)
    except OSError:
        pass
    members = _members_spec(agents)
    parts = split_goal(raw_goal, len(members))
    tid = team_id or ("team-%s-%s" % (datetime.now().strftime("%Y%m%d-%H%M%S"), secrets.token_hex(2)))
    state = None
    path = None
    for _ in range(8):
        if not _valid_id(tid):
            return _err("nevalidan team_id")
        path = _team_path(tid)
        with _locked(path):
            if not os.path.exists(path):
                state = {
                    "id": tid,
                    "goal": goal,
                    "created_at": _now(),
                    "updated_at": _now(),
                    "coordinator": "deterministic-v1",
                    "members": [dict(m, status="idle", tasks=0, done=0) for m in members],
                    "tasks": _tasks(parts, members),
                    "llm_calls": 0,
                    "llm_budget": DEFAULT_BUDGET,
                    "done": False,
                    "summary": "",
                    "isolation": {},
                    "schema": "team-v1",
                }
                _atomic_write(path, state)
                break
        if team_id:
            return _err("team_id vec postoji")
        tid = tid + "-" + secrets.token_hex(2)
    if state is None or path is None:
        return _err("ne mogu dodijeliti team_id")
    try:
        iso = isolate(tid, repo)
    except Exception as exc:
        iso = {"path": "", "mode": "error", "repo": repo or "",
               "error": str(exc)[:200]}
    state["isolation"] = iso
    with _locked(path):
        _atomic_write(path, state)
    return {
        "ok": True,
        "team_id": tid,
        "goal": goal,
        "agents": len(members),
        "tasks": [{"id": t["id"], "title": t["title"], "role": t["role"],
                   "assignee": t["assignee"], "status": t["status"]} for t in state["tasks"]],
        "isolation": state["isolation"],
        "llm_calls": 0,
        "state_path": path,
    }


def _pick_member(state):
    best = None
    for m in state.get("members") or []:
        if best is None or (m.get("tasks", 0) - m.get("done", 0)) < (best.get("tasks", 0) - best.get("done", 0)):
            best = m
    return best or {"name": "agent-1", "agent": DEFAULT_AGENT, "role": ROLES[0]}


def _find_task(state, task):
    key = str(task or "").strip()
    if not key:
        return None
    for t in state.get("tasks") or []:
        if t.get("id") == key:
            return t
    if key.isdigit():
        i = int(key) - 1
        ts = state.get("tasks") or []
        if 0 <= i < len(ts):
            return ts[i]
    for t in state.get("tasks") or []:
        if _clean(t.get("title"), 200).lower() == _clean(key, 200).lower():
            return t
    return None


def _recount(state):
    for m in state.get("members") or []:
        ts = [t for t in state.get("tasks") or [] if t.get("assignee") == m.get("name")]
        m["tasks"] = len(ts)
        m["done"] = len([t for t in ts if t.get("status") == "done"])
        m["status"] = "done" if ts and m["done"] == len(ts) else ("active" if any(
            t.get("status") == "pending" for t in ts) else "idle")
    tasks = state.get("tasks") or []
    state["done"] = bool(tasks) and all(t.get("status") == "done" for t in tasks)
    if state["done"]:
        lines = []
        for t in tasks:
            lines.append("[%s %s @%s] %s" % (t.get("id"), t.get("role"), t.get("assignee"),
                                             _clean(t.get("result"), 400)))
        state["summary"] = "\n".join(lines)[:8000]
    return state


def dispatch(team_id, task, repo=None, llm=None):
    """Posalji jedan zadatak jednom clanu. Najvise jedan LLM poziv po pozivu."""
    res = load(team_id)
    if not res.get("ok"):
        return res
    state = res["state"]
    path = res["path"]
    text = _clean(task, MAX_TASK)
    if not text:
        return _err("task je prazan", team_id=state.get("id"))
    llm_fn = llm or _llm_http

    with _locked(path):
        cur = load(team_id)
        if not cur.get("ok"):
            return cur
        state = cur["state"]
        target = _find_task(state, text)
        if target is not None and target.get("status") == "done":
            return {"ok": True, "team_id": state["id"], "task_id": target["id"],
                    "assignee": target["assignee"], "status": "done", "cached": True,
                    "engine": target.get("engine"), "result": target.get("result"),
                    "llm_calls": state.get("llm_calls", 0), "team_done": bool(state.get("done"))}

        if target is None:
            if state.get("done"):
                state["done"] = False
                state["summary"] = ""
            member = _pick_member(state)
            if len(state.get("tasks") or []) >= MAX_TASKS:
                return _err("previse zadataka (max %d)" % MAX_TASKS, team_id=state["id"])
            target = {
                "id": "t%d" % (len(state["tasks"]) + 1),
                "index": len(state["tasks"]),
                "title": text,
                "role": member.get("role") or ROLES[0],
                "assignee": member.get("name"),
                "status": "pending",
                "engine": "",
                "result": "",
                "ms": 0,
                "created_at": _now(),
            }
            state.setdefault("tasks", []).append(target)

        agent = DEFAULT_AGENT
        for m in state.get("members") or []:
            if m.get("name") == target.get("assignee"):
                agent = m.get("agent") or DEFAULT_AGENT
                break

        prompt = ("Cilj tima: %s\nUloga: %s. %s\nZadatak: %s\n"
                  "Odgovori kratko (max 120 rijeci), konkretno; bez uvoda."
                  % (_clean(state.get("goal"), 600), target.get("role"),
                     ROLE_HINT.get(target.get("role"), ""), _clean(target.get("title"), 1200)))
        prompt = prompt[:MAX_PROMPT]

        budget = int(state.get("llm_budget") or DEFAULT_BUDGET)
        used = int(state.get("llm_calls") or 0)
        target["status"] = "running"
        t0 = time.time()
        if used < budget:
            state["llm_calls"] = used + 1
            result, engine = llm_fn(prompt, agent, LLM_TIMEOUT)
            if not result:
                result, engine = _fallback_text(state, target), engine or "fallback"
        else:
            result, engine = _fallback_text(state, target), "fallback:budget"
        target["status"] = "done"
        target["result"] = _clean(result, MAX_RESULT)
        target["engine"] = _clean(engine, 60)
        target["ms"] = int((time.time() - t0) * 1000)
        target["finished_at"] = _now()
        state["updated_at"] = _now()
        if repo and not (state.get("isolation") or {}).get("repo"):
            try:
                state["isolation"] = isolate(state["id"], repo)
            except Exception:
                pass
        _recount(state)
        _atomic_write(path, state)

    done = [t for t in state.get("tasks") or [] if t.get("status") == "done"]
    return {
        "ok": True,
        "team_id": state["id"],
        "task_id": target["id"],
        "assignee": target.get("assignee"),
        "role": target.get("role"),
        "status": target.get("status"),
        "engine": target.get("engine"),
        "result": target.get("result"),
        "ms": target.get("ms"),
        "llm_calls": state.get("llm_calls", 0),
        "llm_budget": state.get("llm_budget", DEFAULT_BUDGET),
        "results_done": "%d/%d" % (len(done), len(state.get("tasks") or [])),
        "team_done": bool(state.get("done")),
        "summary": state.get("summary", ""),
    }


def status(team_id):
    res = load(team_id)
    if not res.get("ok"):
        return res
    state = res["state"]
    tasks = state.get("tasks") or []
    done = [t for t in tasks if t.get("status") == "done"]
    iso = state.get("isolation") or {}
    files = []
    try:
        if iso.get("path") and os.path.isdir(iso["path"]):
            files = sorted(os.listdir(iso["path"]))[:50]
    except Exception:
        files = []
    return {
        "ok": True,
        "team_id": state.get("id"),
        "goal": state.get("goal"),
        "done": bool(state.get("done")),
        "created_at": state.get("created_at"),
        "updated_at": state.get("updated_at"),
        "coordinator": state.get("coordinator"),
        "llm_calls": state.get("llm_calls", 0),
        "llm_budget": state.get("llm_budget", DEFAULT_BUDGET),
        "progress": "%d/%d" % (len(done), len(tasks)),
        "members": state.get("members") or [],
        "tasks": [{"id": t.get("id"), "title": t.get("title"), "role": t.get("role"),
                   "assignee": t.get("assignee"), "status": t.get("status"),
                   "engine": t.get("engine"), "ms": t.get("ms"),
                   "result": t.get("result")} for t in tasks],
        "summary": state.get("summary", ""),
        "isolation": iso,
        "worktree": iso.get("path", ""),
        "files": files,
        "state_path": res["path"],
    }


def self_test():
    """Brzi offline test bez LLM: create -> dispatch x2 (stub) -> status."""
    import tempfile
    global TEAMS_DIR, WORKTREES_DIR
    old = (TEAMS_DIR, WORKTREES_DIR)
    with tempfile.TemporaryDirectory(prefix="team-selftest-") as tmp:
        TEAMS_DIR = os.path.join(tmp, "teams")
        WORKTREES_DIR = os.path.join(tmp, "work")
        try:
            c = create("analiza ponude; provjeri cijene", agents=2)
            assert c["ok"], c
            assert len(c["tasks"]) == 2, c
            stub = lambda p, s, t: ("STUB:" + p.splitlines()[-2][:60], "stub")
            d1 = dispatch(c["team_id"], "analiza ponude", llm=stub)
            d2 = dispatch(c["team_id"], "provjeri cijene", llm=stub)
            assert d1["ok"] and d2["ok"], (d1, d2)
            s = status(c["team_id"])
            assert s["ok"] and s["done"] and s["progress"] == "2/2", s
            assert s["llm_calls"] == 2, s
            return {"ok": True, "team_id": c["team_id"], "progress": s["progress"],
                    "llm_calls": s["llm_calls"]}
        finally:
            TEAMS_DIR, WORKTREES_DIR = old
