#!/usr/bin/env python3
"""End-to-end MCP stdio smoke test (UTF-8, notifications, batch, tools/call)."""
import json
import os
import subprocess
import sys
import tempfile

REQUESTS = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "0"}}},
    {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}},
    [],
    [{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}],
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "team_create", "arguments": {"goal": "provjeri čćžšđ", "agents": 2}}},
]


def main():
    env = dict(os.environ)
    tmp = tempfile.TemporaryDirectory()
    env["GAMAI_TEAM_STATE_DIR"] = os.path.join(tmp.name, "state")
    env["GAMAI_TEAM_WORKTREES"] = os.path.join(tmp.name, "work")
    p = subprocess.Popen([sys.executable, "-m", "gamai_plugins.mcp"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, encoding="utf-8",
                         env=env)
    payload = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in REQUESTS)
    out, err = p.communicate(payload, timeout=60)
    if p.returncode != 0:
        print("FAIL rc=%s stderr=%s" % (p.returncode, err[:500]))
        return 1
    responses = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            responses.append(json.loads(line))
        except Exception:
            print("FAIL non-json stdout:", line[:200])
            return 1
    by_id = {r.get("id"): r for r in responses if isinstance(r, dict)}
    if 1 not in by_id or "result" not in by_id[1]:
        print("FAIL initialize", responses)
        return 1
    if 2 not in by_id or "tools" not in by_id[2].get("result", {}):
        print("FAIL tools/list", responses)
        return 1
    if len(by_id[2]["result"]["tools"]) != 6:
        print("FAIL tool count", by_id[2]["result"]["tools"])
        return 1
    call = by_id.get(3, {})
    text = (call.get("result", {}).get("content") or [{}])[0].get("text", "")
    if not text or not json.loads(text).get("ok"):
        print("FAIL tools/call", call)
        return 1
    print("OK mcp responses=%d tools=6 unicode=ok" % len(responses))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
