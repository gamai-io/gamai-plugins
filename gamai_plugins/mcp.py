#!/usr/bin/env python3
"""Minimal stdio MCP server for the portable GAMA plugins (stdlib only)."""
import json
import sys

from . import __version__
from .cli import call, tools

PROTOCOL = "2024-11-05"


def _tool_list():
    return [{
        "name": t["name"],
        "description": "[%s] %s" % (t["plugin"], t["description"]),
        "inputSchema": t["inputSchema"],
    } for t in tools()]


def _find(name):
    for t in tools():
        if t["name"] == name:
            return t
    return None


def handle(req):
    if not isinstance(req, dict):
        return None
    rid = req.get("id")
    method = req.get("method")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "gamai-plugins", "version": __version__},
        }}
    if "id" not in req:
        return None
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": _tool_list()}}
    if method == "tools/call":
        params = req.get("params")
        if not isinstance(params, dict):
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32602, "message": "params must be an object"}}
        name = params.get("name") or ""
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            args = {}
        t = _find(name)
        if t is None:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "unknown tool %r" % name}}
        res = call(t["plugin"], t["tool"], args, t.get("timeout_s"))
        text = json.dumps(res, ensure_ascii=False, indent=2)
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": text}],
            "isError": bool(res.get("ok") is False or res.get("allowed") is False),
        }}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "unknown method %r" % method}}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    for stream in (sys.stdin, sys.stdout):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if "--selftest" in argv:
        print(json.dumps({"ok": True, "tools": len(tools()), "names": [t["name"] for t in tools()]}, indent=2))
        return 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        requests = req if isinstance(req, list) else [req]
        for item in requests:
            out = handle(item)
            if out is not None:
                print(json.dumps(out, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
