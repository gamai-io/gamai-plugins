#!/usr/bin/env python3
"""One CLI for all portable GAMA plugins."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "plugins"
PLUGINS = ("trust", "protean", "team")


def manifest(plugin):
    with open(ROOT / plugin / "plugin.json", encoding="utf-8") as fh:
        return json.load(fh)


def _public_name(plugin, tool_name):
    return tool_name if tool_name.startswith(plugin + "_") else "%s_%s" % (plugin, tool_name)


def tools():
    out = []
    for plugin in PLUGINS:
        m = manifest(plugin)
        for tool in m.get("tools", []):
            out.append({
                "name": _public_name(plugin, tool["name"]),
                "plugin": plugin,
                "tool": tool["name"],
                "description": tool.get("description", ""),
                "inputSchema": tool.get("parameters", {"type": "object"}),
                "timeout_s": tool.get("timeout_s", 90),
            })
    return out


def call(plugin, tool, args, timeout=None):
    if plugin not in PLUGINS:
        return {"ok": False, "err": "unknown plugin %r" % plugin}
    path = ROOT / plugin / "run.py"
    if not path.is_file():
        return {"ok": False, "err": "plugin entrypoint missing"}
    if timeout is None:
        timeout = 90
        for entry in tools():
            if entry["plugin"] == plugin and entry["tool"] == tool:
                timeout = int(entry.get("timeout_s") or 90)
                break
    try:
        p = subprocess.run(
            [sys.executable, str(path), tool],
            input=json.dumps(args, ensure_ascii=False),
            text=True, encoding="utf-8", errors="replace",
            capture_output=True, timeout=timeout,
            cwd=str(ROOT / plugin),
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "err": "timeout after %ss" % timeout}
    raw = (p.stdout or "").strip().splitlines()
    for line in reversed(raw):
        try:
            return json.loads(line)
        except Exception:
            continue
    return {"ok": False, "err": (p.stderr or p.stdout or "empty output").strip()[:500]}


def _print(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print("usage: gamai-plugins list | call <plugin> <tool> [json] | mcp")
        return 0
    cmd = argv[0]
    if cmd == "list":
        _print({"ok": True, "tools": tools()})
        return 0
    if cmd == "call":
        if len(argv) < 3:
            _print({"ok": False, "err": "usage: call <plugin> <tool> [json]"})
            return 2
        plugin, tool = argv[1], argv[2]
        try:
            args = json.loads(argv[3]) if len(argv) > 3 else {}
        except Exception as exc:
            _print({"ok": False, "err": "invalid json: %s" % exc})
            return 2
        if not isinstance(args, dict):
            _print({"ok": False, "err": "arguments must be a JSON object"})
            return 2
        res = call(plugin, tool, args)
        _print(res)
        return 0 if res.get("ok") and res.get("allowed") is not False else 1
    if cmd == "mcp":
        from .mcp import main as mcp_main
        return mcp_main()
    _print({"ok": False, "err": "unknown command %r" % cmd})
    return 2


def _plugin_main(plugin, argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        _print({"ok": False, "err": "usage: gamai-%s <tool> [json]" % plugin})
        return 2
    args = {}
    if len(argv) > 1:
        try:
            args = json.loads(argv[1])
        except Exception as exc:
            _print({"ok": False, "err": "invalid json: %s" % exc})
            return 2
    res = call(plugin, argv[0], args)
    _print(res)
    return 0 if res.get("ok") and res.get("allowed") is not False else 1


def trust_main(argv=None):
    return _plugin_main("trust", argv)


def protean_main(argv=None):
    return _plugin_main("protean", argv)


def team_main(argv=None):
    return _plugin_main("team", argv)


if __name__ == "__main__":
    raise SystemExit(main())
