#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""team plugin — argv[1] = team_create | team_dispatch | team_status.

Ugovor: args JSON na stdin, samo JSON na stdout, exit 0 (greske su {ok:false}).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import team_core as TC

for _stream in (sys.stdin, sys.stdout):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _out(obj):
    text = json.dumps(obj, ensure_ascii=False)
    if len(text) > 262144:
        text = json.dumps({"ok": False, "err": "odgovor je prevelik"}, ensure_ascii=False)
    sys.stdout.write(text + "\n")


def main():
    tool = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
    try:
        raw = sys.stdin.read() or "{}"
        args = json.loads(raw)
        if not isinstance(args, dict):
            _out({"ok": False, "err": "ocekivan JSON objekat"})
            return 0
    except Exception as e:
        _out({"ok": False, "err": "nevalidan JSON na stdin: %s" % str(e)[:160]})
        return 0

    try:
        if tool == "team_create":
            r = TC.create(args.get("goal"), agents=args.get("agents", 2),
                          repo=args.get("repo"))
        elif tool == "team_dispatch":
            r = TC.dispatch(args.get("team_id"), args.get("task"), repo=args.get("repo"))
        elif tool == "team_status":
            r = TC.status(args.get("team_id"))
        elif tool == "self_test":
            r = TC.self_test()
        else:
            r = {"ok": False, "err": "nepoznat alat '%s' (team_create|team_dispatch|team_status)" % tool[:40]}
    except Exception as e:
        r = {"ok": False, "err": "team %s: %s" % (tool[:40], str(e)[:200])}
    _out(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
