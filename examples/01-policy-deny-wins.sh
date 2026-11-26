#!/usr/bin/env bash
# Deny beats allow; invalid policy means deny.
#   ./examples/01-policy-deny-wins.sh
set -euo pipefail

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/policy.json" <<'JSON'
{"version": 1, "default": "deny",
 "allow": {"tools": ["shell"]},
 "deny":  {"commands": ["rm -rf*", "re:^\\s*sudo\\b"]}}
JSON

decide () { # expected command
  local want=$1 cmd=$2 out got
  out=$(GAMAI_POLICY="$tmp/policy.json" gamai-plugins call trust managed_policy \
        "{\"action\":\"check\",\"tool\":\"shell\",\"command\":\"$cmd\"}" || true)  # deny exits 1
  got=$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['decision'])" "$out")
  printf '%-5s (want %-5s) %s\n' "$got" "$want" "$cmd"
  [ "$got" = "$want" ] || { echo "FAIL: expected $want"; exit 1; }
}

decide allow "ls -la"
decide deny  "rm -rf /"
decide deny  "sudo rm -rf /tmp/x"

echo -n "invalid policy -> "
out=$(GAMAI_POLICY=/nonexistent.json gamai-plugins call trust managed_policy \
      '{"action":"check","tool":"shell","command":"ls"}' || true)
python3 -c "
import json,sys;d=json.loads(sys.argv[1])
print(d['decision'], '|', d.get('reason'))
assert d['decision']=='deny', d
" "$out"

echo "OK: allow once, deny twice, fail-closed on missing policy"
