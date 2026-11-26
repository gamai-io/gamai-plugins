# gamAI plugins

Portable, dependency-light plugins for AI agents: **policy evaluation**,
**sandbox execution** and **team coordination**. The same code is exposed as an
MCP server, a CLI and a plain Python function, so it can run in Claude Code,
opencode, Codex, Cursor, LangChain or a custom agent loop.

> Status: `0.2.7`
>
> **PyPI 0.2.6 predates the RT5 fixes** (a shell-metacharacter deny bypass and a
> package reported `verified` while `node_modules`/`.git` were never hashed).
> Until 0.2.7 is published, install from this repository:
> `pip install "git+https://github.com/gamai-io/gamai-plugins@main"`. — small, explicit about its limits, and hardened against the
> failures found in an external-style audit. `protean` is a namespace sandbox,
> not a VM and not a hardened multi-tenant boundary.

> **Start here if you are new:** [`gama-mandate`](https://pypi.org/project/gama-mandate/) — sign a business commitment, execute it once, prove it offline.
> This package is one piece of the same stack: `gama-mandate` (commitments) · `gamai-trust` (verify claims) · `gamai-guard` (injection) · `gamai-plugins` (policy, sandbox, team) · `gama-l` (provable computation).

## Plugins

| Plugin | What it does | Default |
|---|---|---|
| `trust` | Evaluates allow/deny policy with audit; verifies package integrity (never executes a manifest). | missing/invalid policy ⇒ deny |
| `protean` | Runs a command in a sandbox with a lease receipt, risk-routed substrates and JSONL evidence. | `low` = bubblewrap |
| `team` | Deterministic goal split, isolated clone, persistent state, at most one optional LLM call per task. | deterministic fallback |

## Install

```bash
pip install gamai-plugins
gamai-plugins list            # 3 plugins, tool names and input schemas
```

Optional Ed25519 verification for the trust plugin: `pip install 'gamai-plugins[crypto]'`.

## Quickstart (30 seconds): a deny that wins

```bash
cat > policy.json <<'JSON'
{"version": 1, "default": "deny",
 "allow": {"tools": ["shell"]},
 "deny":  {"commands": ["rm -rf*", "re:^\\s*sudo\\b"]}}
JSON
export GAMAI_POLICY=$PWD/policy.json

gamai-plugins call trust managed_policy '{"action":"check","tool":"shell","command":"ls -la"}'
# {"decision": "allow", "matched": ["tools:shell"], ...}

gamai-plugins call trust managed_policy '{"action":"check","tool":"shell","command":"rm -rf /"}'
# {"decision": "deny", "matched": ["commands:rm -rf*"], ...}
```

Patterns are **globs** (`rm -rf*`) unless prefixed with `re:` (`re:^\\s*sudo\\b`).
Deny always wins over allow, and a missing or invalid policy is a **deny** —
that is the point of the plugin, not a limitation.

Exit code is usable in CI: **0** = allow, **1** = deny (including fail-closed).

> **0.2.6:** the trust entry point was renamed from `gamai-trust` to
> `gamai-plugins-trust` — it used to shadow the `gamai-trust` package CLI when both
> were installed. The library API and MCP tool names are unchanged.

## MCP

```json
{
  "mcpServers": {
    "gamai-plugins": {
      "command": "gamai-plugins-mcp"
    }
  }
}
```

The server exposes six namespaced tools:

```text
trust_managed_policy
trust_marketplace_verify
protean_run
team_create
team_dispatch
team_status
```

## CLI

```bash
gamai-plugins list
gamai-plugins call trust managed_policy '{"action":"load"}'
gamai-plugins call protean run '{"cmd":"echo hi","risk":"low","timeout_s":5}'
gamai-plugins call team team_create '{"goal":"review this change","agents":2}'
gamai-plugins mcp
```

Or the per-plugin entry points:

```bash
gamai-plugins-trust managed_policy '{"action":"check","tool":"shell"}'
gamai-protean run '{"cmd":"uname -a","risk":"low"}'
gamai-team team_status '{"team_id":"team-..."}'
```

CLI exit code is non-zero when a tool returns `ok:false` or a trust decision is
`deny`, so shell/CI gates can use it.

## Python

```python
from gamai_plugins.cli import call

print(call("protean", "run", {"cmd": "echo hi", "risk": "low", "timeout_s": 5}))
```

## Policy and integrity semantics

`trust_managed_policy` is an **evaluator**, not an enforcement point. The caller
must enforce the returned `decision`. A valid policy without `default` is
`deny`; deny rules win. Paths are normalized and shell segments are evaluated
separately.

`trust_marketplace_verify` returns:

- `integrity_ok` — every expected file matches and there is no unexpected,
  truncated or symlinked content;
- `trusted` — integrity is complete and the signature verifies with a **pinned**
  key (`public_key` argument or `GAMAI_TRUST_PUBKEY`);
- `status` — `verified`, `self_signed`, `unsigned`, `failed` or `unverified`.

A self-signed manifest is not trusted. Without a manifest the result is
`unverified`, not a silent pass. See [docs/MANIFEST.md](docs/MANIFEST.md) for
the canonical signing form and `scripts/sign_manifest.py`.

## Team semantics

`team_create` creates a shared clone (not a source worktree) with
`core.hooksPath` pointing at an empty directory, so an untrusted repository
cannot execute hooks later. State is written before isolation, so a slow clone
does not leave a registered workspace without state.

`team` prompts and role hints are currently Bosnian. That is intentional, not a
translation layer; make it configurable if you need another language. Dispatch
is serialized per team: the LLM call happens while the team lock is held, so
concurrent dispatches wait rather than racing state.

## Configuration

| Variable | Used by | Meaning |
|---|---|---|
| `GAMAI_POLICY` | trust | policy JSON; default `~/.config/gamai/trust/policy.json` |
| `GAMAI_AUDIT` | trust | audit JSONL; default `~/.local/state/gamai/trust/audit.jsonl` |
| `GAMAI_AUDIT_DISABLE` | trust | `1` disables audit **only when the policy does not require audit** |
| `GAMAI_TRUST_PUBKEY` | trust | pinned Ed25519 key (PEM, 64 hex, or base64 raw 32 bytes) |
| `GAMAI_HOME` | trust | base config dir; default `~/.config/gamai` |
| `GAMAI_STATE` | trust | base state dir; default `~/.local/state/gamai` |
| `PROTEAN_HOME` | protean | data dir; default `~/.config/gamai/protean` |
| `PROTEAN_IMAGE` | protean | Docker image for medium/high; default `python:3.12-alpine` |
| `PROTEAN_HIGH_REMOTE` | protean | `1` allows high risk to use the configured remote gVisor |
| `PROTEAN_REMOTE_HOST` | protean | optional remote host for `critical` + gVisor |
| `PROTEAN_REMOTE_PORT`, `PROTEAN_REMOTE_KEY`, `PROTEAN_REMOTE_USER` | protean | SSH details for the remote substrate |
| `PROTEAN_KNOWN_HOSTS` | protean | SSH known_hosts; default `~/.ssh/known_hosts` |
| `PROTEAN_SSH_STRICT` | protean | `yes`, `accept-new` (default) or `no` |
| `GAMAI_TEAM_STATE_DIR` | team | state dir; default `~/.local/state/gamai/teams` |
| `GAMAI_TEAM_WORKTREES` | team | workspace dir; default `~/.cache/gamai/teams` |
| `GAMAI_TEAM_REPO` | team | default repo for isolation when `repo` is omitted |
| `GAMAI_TEAM_LLM_BUDGET` | team | max LLM calls per team; default 50 |
| `GAMAI_TEAM_LLM_TIMEOUT` | team | per-call timeout; default 40 s |
| `GAMAI_LLM_URL` | team | optional HTTPS endpoint for one LLM call per task; HTTP only for loopback |
| `GAMAI_LLM_TOKEN` | team | optional `X-Token` sent to that endpoint |
| `GAMAI_TEAM_AGENT` | team | default backend name; default `agent` |

No secret is stored in this repository. `protean` creates a per-install
`lease.key` at runtime with mode `600`.

## Safety model

- **Trust is fail-closed:** missing/invalid policy, invalid manifest or a
  required audit failure yields deny/failure.
- **Manifest is data:** `trust` hashes and verifies packages; it never executes
  a manifest.
- **Lease is a receipt, not authorization:** `protean` mints and verifies the
  lease in the same process. It binds command/genome/TTL for evidence, but it
  is not an external policy decision.
- **Substrate routing:** `low` uses bubblewrap; `medium`/`high` use Docker with
  no network, dropped capabilities, read-only root and resource limits;
  `critical` is denied unless a remote gVisor host is explicitly configured.
- **Bounded output:** `protean` captures at most 64 KiB per stream and returns
  at most 8,000 characters; evidence runs are pruned to the newest 200.
- **Audit cannot be disabled when required:** `GAMAI_AUDIT_DISABLE=1` is
  ignored when the policy says `audit: true`; audit failure becomes
  `deny`/`audit_failed`.
- **Team is not an authorization boundary.** It coordinates work; the backend
  decides what it executes. LLM redirects are not followed and public plain
  HTTP is refused; the configured HTTPS origin still receives the token by
  design.
- **Docker socket is root-equivalent.** Do not expose `protean` medium/high to
  untrusted users.
- **Trust score is heuristic:** `trust_score` is a documented 0–100 heuristic,
  not a cryptographic proof.

Read [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md) before
using this in production.

## Development

```bash
python -m unittest discover -s tests -v
python -m gamai_plugins.mcp --selftest
python scripts/smoke_mcp.py
```

The tests do not need network access, Docker, or an LLM. `protean` low-risk
tests use bubblewrap when available; Windows runs the same suite without it.

## License

MIT.
