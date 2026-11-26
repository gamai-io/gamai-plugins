# Changelog

## 0.2.8 — 2026-11-26
- The protean allowlist now checks every shell segment and the inside of
  `sh -c '...'`, so `sh -c 'rm ...'`, `( env )` and `echo $(...)` no longer slip
  past a first-token check. Still best-effort: the sandbox is the boundary.
- `net=true` is refused: the bwrap path dropped `--unshare-net` and shared the
  host network namespace. No substrate grants network now.
- Remote gVisor: `ssh` options now end with `--` before the destination, so the
  remote command is not prefixed with `--` (it never ran).
- 0.2.6 is yanked on PyPI; 0.2.7 published the deny/integrity fixes.

## 0.2.7 — 2026-11-26
- A deny rule can no longer be bypassed with a bare `&`, `$(...)`, backticks or a
  subshell: the splitter treats them as separators and the whole command is
  matched as well.
- `marketplace_verify` no longer says `complete`/`verified` while files inside
  `node_modules`, `.git`, `__pycache__`, etc. were never hashed. `skipped_content`
  is reported and makes the result incomplete.
- Not yet on PyPI (publishing needs the account login); install from git.

## 0.2.2 — 2026-10-22

- `trust`: added `scripts/sign_manifest.py` and `docs/MANIFEST.md` for the
  canonical signing form; improved redaction coverage; stale audit/rotation
  edge cases.
- `protean`: `prlimit` is used only when it is inside the mounted root; the
  fallback shell applies `ulimit` limits.
- `team`: stale Windows lock directories older than 10 minutes are reclaimed;
  README now documents serialized dispatch and substrate-dependent binaries.
- Tests: 33; CI remains Ubuntu + Windows, Python 3.10/3.11/3.12.

## 0.2.1 — 2026-10-22

- Windows: replace byte-range `msvcrt` locking with an atomic directory
  lock, fixing `PermissionError`/lock failures on real Windows runners.
- Windows: normalize policy paths to forward slashes before matching, so
  `/etc/*` rules work with Windows-normalized paths.
- Windows: reconfigure plugin stdin/stdout to UTF-8 for Bosnian diacritics.
- Added `test_cli.py` and the MCP stdio smoke script to CI.

## 0.2.0 — 2026-10-22

Security and correctness hardening from a five-agent audit.

- `protean`: low-risk now mounts a minimal read-only root and an allowlist of
  `/etc` files (not all of `/etc`); only the resolv.conf file is bound, never
  `/run`; `/etc/shadow`, `gshadow`, `sudoers`, SSH/TLS keys are masked;
  32 MiB `/tmp`; `prlimit` memory/process caps; output capture bounded.
- `protean`: remote container gets its own `timeout`; evidence runs are pruned.
- `trust`: a valid manifest must be complete (no unexpected, truncated or
  symlinked content) for `integrity_ok`; a self-signed manifest is
  `self_signed`, not trusted; pinned Ed25519 key via argument or
  `GAMAI_TRUST_PUBKEY` gives `verified`.
- `trust`: audit uses `O_NOFOLLOW`, regular-file checks, rotation and tail
  reads; audit failure denies when required and cannot be disabled by env.
- `trust`: policy default is deny; paths are normalized and shell segments are
  evaluated; manifest digests, regexes and sizes are validated.
- `team`: default clone (not worktree) with persistent `core.hooksPath`
  isolation; Windows `msvcrt` lock retries with a real deadline; proxy
  environment is ignored; multi-line goals split correctly; new tasks after
  `done` are not swallowed; state is saved before isolation; reserved Windows
  ids and non-UTF8 subprocess output are handled.
- CLI/MCP: UTF-8 pipes, malformed JSON handling, JSON-RPC notifications and
  batches, manifest timeouts, non-zero CLI exit on deny, non-object line
  resilience.
- CI: Ubuntu/Windows, Python 3.10/3.11/3.12, MCP stdio smoke, wheel build.

## 0.1.2 — 2026-10-22

- `team`: LLM calls no longer follow redirects and refuse plain HTTP to
  non-loopback hosts, preventing token forwarding and SSRF-style use.
- `team`: git worktrees/clones run with `core.hooksPath` pointing at an empty
  directory, so an untrusted repository cannot execute hooks.
- `trust`: audit failure now denies when the policy requires audit; audit
  commands are redacted and length-capped.
- `trust`: `marketplace_verify` exposes `trusted` and `integrity_ok`, and
  unsigned manifests cannot hide files through `ignore`.
- `protean`: stdout/stderr capture is bounded (64 KiB per stream), preventing
  memory exhaustion from noisy commands.
- CI now runs on Ubuntu and Windows, Python 3.10 and 3.12.
- Tests: 15.

## 0.1.1 — 2026-10-22

- Security: `protean` low-risk now uses a minimal read-only root instead of
  exposing the whole host filesystem. `/etc/shadow`, `gshadow`, `sudoers`,
  host SSH keys and private TLS keys are masked; `/root`, `/home`, `/opt` and
  `/var` are not mounted.
- Security: `protean` remote SSH uses `accept-new` host-key checking by default
  and a persistent known_hosts file.
- Security: state/audit files are written with mode `600` and state dirs `700`.
- Portability: `team` no longer hard-depends on `fcntl`; Windows uses `msvcrt`
  locking.
- Robustness: `team` rejects an existing custom team id, caps LLM responses,
  rejects non-HTTP(S) endpoints, and avoids leaking endpoint errors.
- Fixed a public denial message that still mentioned an internal host.
- Added regression tests for host-secret isolation and file permissions.

## 0.1.0 — 2026-10-22

- Initial portable release of `trust`, `protean` and `team`.
- One MCP stdio server and one CLI for all three plugins.
- Env-driven paths; no internal hosts, tokens or harness paths.
- `protean` creates its lease key locally and ships its seccomp profile.
- `team` uses an optional generic HTTP LLM endpoint and a deterministic fallback.
- Tests for policy fail-closed behavior, integrity verification, sandbox
  execution, remote denial, team persistence and MCP discovery.
