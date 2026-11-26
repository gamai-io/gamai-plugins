# Threat model (summary)

| Asset | Threat | Control |
|---|---|---|
| Host | command execution | minimal bwrap root, genome token check, TTL, timeout, output cap |
| Host | secret read | `/etc` allowlist; shadow/gshadow/sudoers/SSH/TLS keys masked; `/root`, `/home`, `/opt`, `/var`, `/run` not mounted |
| Host | resource exhaustion | 32 MiB `/tmp`, `prlimit` address-space/process caps, bounded capture |
| Lease | forged/replayed evidence | HMAC-SHA256, TTL, command/genome binding, per-install key |
| Policy | missing/tampered | fail-closed deny, normalized paths, segment matching, audit |
| Audit | silent edit/leak | `O_NOFOLLOW`, regular-file check, 600 mode, rotation, redaction |
| Manifest | substitution/self-signing | SHA-256 + Ed25519; only a pinned key yields `trusted` |
| Secrets | leak to LLM origin | HTTPS/loopback only, no redirects, explicit `X-Token` |
| Team | runaway LLM use | per-task budget, one call per dispatch, no self-signed trust |
| Team | malicious git repo | shared clone; persistent `core.hooksPath` to empty dir |
| Team | state corruption | atomic writes, lock deadline, state saved before isolation |

Residual risks: Docker daemon compromise, kernel bugs, GPU memory is shared,
bubblewrap is namespaces (not a kernel), the command allowlist checks only the
first token, the lease is not external authorization, and `team` state is not
encrypted. `trust_score` is a heuristic, not a proof.
