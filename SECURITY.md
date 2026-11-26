# Security

These plugins execute or coordinate code. Treat them as security-sensitive.

## Reporting

Do not open a public issue for a sandbox escape, policy bypass, lease forgery,
or secret exposure. Use GitHub's private vulnerability reporting for this
repository. Include a minimal reproducer and affected version.

## Boundaries

- `protean` is **not** a hardened multi-tenant sandbox or a VM. Docker socket
  access is root-equivalent. Use `risk=low` (bubblewrap) by default.
- `protean` low-risk uses a minimal read-only root, a `/etc` allowlist and a
  32 MiB `/tmp`; it does not mount `/root`, `/home`, `/opt`, `/var` or `/run`.
  The command allowlist checks only the first token; the sandbox is the
  boundary.
- `protean` never stores a lease key in git; the first run writes one to
  `~/.config/gamai/protean/lease.key` with mode 600.
- The `protean` lease is an internal consistency/evidence receipt. It is minted
  and verified in the same process; it is **not** caller authorization.
- `protean` remote SSH uses `StrictHostKeyChecking=accept-new` by default; set
  `PROTEAN_SSH_STRICT=yes` after verifying the host key.
- `trust` is fail-closed: missing/invalid policy or missing default means deny.
  If `audit: true` and the audit write fails, the decision is deny
  (`audit_failed`); `GAMAI_AUDIT_DISABLE` is ignored in that case.
- `trust` verifies signatures only against a pinned key (`public_key` argument
  or `GAMAI_TRUST_PUBKEY`). A self-signed manifest is reported as
  `self_signed`, not `trusted`.
- `team` is a coordinator, not an authorization boundary. It executes no LLM
  output itself. LLM calls refuse non-loopback HTTP and do not follow
  redirects; the configured HTTPS origin still receives the token by design.
- `team` clones with hooks disabled (`core.hooksPath` → empty directory) and
  writes state with mode 600 on POSIX. Keep the state directory private.

## Supported versions

0.2.x receives security fixes.
