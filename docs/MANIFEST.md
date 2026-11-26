# Manifest signing

`trust_marketplace_verify` signs/verifies the manifest **minus**
`signature`, `signatures`, `public_key`, `sig_alg` and `signature_alg`, using
compact sorted JSON (`ensure_ascii=False`, separators `,` and `:`).

Generate a key and sign:

```bash
python - <<'PY'
from cryptography.hazmat.primitives.asymmetric import ed25519
open('ed25519.key','wb').write(ed25519.Ed25519PrivateKey.generate().private_bytes_raw())
PY
python scripts/sign_manifest.py manifest.json --key ed25519.key --out signed.json
```

Pin the printed public key on the verifier:

```bash
gamai-plugins call trust marketplace_verify \
  '{"path":"pkg","public_key":"<printed-public-key>"}'
# or export GAMAI_TRUST_PUBKEY
```

A valid signature made with the manifest's own key is reported as
`self_signed`; only a pinned key yields `verified`/`trusted`.
