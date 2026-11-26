#!/usr/bin/env python3
"""Sign a trust manifest with Ed25519 using the same canonical form as trust.

The payload is the manifest minus signature/signatures/public_key/sig_alg/
signature_alg, serialized as compact sorted JSON. The signature is stored under
`signature`; the public key is printed but not added to the manifest (pin it
separately with GAMAI_TRUST_PUBKEY).
"""
import argparse
import base64
import json
import sys

SIGN_EXCLUDE = {"signature", "signatures", "public_key", "sig_alg", "signature_alg"}


def canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str).encode("utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("--key", required=True, help="raw 32-byte Ed25519 key or PEM private key")
    ap.add_argument("--out", help="write signed manifest here (default: stdout)")
    args = ap.parse_args()
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except Exception:
        print("cryptography is required: pip install 'gamai-plugins[crypto]'", file=sys.stderr)
        return 2
    with open(args.key, "rb") as fh:
        raw = fh.read()
    if b"BEGIN PRIVATE KEY" in raw:
        key = serialization.load_pem_private_key(raw, password=None)
    else:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(raw[:32])
    with open(args.manifest, encoding="utf-8") as fh:
        manifest = json.load(fh)
    if not isinstance(manifest, dict):
        print("manifest root must be an object", file=sys.stderr)
        return 2
    payload = {k: v for k, v in manifest.items() if k not in SIGN_EXCLUDE}
    sig = key.sign(canon(payload))
    manifest["signature"] = {"alg": "ed25519",
                             "value": base64.b64encode(sig).decode()}
    text = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    print("public_key=" + base64.b64encode(pub).decode(), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
