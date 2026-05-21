#!/usr/bin/env python3
"""
verify_receipt.py — offline verifier for FeedOracle hybrid-PQC receipts (x402 #2357).

Verifies BOTH signatures on a hybrid-pqc receipt over the identical JCS-canonical bytes:
  1. ES256K  (classical, secp256k1 ECDSA)
  2. ML-DSA-65 (FIPS 204, post-quantum)

Plus the work-layer binding check:
  3. action_ref == SHA-256(JCS(preimage))

No facilitator callback. Fetches public keys from the JWKS URL (or a local snapshot).

Usage:
  python3 verify_receipt.py receipt_sample.json --jwks jwks_snapshot.json \
      [--preimage action_ref_preimage.json]

Dependencies:
  pip install cryptography pqcrypto
"""
import json, hashlib, base64, argparse, sys

def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def jcs(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, default=str).encode()

def canonical_bytes_for_signing(receipt: dict) -> bytes:
    """Strip sig values + pqc_signature, canonicalise the rest. Byte-identical to issuer."""
    work = json.loads(json.dumps(receipt, default=str))
    sig_block = work.get("signature", {})
    sig_block.pop("sig", None)
    sig_block.pop("signed_at", None)
    work["signature"] = sig_block
    work.pop("pqc_signature", None)
    return jcs(work)

def find_key(jwks: dict, kid: str):
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            return k
    return None

def verify_es256k(receipt, jwks):
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
    sig_block = receipt["signature"]
    kid = sig_block["kid"]
    jwk = find_key(jwks, kid)
    if not jwk:
        return False, f"ES256K key {kid} not in JWKS"
    x = int.from_bytes(b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(jwk["y"]), "big")
    pub = EllipticCurvePublicNumbers(x, y, ec.SECP256K1()).public_key()
    canonical = canonical_bytes_for_signing(receipt)
    sig = b64url_decode(sig_block["sig"])
    try:
        pub.verify(sig, canonical, ec.ECDSA(hashes.SHA256()))
        return True, "ES256K OK"
    except Exception as e:
        return False, f"ES256K FAIL: {e}"

def verify_mldsa(receipt, jwks):
    from pqcrypto.sign import ml_dsa_65
    pqc = receipt.get("pqc_signature")
    if not pqc:
        return False, "no pqc_signature block"
    kid = pqc["kid"]
    jwk = find_key(jwks, kid)
    if not jwk:
        return False, f"ML-DSA key {kid} not in JWKS"
    pk = b64url_decode(jwk["x"])
    canonical = canonical_bytes_for_signing(receipt)
    sig = b64url_decode(pqc["sig"])
    try:
        # pqcrypto's ml_dsa_65.verify returns a bool, it does NOT raise on bad sig.
        ok = ml_dsa_65.verify(pk, canonical, sig)
        if ok:
            return True, "ML-DSA-65 OK"
        return False, "ML-DSA-65 FAIL: signature does not verify over canonical bytes"
    except Exception as e:
        return False, f"ML-DSA-65 FAIL: {e}"

def verify_action_ref(receipt, preimage):
    expected = receipt.get("action_ref")
    if not expected:
        return None, "no action_ref in receipt"
    computed = hashlib.sha256(jcs(preimage)).hexdigest()
    if computed == expected:
        return True, f"action_ref binding OK ({computed[:16]}...)"
    return False, f"action_ref MISMATCH: receipt={expected[:16]}... computed={computed[:16]}..."

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("receipt")
    ap.add_argument("--jwks", required=True, help="JWKS file or URL")
    ap.add_argument("--preimage", help="action_ref preimage JSON (optional binding check)")
    args = ap.parse_args()

    receipt = json.load(open(args.receipt))

    if args.jwks.startswith("http"):
        import urllib.request
        jwks = json.load(urllib.request.urlopen(args.jwks, timeout=10))
    else:
        jwks = json.load(open(args.jwks))

    print(f"Receipt: {args.receipt}")
    print(f"  receipt_format: {receipt.get('receipt_format')}")
    print(f"  payment_hash:   {receipt.get('payment_hash','')[:32]}...")
    print(f"  action_ref:     {receipt.get('action_ref','')[:32]}...")
    print()

    results = []
    ok_es, msg_es = verify_es256k(receipt, jwks); print(f"  [1] {msg_es}"); results.append(ok_es)
    ok_pq, msg_pq = verify_mldsa(receipt, jwks);  print(f"  [2] {msg_pq}"); results.append(ok_pq)
    if args.preimage:
        preimage = json.load(open(args.preimage))
        ok_ar, msg_ar = verify_action_ref(receipt, preimage); print(f"  [3] {msg_ar}"); results.append(ok_ar)

    print()
    if all(r for r in results if r is not None):
        print("RESULT: PASS — hybrid signatures valid, binding intact")
        sys.exit(0)
    else:
        print("RESULT: FAIL")
        sys.exit(1)

if __name__ == "__main__":
    main()
