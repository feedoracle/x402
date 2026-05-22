# hybrid-pqc conformance fixtures (v0)

Conformance vectors for the **receipt-integrity signature** axis (Axis 2) of the x402 receipt extension discussed in [#2357](https://github.com/x402-foundation/x402/issues/2357). Sibling suite to [`action-ref-verify`](../../action-ref-verify/v0/) (Axis 3, [#2398](https://github.com/x402-foundation/x402/pull/2398)).

This suite covers post-quantum receipt integrity: a hybrid **ES256K + ML-DSA-65** signature over the same JCS-canonical bytes, offline-verifiable against a public JWKS with no facilitator callback.

## Derivation

```
canonical_bytes = JCS(RFC 8785)(receipt_core)   # sig values stripped before canonicalisation
ES256K_sig      = ES256K_sign(canonical_bytes)
ML-DSA-65_sig   = ML-DSA-65_sign(canonical_bytes)   # FIPS 204, same bytes
```

Both signatures cover the **identical** canonical bytes. A verifier requires BOTH to validate — an attacker must break ES256K (classical) *and* ML-DSA-65 (post-quantum) to forge. This is the hybrid construction NIST IR 8547 and the EU PQC roadmap endorse for the migration period: PQC/classical hybrids remain permitted past the 2035 ECDSA disallowance line because the classical half is composed with, not relied upon alone.

## Vectors

| # | Name | Result | Tests |
|---|------|--------|-------|
| 0001 | baseline-hybrid-pqc | PASS | Canonical receipt core; both sigs cover SHA-256(JCS(core)) |
| 0002 | field-name-load-bearing | FAIL | `observed_at` (RFC 3339) vs `observed_at_ms` (epoch int) → different digest |
| 0003 | hybrid-signature-tamper-evidence | FAIL | One byte flipped in signed core → both sigs fail |
| 0008 | interop-shared-payment-hash | PASS | Cross-layer binding via shared `payment_hash` + `action_ref` |

Negative vectors (0002, 0003) pin the **actual divergent digest** (`expected_divergent_digest`), not just inequality — per the cross-axis convention agreed on [#2398](https://github.com/x402-foundation/x402/pull/2398). A downstream harness then catches the wrong-but-deterministic case (an implementation that diverges in a *different* way that still differs from baseline).

## Cross-axis interop

Vector 0008 carries the same `payment_hash` (`2ed186eb…0f580`) and `action_ref` (`10d8a38c…0c2c1`) as:
- [`action-ref-verify` v0 vector 0008](../../action-ref-verify/v0/vectors/0008-interop-shared-payment-hash.json) (Axis 3, work-receipt binding)
- the zkpay STARK Axis 1 set (payment-conditions proof)

One payment, three axes: payment-conditions proof (STARK) / receipt-integrity signature (this) / work-receipt binding (action_ref). The `action_ref` digest `10d8a38c…` reproduces across Node.js, Python, Rust, and our path with independent JCS implementations and no shared code.

## Validation

Substrate validation: chopmob-cloud (AlgoVoi) 4-impl JCS reference matrix (rfc8785@0.1.4 / canonicalize@3.0.0 / gowebpki/jcs v1.0.1 / cyberphone/json-canonicalization) -- 4 vectors x 4 implementations = 16/16 byte-for-byte agreements; divergent-digest pin on vector 0002 confirmed across all 4 impls. JWKS rotation check: pinned snapshot SHA-256 `6ecad37c...` byte-equivalent to live `https://tooloracle.io/.well-known/jwks.json` at time of validation.

## Reproducing

```bash
pip install cryptography pqcrypto

# Verify the signed receipt sample against the live JWKS (independent, no callback):
python3 verify_receipt.py receipt_sample_signed.json \
    --jwks https://tooloracle.io/.well-known/jwks.json \
    --preimage action_ref_preimage.json
# RESULT: PASS — hybrid signatures valid, binding intact

# Or against the pinned snapshot:
python3 verify_receipt.py receipt_sample_signed.json --jwks jwks_snapshot.json --preimage action_ref_preimage.json
```

To check a vector's pinned digest, recompute `SHA-256(JCS(receipt_core))` and compare to `expected_core_digest` (PASS vectors) or `expected_divergent_digest` (FAIL vectors).

## Keys

```
https://tooloracle.io/.well-known/jwks.json
  kid "feedoracle-mcp-es256k-1"  kty "EC"      alg "ES256K"     (secp256k1)
  kid "feedoracle-mldsa65-1"     kty "ML-DSA"  alg "ML-DSA-65"  (FIPS 204, Category 3)
```

## Regulatory note

ML-DSA-65 is NIST FIPS 204 at Security Category 3. NIST IR 8547 deprecates 112-bit ECDSA after 2030 and disallows it after 2035; the IR 8547 PQC Forum clarification confirms the disallowance does not apply to hybrid modes combining an approved PQC algorithm with a classical one. The EU PQC roadmap (June 2025) and ENISA both recommend starting with hybrid schemes; the roadmap targets PQC for critical-infrastructure-including-finance by 2030. For MiCA Art. 76 / EU AI Act Art. 12 deployments not needing zero-knowledge proof of payment conditions, the hybrid signature is the compliant receipt-integrity path at ~3.3 KB rather than ~100 KB.

## Source

Derived from the FeedOracle Grounding Receipt v0.4 format. Reference gist: https://gist.github.com/feedoracle/704ab891170e2b43050f6f0ae00e6923 · Apache-2.0.
