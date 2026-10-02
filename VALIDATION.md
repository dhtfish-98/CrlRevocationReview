# Validation

Recorded on 2026-10-02 for the final selected implementation. 11 unittest cases passed. Runtime dependencies: cryptography==50.0.2; PyNaCl==1.6.2 for native Ed25519 public-point validation. Python 3.14 on macOS arm64 was exercised. Other operating systems and Python versions remain untested.

The suite covers valid declared inputs, malformed/unsupported input, duplicate and nonfinite JSON, lone-surrogate input rejected through both API and CLI, bounded local regular-file reads (symlink/FIFO rejection), and failing CLI exit status. Project-specific tests cover the cryptographic or static semantics listed below. Each project with a cryptographic input also rejects identity, torsion and noncanonical Ed25519 points through its concrete application API and CLI; CRL/OCSP additionally reject certificate/CRL inner-versus-outer AlgorithmIdentifier mismatches. Shared tests reject signature key-family/hash mismatches and noncanonical signature scalars. Normal tests use temporary files and never rewrite saved examples.

## Independent or standard comparison

```json
{
  "reference": "OpenSSL 3.6.2 7 Apr 2026 (Library: OpenSSL 3.6.2 7 Apr 2026)",
  "valid_signature_accepted_by_both": true,
  "tamper_rejected_by_both": true,
  "valid_output": "verify OK\n",
  "tamper_output": "verify failure\nC0A15BF001000000:error:0200008A:rsa routines:RSA_padding_check_PKCS1_type_1:invalid padding:crypto/rsa/rsa_pk1.c:78:\nC0A15BF001000000:error:02000072:rsa routines:rsa_ossl_public_decrypt:padding check failed:crypto/rsa/rsa_ossl.c:779:\nC0A15BF001000000:error:1C880004:Provider routines:rsa_verify_directly:RSA lib:providers/implementations/signature/rsa_sig.c:1038:\nC0A15BF001000000:error:06880006:asn1 encoding routines:ASN1_item_verify_ctx:EVP lib:crypto/asn1/a_verify.c:219:\n"
}
```

This comparison is validation-only. Upstream application packages are not runtime dependencies.

## Packaging and isolation

A wheel was built and installed into a separate per-project virtual environment with source import paths removed. The imported module resided in that environment. The installed CLI accepted the saved valid request (exit 0), rejected an empty object (exit 1), and the installed audit completed with socket creation blocked. This proves the exercised offline input profile and installed artifact; it does not prove all code paths, real deployment, program eligibility or acceptance. Final wheel SHA-256 and installation details are recorded by the aggregate publication evidence.

## Review and limits

Every new production source file was reviewed, including file handling, parser bounds, trust binding, result semantics and unsupported branches. Fixed upstream source review boundaries are listed in ORIGIN.md and provenance/SOURCE_REVIEW.json. Pinned direct issuer only. No root-chain building, distribution-point fetch, delta CRLs, indirect CRLs, partitioned CRLs, or partial reason coverage. Not listed in this fresh full CRL is scoped revocation evidence, not general certificate safety.

Cryptographic PASS asserts only the explicit signed input contract where `verified=true`. Static audits retain `verified=false`. An authenticated revoked status can be FAIL with `complete=true`; an unsupported or invalid input is FAIL with `complete=false`. No repository count, package build, or synthetic test is used as evidence of CVP eligibility.
