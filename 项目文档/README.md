> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# CrlRevocationReview

New implementation author: **dhtfish98**. Package version: **0.1.2**.

Direct-issuer full CRL signature and freshness verification for one pinned issuer and one explicitly supplied target certificate.

This is an independently implemented, complete selected offline input profile. It is not an equivalent rewrite of the entire upstream platform. Cryptographic primitives use cryptography; no upstream application is called.

## Contract

Run `crl-revocation-review request.json` or pipe JSON to `crl-revocation-review -`. Every input is local and supplied by its authorized owner. Parsing is bounded; duplicate fields, unknown algorithms, unsupported semantics, and failed signatures fail closed. The CLI returns 0 for PASS, 1 for FAIL, and 2 for OPEN. PASS applies only to the declared profile; it is not a general safety or CVP eligibility finding. Output excludes private material and raw credential identifiers.

## Boundaries

- Pinned direct issuer only. No root-chain building, distribution-point fetch, delta CRLs, indirect CRLs, partitioned CRLs, or partial reason coverage. Not listed in this fresh full CRL is scoped revocation evidence, not general certificate safety.

CVP organizational eligibility, an actually blocked legitimate task, application review, and approval remain OPEN. A repository and passing tests do not establish eligibility.

## Complete input profile

Required public `issuer_pem`, independently pinned `issuer_sha256`, target `certificate_pem`, standard base64 `crl_der` and timezone-aware `now` bind one direct issuer and one target. Issuer/leaf signature, issuer CA/keyCertSign/crlSign use, validity, unknown critical extensions, CRL issuer, supported AKI/CRLNumber fields, actual signature, this/next update and every revocation entry are checked. A fresh complete direct CRL without the target reports scoped `not_listed`; a signed revoked target reports FAIL with `complete=true` and `verified=true`. Delta, indirect, issuingDistributionPoint/partial, removeFromCRL, unsupported entry semantics, duplicate serials and missing nextUpdate fail closed. No root chain or distribution-point applicability proof is claimed.

All accepted Ed25519 public keys are canonical nonidentity points in the main subgroup, checked through libsodium. Ed25519 signature R points must also be canonical nonidentity main-subgroup points and S must be below the group order. Certificates and CRLs require exactly matching inner/outer AlgorithmIdentifiers; the strict profile permits only RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and Ed25519 with absent parameters. OCSP permits the same explicit algorithm encodings and key-family/hash binding.

Where the profile accepts public PEM inputs, they contain one SubjectPublicKeyInfo or certificate object respectively, with canonical base64, no duplicate object and no trailing content. UTF-8 string values and keys reject lone surrogates; parsed floating-point overflow is rejected as nonfinite; JSON results are safely ASCII-escaped.

The saved `examples/valid.json` is synthetic and contains only public data. Time-dependent examples retain their recorded reference `now`; tests generate fresh synthetic objects in temporary directories without changing examples.

## Install and check

```sh
python -m pip install .
python -m unittest discover -s tests -v
crl-revocation-review examples/valid.json
```

See [ORIGIN.md](<ORIGIN.md>), [VALIDATION.md](<VALIDATION.md>), [LICENSE](<LICENSE>) and [UPSTREAM_LICENSE](<../UPSTREAM_LICENSE>) for scope, evidence and attribution.

## File input platform contract

Regular-file input and file-based CLI requests require usable `os.O_NOFOLLOW` and `os.O_NONBLOCK` capabilities. Missing capabilities produce a controlled incomplete FAIL; there is no fallback that follows the final-component symlink or blocks on a FIFO. macOS and Linux CI have been exercised. Native Windows file-input behavior remains unverified.

## Re-audited input semantics

As a strict profile consistency requirement, every revocationDate must be at or before the CRL thisUpdate issuance time. Contradictory evidence is FAIL with complete=false, even if its signature validates. A consistent authenticated revoked target remains FAIL with complete=true. This follows the issuance and revocation time meanings in [RFC 5280 sections 5.1.2.4 and 5.1.2.6](https://www.rfc-editor.org/rfc/rfc5280.html#section-5.1.2.4); it does not extend the scope to full PKIX validation.
