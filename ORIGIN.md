# Origin and implementation scope

CrlRevocationReview independently implements this selected scope: Direct-issuer full CRL signature and freshness verification for one pinned issuer and one explicitly supplied target certificate.

The research source is [wbond/certvalidator](https://github.com/wbond/certvalidator) at fixed commit `dff539af0919b6eb9cecf7d9a5180bf1826c8770`. Source archive SHA-256: `861d84a9c7113d54090f876a312c3d69829a65462b259e638c06257a82f07d1a`. Its license is MIT; the exact source license notice is retained as `UPSTREAM_LICENSE`. The new application code and documentation are licensed under MIT (`LICENSE`). The upstream application is neither imported nor executed by the production package. No upstream application source is bundled in the production package.

## Selected source evidence

- [certvalidator/validate.py](https://github.com/wbond/certvalidator/blob/dff539af0919b6eb9cecf7d9a5180bf1826c8770/certvalidator/validate.py) — SHA-256 `c298d153b624226a7483e3ca8922986c312b43eec83966fa0356775a726c58c8`.
- [certvalidator/path.py](https://github.com/wbond/certvalidator/blob/dff539af0919b6eb9cecf7d9a5180bf1826c8770/certvalidator/path.py) — SHA-256 `8c9960b5d48b64bd25f64e5b16b1a566e5245b31f19b9b66d01dfbb993669108`.

Full selected file contents and their inventory are retained in the research archive identified by `provenance/SOURCE_REVIEW.json`; those fixed links and hashes allow independent reconstruction. Review focused on direct CRL applicability, signature and freshness, delta/indirect/partial semantics deliberately excluded. This record does not assert a whole-platform source audit, original authorship of standards, or equivalence to all upstream behavior.

## Concrete new work

The new implementation owns bounded local input parsing, strict supported-field validation, the complete selected application logic, explicit trust input binding, fail-closed unsupported semantics, privacy-limited result fields, and a three-state CLI contract. Mature cryptographic primitives are reused rather than reimplemented. New scope and tests are substantive application work; a source SHA, rename, mirror or wrapper is not claimed as original contribution.

Required public `issuer_pem`, independently pinned `issuer_sha256`, target `certificate_pem`, standard base64 `crl_der` and timezone-aware `now` bind one direct issuer and one target. Issuer/leaf signature, issuer CA/keyCertSign/crlSign use, validity, unknown critical extensions, CRL issuer, supported AKI/CRLNumber fields, actual signature, this/next update and every revocation entry are checked. A fresh complete direct CRL without the target reports scoped `not_listed`; a signed revoked target reports FAIL with `complete=true` and `verified=true`. Delta, indirect, issuingDistributionPoint/partial, removeFromCRL, unsupported entry semantics, duplicate serials and missing nextUpdate fail closed. No root chain or distribution-point applicability proof is claimed.

## Primitive policy

All Ed25519 keys and signature R points require canonical nonidentity main-subgroup points. The package calls libsodium point validation and also verifies [L-1]P+P equals identity with native scalar-multiplication/addition primitives, covering older system-library subgroup behavior. Certificate/CRL inner and outer AlgorithmIdentifiers must match exactly. The selected ASN.1 profile permits RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and absent-parameter Ed25519; family and digest must match the signer. These are deliberately strict declared limits.

Primary references: [libsodium point arithmetic](https://libsodium.gitbook.io/doc/advanced/point-arithmetic), [RFC 5280 certificate/CRL identifiers](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2), [RFC 8410 Ed25519 parameters](https://www.rfc-editor.org/rfc/rfc8410.html#section-3).

## Defensive use and application evidence

Inputs must belong to the authorized reviewer. Runtime performs no fetch, sample execution, private-key processing, key export, signing, remote modification or outbound communication. CVP organizational eligibility, evidence of a legitimate blocked task, application review and program acceptance remain OPEN. These local results alone do not establish them.
