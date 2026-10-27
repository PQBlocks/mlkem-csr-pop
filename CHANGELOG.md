# Changelog: pqblocks-csr-pop

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-10-26

### Added
- PKCS#10 Certificate Signing Request (CSR) generator supporting ML-KEM-768 and ML-KEM-1024 public keys per NIST FIPS 203.
- RFC 9883 Proof of Possession (PoP) attribute (`statementOfPossession`) construction and verification.
- Dual-key attestation model supporting Ed25519 and standard x509 attestor credentials.
- ASN.1 DER parser for incoming PKCS#10 requests and cryptographic signature verification.
- Vendored KAT corpora from NIST ACVP and Google Wycheproof test vectors.
- Comprehensive test suite with 438 passing automated tests.
- Multi-version support across Python 3.11, 3.12, 3.13, and 3.14.
