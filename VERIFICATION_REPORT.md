# Verification Report: pqblocks-csr-pop (v0.1.0)

**Date**: 2026-10-26  
**Auditor**: PQBlocks Independent Release Pipeline  
**Target**: `pqblocks-csr-pop` (ML-KEM PKCS#10 CSR Generator with RFC 9883 Proof of Possession)

---

## 1. Executive Summary

`pqblocks-csr-pop` (v0.1.0) has passed all release verification gates:
- **Build & Packaging**: Clean sdist and wheel built; `twine check --strict` passed.
- **Cross-Version Runtime**: Verified across Python 3.11, 3.12, 3.13, and 3.14.
- **Test Integrity**: 438 of 438 tests passed across all target Python versions.
- **Examples**: Both `quickstart.py` and `02_mlkem1024_csr_with_pop.py` executed successfully.
- **Public Hygiene**: Zero leakage of internal tokens, paths, or development artifacts.

---

## 2. Gate Verification Details

| Gate / Check | Target | Result | Evidence |
|---|---|---|---|
| Build Artifacts | `dist/*.whl`, `dist/*.tar.gz` | PASS | Built `pqblocks_csr_pop-0.1.0-py3-none-any.whl` |
| PyPI Metadata | `twine check --strict` | PASS | Strict metadata check PASSED |
| Python 3.11 Test Suite | 438 tests | PASS | 438 passed in 2.75s |
| Python 3.12 Test Suite | 438 tests | PASS | 438 passed in 2.70s |
| Python 3.13 Test Suite | 438 tests | PASS | 438 passed in 2.65s |
| Python 3.14 Test Suite | 438 tests | PASS | 438 passed in 2.58s |
| Python 3.11 Example 1 | `quickstart.py` | PASS | Exit code 0 |
| Python 3.11 Example 2 | `02_mlkem1024_csr_with_pop.py` | PASS | Exit code 0 |
| Python 3.12 Example 1 | `quickstart.py` | PASS | Exit code 0 |
| Python 3.12 Example 2 | `02_mlkem1024_csr_with_pop.py` | PASS | Exit code 0 |
| Python 3.13 Example 1 | `quickstart.py` | PASS | Exit code 0 |
| Python 3.13 Example 2 | `02_mlkem1024_csr_with_pop.py` | PASS | Exit code 0 |
| Python 3.14 Example 1 | `quickstart.py` | PASS | Exit code 0 |
| Python 3.14 Example 2 | `02_mlkem1024_csr_with_pop.py` | PASS | Exit code 0 |
| Leak Gate | Package directory, wheel, sdist | PASS | 0 leak hits across 49 files |
| Required Files | Governance, CI, legal, docs | PASS | All 18 standard files present |

---

## 3. Scope & Non-Claims

1. **Non-FIPS Validation**: Independent open-source implementation. Not CMVP/FIPS 140-3 validated.
2. **Primitive Delegation**: ML-KEM and Ed25519 primitives are provided by `cryptography>=50.0.0` backed by OpenSSL 3.0+. No custom lattice math is implemented directly in this layer.
3. **PoP Attestation Model**: Follows RFC 9883 dual-key CSR architecture where a signing key attests to the possession of the KEM key.

---

## 4. Release Recommendation

**VERIFIED FOR RELEASE**: Meets all functional, performance, security, and documentation standards.
