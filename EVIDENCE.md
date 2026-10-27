# Verification Evidence: pqblocks-csr-pop

This document records the empirical verification evidence for `pqblocks-csr-pop` (v0.1.0).

---

## Environment & Build Metadata

- **Package**: `pqblocks-csr-pop`
- **Version**: `0.1.0`
- **Build Backend**: `setuptools>=77`
- **Wheel Artifact**: `pqblocks_csr_pop-0.1.0-py3-none-any.whl`
- **Sdist Artifact**: `pqblocks_csr_pop-0.1.0.tar.gz`
- **Date Verified**: 2026-10-26

---

## Test Execution Summary

Executed across Python 3.11, 3.12, 3.13, and 3.14:

```
platform linux -- Python 3.14.8, pytest-9.1.1, pluggy-1.6.0
rootdir: <repo>/packages/pqblocks-csr-pop
configfile: pyproject.toml
testpaths: tests
plugins: hypothesis-6.168.0, cov-7.1.0, anyio-4.15.1
collected 438 items

tests/test_S4_implement_error_taxonomy.py .............                  [  2%]
tests/test_cri.py ..............                                         [  6%]
tests/test_csr_builders.py ................................              [ 13%]
tests/test_equivalence.py ............                                   [ 16%]
tests/test_errors.py .............                                       [ 19%]
tests/test_g3_cover_push3.py .....................................       [ 27%]
tests/test_g3_coverage_boost.py ........................................ [ 36%]
.......                                                                  [ 38%]
tests/test_g3_coverage_boost_manager.py ................................ [ 45%]
.......................................                                  [ 54%]
tests/test_g3_coverage_boost_manager2.py ............................... [ 61%]
.....................                                                    [ 66%]
tests/test_g3_coverage_final.py ........................................ [ 75%]
..............                                                           [ 78%]
tests/test_g3_golden.py ......                                           [ 80%]
tests/test_kat_acvp.py .......                                           [ 81%]
tests/test_kat_wycheproof.py ......                                      [ 83%]
tests/test_mlkem.py ..............                                       [ 86%]
tests/test_mlkem_coverage_final.py ..........................            [ 92%]
tests/test_policy.py ..................................                  [100%]

======================= 438 passed, 14 warnings in 2.58s =======================
```

- **Python 3.11**: 438 passed in 2.75s
- **Python 3.12**: 438 passed in 2.70s
- **Python 3.13**: 438 passed in 2.65s
- **Python 3.14**: 438 passed in 2.58s

---

## FIPS 203 & RFC 9883 Sizing Assertions

| Parameter | Standard | Expected Bytes | Verified Bytes | Status |
|---|---|---|---|---|
| ML-KEM-768 Encapsulation Key | FIPS 203 | 1184 | 1184 | PASS |
| ML-KEM-1024 Encapsulation Key | FIPS 203 | 1568 | 1568 | PASS |
| ML-KEM Keygen Seed | FIPS 203 | 64 | 64 | PASS |
| Ed25519 Attestor Key | RFC 8032 | 32 | 32 | PASS |
| PKCS#10 CSR (ML-KEM-768 + PoP) | RFC 9883 | ~1393 | 1393 | PASS |
| PKCS#10 CSR (ML-KEM-1024 + PoP) | RFC 9883 | ~1833 | 1833 | PASS |

---

## Package Integrity & Security Audit

- **`twine check --strict`**: PASSED (valid package description and metadata).
- **Leak Gate Audit**: 49 files scanned, 0 hits (zero internal tokens, rules, or environment leaks).
- **Supply Chain**: Relies on `cryptography>=50.0.0` with no binary extensions required.
