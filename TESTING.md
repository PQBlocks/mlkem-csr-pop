# Testing & Test Suite: pqblocks-csr-pop

This document outlines the testing strategy, test coverage, and execution instructions for `pqblocks-csr-pop`.

---

## Test Suite Overview

The package features 438 automated unit, property, and integration tests across 16 test files:

| Module | Focus Area | Count |
|---|---|---|
| `test_cri.py` | Certification Request Information (CRI) ASN.1 encoding | 14 |
| `test_csr_builders.py` | PKCS#10 CSR structure creation, attribute injection, roundtrips | 32 |
| `test_equivalence.py` | Equivalence against reference KEM implementations | 12 |
| `test_errors.py` | Error taxonomy and exception mapping | 13 |
| `test_g3_golden.py` | Golden byte assertions for deterministic ML-KEM CSRs | 6 |
| `test_kat_acvp.py` | NIST ACVP FIPS 203 KAT vectors (keygen and decapsulation) | 7 |
| `test_kat_wycheproof.py` | Google Wycheproof known answer test vectors | 6 |
| `test_mlkem.py` | ML-KEM key generation, parameter validation, sizing | 14 |
| `test_mlkem_coverage_final.py` | Comprehensive ML-KEM branch and edge case coverage | 26 |
| `test_policy.py` | Certificate policy validation and OID compatibility | 34 |
| `test_S4_implement_error_taxonomy.py` | Exhaustive error condition validation | 13 |
| Additional coverage boost files (`test_g3_cover_push3`, `test_g3_coverage_*`) | Edge cases, malformed ASN.1 parsing, tamper resistance | 261 |

**Total Tests**: 438 passing.

---

## Vendored Official Vector Corpora

The package carries self-contained, official test vector files under `tests/kats/`:
- **NIST ACVP**: `tests/kats/acvp/` containing `internalProjection.json`, `keyGen.json`, `lane_generated_roundtrip.json`.
- **Google Wycheproof**: `tests/kats/wycheproof/` containing `mlkem_768_test.json`, `mlkem_768_keygen_seed_test.json`, `mlkem_768_encaps_test.json`, `mlkem_768_semi_expanded_decaps_test.json`.

---

## Running Tests

```bash
pytest tests/
```

With statement coverage:
```bash
pytest --cov=pqblocks_csr_pop --cov-report=term-missing tests/
```
