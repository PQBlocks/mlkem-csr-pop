# AI & Automation Guide: pqblocks-csr-pop

This guide provides operational patterns and constraints for AI agents interacting with or generating code using `pqblocks-csr-pop`.

---

## Package Overview & Imports

```python
from pqblocks_csr_pop.csr_builder import (
    build_csr_with_pop,
    parse_csr,
    verify_csr_signature,
)
from pqblocks_csr_pop.mlkem import mlkem_keygen, mlkem_encapsulate, mlkem_decapsulate
from pqblocks_csr_pop.errors import PQCSRError
```

---

## Safe Coding Patterns

### 1. Generating ML-KEM Keys
Always pass explicit parameter sets (`"ML-KEM-768"` or `"ML-KEM-1024"`):
```python
ek, dk = mlkem_keygen("ML-KEM-768")
# len(ek) == 1184 bytes (ML-KEM-768 public key)
# len(dk) == 64 bytes (seed for reconstruction)
```

### 2. Building CSR with PoP
Ensure `attestor_key` is a signing private key (e.g. Ed25519) and `attestor_cert` is its corresponding x509 Certificate:
```python
csr_der = build_csr_with_pop(
    encapsulation_key=ek,
    parameter_set="ML-KEM-768",
    subject=subject,
    attestor_key=attestor_key,
    attestor_cert=attestor_cert,
)
```

### 3. Validating CSRs
Always verify signatures using the attestor's certificate:
```python
is_valid = verify_csr_signature(csr_der, attestor_cert)
assert is_valid
```

---

## Prohibited Patterns

1. **Do NOT Attempt Self-Signing with ML-KEM**: ML-KEM is a KEM, not a signature scheme. Never attempt to pass an ML-KEM private key as the `attestor_key`.
2. **Do NOT Truncate or Pad Keys**: Passing public keys of incorrect length (e.g., != 1184 for ML-KEM-768 or != 1568 for ML-KEM-1024) raises `ValueError`.
