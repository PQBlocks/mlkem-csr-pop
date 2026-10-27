# Use Cases & Integration Patterns: pqblocks-csr-pop

This document describes primary integration architectures and practical patterns for `pqblocks-csr-pop`.

---

## 1. Enterprise Post-Quantum PKI Enrollment

### Challenge
Enterprises issuing quantum-safe TLS certificates cannot use traditional self-signed CSRs with ML-KEM keys because KEMs cannot sign payloads. The CA must verify that the requesting entity actually controls the private decapsulation key.

### Solution
Use `build_csr_with_pop()` to construct an RFC 9883-compliant CSR. The client's existing device key (e.g. Ed25519 or ECDSA) signs the Certification Request Information (CRI) containing the `statementOfPossession` attribute.

```python
from pqblocks_csr_pop.csr_builder import build_csr_with_pop
from pqblocks_csr_pop.mlkem import mlkem_keygen

# 1. Device generates its ML-KEM-768 keypair
ek, dk = mlkem_keygen("ML-KEM-768")

# 2. Device creates CSR signed by its hardware/device identity key
csr_der = build_csr_with_pop(
    encapsulation_key=ek,
    parameter_set="ML-KEM-768",
    subject=subject,
    attestor_key=device_key,
    attestor_cert=device_cert,
)

# 3. Transmit csr_der to CA via ACME or SCEP
submit_to_ca(csr_der)
```

---

## 2. Certificate Authority (CA) Automated Validation

### Challenge
Public and internal CAs must inspect incoming PKCS#10 requests to confirm they adhere to RFC 9883 and that the PoP signature matches the included attestor certificate.

### Solution
Use `parse_csr()` and `verify_csr_signature()` to validate the request in under 0.2 milliseconds before issuing the x509 certificate:

```python
from pqblocks_csr_pop.csr_builder import parse_csr, verify_csr_signature

def handle_csr_submission(csr_der_bytes: bytes, trusted_ca_roots):
    parsed = parse_csr(csr_der_bytes)
    attestor_cert = extract_attestor_cert(parsed)
    
    # 1. Verify attestor cert chains to trusted root
    validate_chain(attestor_cert, trusted_ca_roots)
    
    # 2. Verify PoP signature over the ML-KEM public key
    if not verify_csr_signature(csr_der_bytes, attestor_cert):
        raise SecurityViolation("Invalid Proof of Possession signature!")
        
    # 3. Issue post-quantum leaf certificate
    return issue_certificate(parsed)
```
