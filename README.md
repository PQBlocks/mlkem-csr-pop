# pqblocks-csr-pop

> ML-KEM (FIPS 203) PKCS#10 Certificate Signing Request (CSR) generator with RFC 9883 Proof of Possession (PoP).

[![CI](https://github.com/PQBlocks/mlkem-csr-pop/actions/workflows/ci.yml/badge.svg)](https://github.com/PQBlocks/mlkem-csr-pop/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## Overview

`pqblocks-csr-pop` is a specialized post-quantum PKI library for generating and validating **PKCS#10 Certification Requests (CSRs)** carrying **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism, FIPS 203) public keys.

Because KEM keys cannot sign their own CSRs (unlike RSA, ECDSA, or ML-DSA), standards such as **RFC 9883** require an explicit Proof of Possession (PoP) structure. `pqblocks-csr-pop` constructs and verifies DER-encoded PKCS#10 requests carrying the `statementOfPossession` attribute attested by an Ed25519 or classical key.

### Standards Alignment

- **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM-768, ML-KEM-1024).
- **RFC 9883**: Use of the Proof of Possession (PoP) Attribute in PKCS#10 Certification Requests.
- **RFC 2986 / PKCS#10**: Certification Request Syntax Specification Version 1.7.
- **RFC 5280**: X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile.

> [!WARNING]
> **Non-FIPS Notice**: This library is an independent open-source implementation. It is not certified under FIPS 140-3 and has not undergone CMVP validation.

---

## Installation

```bash
pip install pqblocks-csr-pop
```

### Dependencies

Requires Python 3.11+ and `cryptography>=50.0.0` (with built-in ML-KEM support). No C compilation or external system libraries required.

---

## Quickstart

```python
import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from pqblocks_csr_pop.csr_builder import build_csr_with_pop, parse_csr, verify_csr_signature
from pqblocks_csr_pop.mlkem import mlkem_keygen

# 1. Attestor Identity (e.g. Host/Device Ed25519 key)
attestor_key = ed25519.Ed25519PrivateKey.generate()
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Device Attestor")])
now = datetime.datetime.now(datetime.timezone.utc)
attestor_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name).issuer_name(ca_name)
    .public_key(attestor_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=365))
    .sign(attestor_key, None)
)

# 2. Generate ML-KEM Keypair (FIPS 203 ML-KEM-768)
ek, dk = mlkem_keygen("ML-KEM-768")

# 3. Construct PKCS#10 CSR with RFC 9883 PoP Extension
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pqc-server.internal.net")])
csr_der = build_csr_with_pop(ek, "ML-KEM-768", subject, attestor_key, attestor_cert)

# 4. CA parses CSR and verifies PoP signature
parsed = parse_csr(csr_der)
valid = verify_csr_signature(csr_der, attestor_cert)
assert valid
print(f"CSR verified successfully: {len(csr_der)} bytes DER")
```

---

## Performance Summary

Measured on Linux x86_64 across 500 timed runs per operation:

| Operation | Parameter Set | Mean Latency | Median Latency | Throughput |
|---|---|---|---|---|
| Key Generation | ML-KEM-768 | 0.306 ms | 0.298 ms | ~3,260 ops/sec |
| Key Generation | ML-KEM-1024 | 0.370 ms | 0.386 ms | ~2,700 ops/sec |
| Build CSR with PoP | ML-KEM-768 | 0.083 ms | 0.071 ms | ~12,120 ops/sec |
| Build CSR with PoP | ML-KEM-1024 | 0.089 ms | 0.075 ms | ~11,300 ops/sec |
| Parse CSR | RFC 9883 Structure | 0.024 ms | 0.027 ms | ~41,130 ops/sec |
| Verify Signature | Ed25519 Attestor | 0.174 ms | 0.147 ms | ~5,730 ops/sec |

For complete benchmark methodology, see [BENCHMARKS.md](BENCHMARKS.md).

---

## Security & Verification

- **KAT Corpora**: Tested against official NIST ACVP ML-KEM vectors and Google Wycheproof test vectors (`mlkem_768_test`, `mlkem_768_keygen_seed_test`, `mlkem_768_encaps_test`).
- **Comprehensive Test Suite**: 438 automated unit, property, and golden verification tests passing across Python 3.11–3.14.
- **Cryptographic Backend**: Relies on OpenSSL 3.0+ backend via `cryptography`.

For details, see [SECURITY_NOTES.md](SECURITY_NOTES.md) and [TESTING.md](TESTING.md).

---

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
