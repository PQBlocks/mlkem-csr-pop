# Security Notes: pqblocks-csr-pop

This document describes the security posture, assumptions, and architectural properties of `pqblocks-csr-pop`.

---

## 1. Cryptographic Primitive Delegation

`pqblocks-csr-pop` delegates all raw cryptographic operations to maintained, audited libraries:
- **ML-KEM Operations**: Performed via `cryptography.hazmat.primitives.asymmetric.mlkem`, backed by OpenSSL 3.0+.
- **Signature & Attestation**: Ed25519 and ECDSA signatures are generated and verified via `cryptography`.

No custom mathematical lattice implementations or hand-rolled ASN.1 parsers are present in this layer.

---

## 2. Proof of Possession (PoP) Architecture (RFC 9883)

1. **Dual-Key Model**: Because KEMs do not have a signing operation, a CSR cannot be self-signed with the KEM key.
2. **Attestation Structure**: The requester provides:
   - The ML-KEM public key inside `SubjectPublicKeyInfo`.
   - An included `statementOfPossession` attribute.
   - A digital signature from an attesting identity key (e.g. Ed25519).
3. **CA Trust Verification**: The CA must verify both the cryptographic signature on the CSR and that the attestor key is authorized to request certificates for the subject.

---

## 3. Input Validation & ASN.1 Parsing

- **Strict Key Sizing**: Validates that ML-KEM-768 public keys are exactly 1184 bytes and ML-KEM-1024 keys are exactly 1568 bytes. Rejects malformed lengths loudly before ASN.1 encoding.
- **Tamper Resistance**: Any alteration of the subject, OID, or key material invalidates the outer DER signature.

---

## 4. Non-FIPS Validation Notice

> [!IMPORTANT]
> `pqblocks-csr-pop` has not been submitted to the NIST CMVP program and is not certified under FIPS 140-3. It is intended for post-quantum PKI deployment testing, research, and non-FIPS cryptographic agility.
