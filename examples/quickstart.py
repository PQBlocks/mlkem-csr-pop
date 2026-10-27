"""Minimal end-to-end demo: ML-KEM-768 keygen -> RFC 9883 CSR -> verify.

Run with:
    python3 examples/quickstart.py
Deterministic: fixed Ed25519 and ML-KEM seeds, so output is stable.
"""
import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from pqblocks_csr_pop.csr_builder import build_csr_with_pop, parse_csr, verify_csr_signature
from pqblocks_csr_pop.mlkem import mlkem_keygen


def main() -> None:
    attestor_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Attestor")])
    now = datetime.datetime.now(datetime.timezone.utc)
    attestor_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(attestor_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(attestor_key, None)
    )
    ek, dk = mlkem_keygen("ML-KEM-768", bytes(range(64)))
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "CN=test.example.com")]
    )
    csr_der = build_csr_with_pop(ek, "ML-KEM-768", subject, attestor_key, attestor_cert)
    parsed = parse_csr(csr_der)
    ok = verify_csr_signature(csr_der, attestor_cert)
    print(f"ek={len(ek)} bytes, dk={len(dk)} bytes (seed)")
    print(f"csr={len(csr_der)} bytes DER, subject={parsed.subject.rfc4514_string()}")
    print(f"signature-valid={ok}")
    assert len(ek) == 1184 and ok


if __name__ == "__main__":
    main()
