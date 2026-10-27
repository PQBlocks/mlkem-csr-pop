"""Demonstrate ML-KEM-1024 PKCS#10 CSR generation with RFC 9883 Proof-of-Possession."""
import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from pqblocks_csr_pop.csr_builder import build_csr_with_pop, parse_csr, verify_csr_signature
from pqblocks_csr_pop.mlkem import mlkem_keygen

def main():
    print("1. Generating Attestor Identity (Ed25519 CA)...")
    attestor_key = ed25519.Ed25519PrivateKey.generate()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Corporate PQC Sub-CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    attestor_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(attestor_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(attestor_key, None)
    )
    print("   Attestor certificate created.")

    print("\n2. Generating ML-KEM-1024 Keypair (FIPS 203 Level 5 Security)...")
    ek, dk = mlkem_keygen("ML-KEM-1024")
    print(f"   Encapsulation Key (Public): {len(ek)} bytes (expected 1568)")
    print(f"   Decapsulation Key (Private): {len(dk)} bytes")
    assert len(ek) == 1568

    print("\n3. Constructing PKCS#10 CSR with RFC 9883 Statement of Possession...")
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PQBlocks Enterprise"),
        x509.NameAttribute(NameOID.COMMON_NAME, "quantum-safe.internal.net"),
    ])
    csr_der = build_csr_with_pop(ek, "ML-KEM-1024", subject, attestor_key, attestor_cert)
    print(f"   CSR DER size: {len(csr_der)} bytes")

    print("\n4. Parsing and Verifying CSR Proof-of-Possession...")
    parsed = parse_csr(csr_der)
    print(f"   Parsed Subject: {parsed.subject.rfc4514_string()}")
    valid = verify_csr_signature(csr_der, attestor_cert)
    print(f"   Signature Verification: {valid}")
    assert valid, "CSR Signature verification failed!"

    print("\nML-KEM-1024 CSR with PoP verified successfully.")

if __name__ == "__main__":
    main()
