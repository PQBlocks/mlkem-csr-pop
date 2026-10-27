"""Check 3 (correctness) Golden Verification test suite — Part 1: Golden instance creation."""

import pytest, json, datetime, os
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519

from pqblocks_csr_pop.mlkem import mlkem_keygen
from pqblocks_csr_pop.csr_builder import build_csr_with_pop, verify_csr_signature

GOLDEN = Path(__file__).parent / "fixtures" / "golden" if (Path(__file__).parent / "fixtures" / "golden").exists() else Path(__file__).parent.parent / "verification" / "golden"


def _attestor_cn(cn="Test CA"):
    sk = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(sk.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(sk, None)
    )
    return cert, sk


class TestGoldenCreation:
    def test_golden_dir_has_files(self):
        assert GOLDEN.is_dir()
        files = list(GOLDEN.glob("golden_*.json"))
        assert len(files) >= 1

    def _write(self, name, payload):
        (GOLDEN / name).write_text(json.dumps(payload, indent=2))

    def test_golden_mlkem768_keygen(self):
        seed = bytes.fromhex("00" * 64)
        ek, dk = mlkem_keygen("ML-KEM-768", seed)
        self._write("golden_mlkem768_keygen.json", {
            "parameter_set": "ML-KEM-768",
            "seed_hex": seed.hex(),
            "ek_hex": ek.hex(), "dk_hex": dk.hex(),
            "ek_size": len(ek), "dk_size": len(dk),
        })
        assert len(ek) == 1184 and len(dk) == 64

    def test_golden_mlkem1024_keygen(self):
        seed = bytes.fromhex("00" * 64)
        ek, dk = mlkem_keygen("ML-KEM-1024", seed)
        self._write("golden_mlkem1024_keygen.json", {
            "parameter_set": "ML-KEM-1024",
            "seed_hex": seed.hex(),
            "ek_hex": ek.hex(), "dk_hex": dk.hex(),
            "ek_size": len(ek), "dk_size": len(dk),
        })
        assert len(ek) == 1568 and len(dk) == 64

    def test_golden_csr_mlkem768(self):
        seed = bytes.fromhex("42" * 64)
        ek, _ = mlkem_keygen("ML-KEM-768", seed)
        cert, sk = _attestor_cn("Attestor CA")
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        der = build_csr_with_pop(ek, "ML-KEM-768", subj, sk, cert)
        self._write("golden_csr_mlkem768.json", {
            "parameter_set": "ML-KEM-768",
            "seed_hex": seed.hex(),
            "csr_der_hex": der.hex(), "csr_der_len": len(der),
        })
        assert len(der) > 0

    def test_golden_csr_mlkem1024(self):
        seed = bytes.fromhex("AB" * 64)
        ek, _ = mlkem_keygen("ML-KEM-1024", seed)
        cert, sk = _attestor_cn("Attestor CA 2")
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cross.example.org")])
        der = build_csr_with_pop(ek, "ML-KEM-1024", subj, sk, cert)
        self._write("golden_csr_mlkem1024.json", {
            "parameter_set": "ML-KEM-1024",
            "seed_hex": seed.hex(),
            "csr_der_hex": der.hex(), "csr_der_len": len(der),
        })
        assert len(der) > 0

    def test_golden_csr_verify(self):
        seed = bytes.fromhex("DE" * 64)
        ek, _ = mlkem_keygen("ML-KEM-768", seed)
        cert, sk = _attestor_cn("Verify CA")
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "verify.example")])
        der = build_csr_with_pop(ek, "ML-KEM-768", subj, sk, cert)
        assert verify_csr_signature(der, cert) is True
        self._write("golden_verify.json", {
            "parameter_set": "ML-KEM-768",
            "csr_der_hex": der.hex(),
            "verify": "PASS",
        })
