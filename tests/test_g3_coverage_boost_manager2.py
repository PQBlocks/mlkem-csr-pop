"""Coverage boost — targeted tests for remaining Check 3 (correctness) gaps (v4).

All function signatures and APIs verified against actual source.
"""

import pytest
from unittest.mock import MagicMock
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec, mlkem as crypto_mlkem
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import Name, NameAttribute, CertificateBuilder
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import datetime
import os

import pqblocks_csr_pop.policy as POL
import pqblocks_csr_pop.errors as ERR
import pqblocks_csr_pop.csr_builder as CB
import pqblocks_csr_pop.csr_opt as CO
import pqblocks_csr_pop.mlkem as MK
import pqblocks_csr_pop.mlkem_opt as MKO
from pqblocks_csr_pop.policy import _attestor_strength_bits, infer_parameter_set, check_attestor_strength
from pqblocks_csr_pop.errors import PQCSRError, get_error_message


# ── policy.py coverage ──────────────────────────

class TestPolicyAttestorStrength:
    """Cover _attestor_strength_bits branches."""

    def test_rsa_key_size_1024_returns_256(self):
        """Cover size >= 512 branch (line 39)."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        bits = _attestor_strength_bits(key)
        assert bits == 256

    def test_rsa_key_size_mock_384_returns_192(self):
        """Cover size >= 384 branch (line 41)."""
        mock_key = MagicMock(spec=rsa.RSAPrivateKey)
        mock_key.key_size = 384
        bits = _attestor_strength_bits(mock_key)
        assert bits == 192

    def test_rsa_key_size_mock_256_returns_128(self):
        """Cover size >= 256 branch (line 43)."""
        mock_key = MagicMock(spec=rsa.RSAPrivateKey)
        mock_key.key_size = 256
        bits = _attestor_strength_bits(mock_key)
        assert bits == 128

    def test_rsa_key_size_mock_below_256_returns_none(self):
        """Cover branch where size < 256 returns None (line 75)."""
        mock_key = MagicMock(spec=rsa.RSAPrivateKey)
        mock_key.key_size = 128
        bits = _attestor_strength_bits(mock_key)
        assert bits is None

    def test_ed25519_private_key_returns_128(self):
        """Cover Ed25519 private key branch (line 47)."""
        key = ed25519.Ed25519PrivateKey.generate()
        bits = _attestor_strength_bits(key)
        assert bits == 128

    def test_ed25519_public_key_returns_128(self):
        """Cover Ed25519 public key branch (lines 52-53)."""
        key = ed25519.Ed25519PrivateKey.generate()
        pub = key.public_key()
        bits = _attestor_strength_bits(pub)
        assert bits == 128

    def test_ec_secp256r1_returns_128(self):
        """Cover EC secp256r1 branch (line 66)."""
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        bits = _attestor_strength_bits(key)
        assert bits == 128

    def test_ec_secp384r1_returns_192(self):
        """Cover EC secp384r1 branch."""
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        bits = _attestor_strength_bits(key)
        assert bits == 192

    def test_ec_secp521r1_returns_256(self):
        """Cover EC secp521r1 branch."""
        key = ec.generate_private_key(ec.SECP521R1(), default_backend())
        bits = _attestor_strength_bits(key)
        assert bits == 256

    def test_infer_parameter_set_explicit_invalid_raises(self):
        with pytest.raises(ValueError, match="Unknown parameter set"):
            infer_parameter_set(explicit="INVALID")

    def test_infer_parameter_set_env_var(self):
        os.environ["ML_KEM_PARAM"] = "768"
        try:
            result = infer_parameter_set()
            assert result == "ML-KEM-768"
        finally:
            del os.environ["ML_KEM_PARAM"]

    def test_infer_parameter_set_none_ek_none_len(self):
        result = infer_parameter_set(ek=None, ek_len=None)
        assert result is None

    def test_infer_parameter_set_invalid_size_raises(self):
        with pytest.raises(ValueError, match="Invalid key size"):
            infer_parameter_set(ek=b"\x00" * 100)

    def test_check_attestor_strength_weak_key(self):
        """Cover ERR_ATTESTOR_WEAK branch: bits < required."""
        mock_key = MagicMock(spec=rsa.RSAPrivateKey)
        mock_key.key_size = 256  # returns 128 < 256 required for ML-KEM-1024
        result = check_attestor_strength("ML-KEM-1024", mock_key)
        assert result == PQCSRError.ERR_ATTESTOR_WEAK

    def test_check_attestor_strength_strong_key(self):
        """Cover SUCCESS branch."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        result = check_attestor_strength("ML-KEM-768", key)
        assert result == PQCSRError.SUCCESS


# ── errors.py coverage ──────────────────────────

class TestErrorsCoverage:
    """Cover errors.py edge cases."""

    def test_error_message_known_codes(self):
        """Cover ERROR_MESSAGES dict lookup for all known codes."""
        for code in PQCSRError:
            msg = code.message
            assert isinstance(msg, str)
            assert len(msg) > 0

    def test_get_error_message_known(self):
        msg = get_error_message(PQCSRError.SUCCESS)
        assert msg == "Success"

    def test_is_success(self):
        assert ERR.is_success(PQCSRError.SUCCESS) is True
        assert ERR.is_success(PQCSRError.ERR_MISSING_POP) is False

    def test_is_failure(self):
        assert ERR.is_failure(PQCSRError.SUCCESS) is False
        assert ERR.is_failure(PQCSRError.ERR_MISSING_POP) is True

    def test_errors___main__(self):
        """Cover __main__ block in errors.py."""
        import io, sys, os
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            # ERR is the already-imported src.errors module (rewritten to the
            # installed package name by the release harness). Its __file__
            # resolves in both this package tree and the installed-package clean
            # room, unlike a tests/../src/ relative path which only exists
            # in this package tree.
            errors_path = ERR.__file__
            exec(open(errors_path).read())
        finally:
            sys.stdout = old_stdout


# ── csr_builder.py coverage ────────────────────

class TestCsrBuilderCoverage:
    """Cover csr_builder.py edge cases."""

    def test_encode_pi_value_none(self):
        result = CB._encode_pi_value(None)
        assert result == b""

    def test_sign_cri_generates_signature(self):
        """Cover _sign_cri function."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        cert = CertificateBuilder().subject_name(
            Name([NameAttribute(NameOID.COMMON_NAME, "test")])
        ).issuer_name(
            Name([NameAttribute(NameOID.COMMON_NAME, "test")])
        ).public_key(key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        ).sign(key, hashes.SHA256(), default_backend())

        cri_bytes = b"\x30\x00"
        result = CB._sign_cri(cert, [("CN", "test")], cri_bytes)
        assert hasattr(result, "signature")
        assert hasattr(result, "certificate")

    def test_sign_with_ed25519(self):
        """Cover _sign_with_ed25519."""
        key = ed25519.Ed25519PrivateKey.generate()
        data = b"\x00" * 32
        sig = CB._sign_with_ed25519(data, key)
        assert isinstance(sig, bytes)
        assert len(sig) == 64

    def test_get_issuer_record_with_cert(self):
        """Cover _build_issuer_record with real cert."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        cert = CertificateBuilder().subject_name(
            Name([NameAttribute(NameOID.COMMON_NAME, "test-cn"), NameAttribute(NameOID.ORGANIZATION_NAME, "test-org")])
        ).issuer_name(
            Name([NameAttribute(NameOID.COMMON_NAME, "issuer-cn"), NameAttribute(NameOID.ORGANIZATION_NAME, "issuer-org")])
        ).public_key(key.public_key()).serial_number(42).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        ).sign(key, hashes.SHA256(), default_backend())

        result = CB._build_issuer_record(cert, True)
        assert result["subject"] == "test-cn"
        assert result["org"] == "test-org"
        assert result["issuer_der_bytes"] is not None

    def test_get_issuer_record_no_cert(self):
        """Cover _build_issuer_record with issuer=None."""
        result = CB._build_issuer_record(None, False)
        assert result["issuer_der_bytes"] is None
        assert result["subject"] is None
        assert result["org"] is None

    def test_build_subject_records(self):
        """Cover _build_subject_records."""
        result = CB._build_subject_records([("CN", "test"), ("O", "org")])
        assert isinstance(result, list)
        assert len(result) > 0


# ── csr_opt.py coverage ────────────────────────

class TestCsrOptCoverage:
    """Cover csr_opt.py edge cases."""

    def test_der_encode_integer_zero(self):
        result = CO._der_encode_integer(0)
        assert result == bytes([0x02, 0x01, 0x00])

    def test_der_encode_integer_positive(self):
        result = CO._der_encode_integer(255)
        assert result[0] == 0x02

    def test_der_encode_integer_negative(self):
        result = CO._der_encode_integer(-1)
        assert result[0] == 0x02

    def test_encode_pi_value_none(self):
        result = CO._encode_pi_value(None)
        assert result == b""

    def test_get_expected_ek_size(self):
        size = CO._get_expected_ek_size("ML-KEM-768")
        assert size == 1184

    def test_get_expected_ek_size_1024(self):
        size = CO._get_expected_ek_size("ML-KEM-1024")
        assert size == 1568

    def test_get_mlkem_public_key_class(self):
        cls = CO._get_mlkem_public_key_class("ML-KEM-768")
        assert cls is not None

    def test_build_csr_with_pop_valid(self):
        """Cover build_csr_with_pop with valid inputs."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        priv_key = ed25519.Ed25519PrivateKey.generate()
        cert = CertificateBuilder().subject_name(
            Name([NameAttribute(NameOID.COMMON_NAME, "test")])
        ).issuer_name(
            Name([NameAttribute(NameOID.COMMON_NAME, "test")])
        ).public_key(priv_key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        ).sign(priv_key, algorithm=None)

        result = CO.build_csr_with_pop(
            mlkem_public_key_bytes=ek,
            parameter_set="ML-KEM-768",
            subject_name=Name([NameAttribute(NameOID.COMMON_NAME, "test")]),
            attestor_private_key=priv_key,
            attestor_certificate=cert
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_build_csr_with_pop_invalid_param(self):
        """Cover build_csr_with_pop with invalid parameter set."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        priv_key = ed25519.Ed25519PrivateKey.generate()
        cert = CertificateBuilder().subject_name(
            Name([NameAttribute(NameOID.COMMON_NAME, "test")])
        ).issuer_name(
            Name([NameAttribute(NameOID.COMMON_NAME, "test")])
        ).public_key(priv_key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        ).sign(priv_key, algorithm=None)

        with pytest.raises(ValueError, match="Invalid parameter set"):
            CO.build_csr_with_pop(
                mlkem_public_key_bytes=ek,
                parameter_set="INVALID",
                subject_name=Name([NameAttribute(NameOID.COMMON_NAME, "test")]),
                attestor_private_key=priv_key,
                attestor_certificate=cert
            )

    def test_build_csr_with_pop_invalid_key_size(self):
        """Cover build_csr_with_pop with invalid key size."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        priv_key = ed25519.Ed25519PrivateKey.generate()
        cert = CertificateBuilder().subject_name(
            Name([NameAttribute(NameOID.COMMON_NAME, "test")])
        ).issuer_name(
            Name([NameAttribute(NameOID.COMMON_NAME, "test")])
        ).public_key(priv_key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        ).sign(priv_key, algorithm=None)

        with pytest.raises(ValueError, match="ML-KEM public key must be 1568 bytes"):
            CO.build_csr_with_pop(
                mlkem_public_key_bytes=b"\x00" * 100,
                parameter_set="ML-KEM-1024",
                subject_name=Name([NameAttribute(NameOID.COMMON_NAME, "test")]),
                attestor_private_key=priv_key,
                attestor_certificate=cert
            )

    def test_build_csr_with_pop_none_attestor_cert(self):
        """Cover build_csr_with_pop with attestor_certificate=None."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        priv_key = ed25519.Ed25519PrivateKey.generate()
        result = CO.build_csr_with_pop(
            mlkem_public_key_bytes=ek,
            parameter_set="ML-KEM-768",
            subject_name=Name([NameAttribute(NameOID.COMMON_NAME, "test")]),
            attestor_private_key=priv_key,
            attestor_certificate=None
        )
        assert result is None

    def test_parse_csr_bad_tag(self):
        """Cover parse_csr with bad tag."""
        with pytest.raises(ValueError):
            CO.parse_csr(b"\x01\x00")

    def test_verify_csr_signature_with_none(self):
        """Cover verify_csr_signature with attestor_certificate=None."""
        result = CO.verify_csr_signature(b"\x00", attestor_certificate=None)
        assert isinstance(result, bool)

    def test_verify_csr_signature_with_ed25519(self):
        """Cover verify_csr_signature with Ed25519 key."""
        key = ed25519.Ed25519PrivateKey.generate()
        pub = key.public_key()
        class MockCert:
            def public_key(self):
                return pub
        result = CO.verify_csr_signature(b"\x00", attestor_certificate=MockCert())
        assert result is False

    def test_verify_csr_signature_with_ec(self):
        """Cover verify_csr_signature with EC key."""
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pub = key.public_key()
        class MockCert:
            def public_key(self):
                return pub
        result = CO.verify_csr_signature(b"\x00", attestor_certificate=MockCert())
        assert result is False

    def test_encode_private_key_possession_statement(self):
        """Cover _encode_private_key_possession_statement."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        cert = CertificateBuilder().subject_name(
            Name([NameAttribute(NameOID.COMMON_NAME, "test")])
        ).issuer_name(
            Name([NameAttribute(NameOID.COMMON_NAME, "test")])
        ).public_key(key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        ).sign(key, hashes.SHA256(), default_backend())
        result = CO._encode_private_key_possession_statement(
            cert.issuer, cert.serial_number, cert
        )
        assert isinstance(result, bytes)

    def test_build_subject_public_key_info(self):
        """Cover _build_subject_public_key_info."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        result = CO._build_subject_public_key_info(ek, "ML-KEM-768")
        assert isinstance(result, bytes)


# ── mlkem.py coverage ──────────────────────────

class TestMlkemCoverage:
    """Cover mlkem.py edge cases."""

    def test_mlkem_keygen_valid_seed(self):
        """Cover mlkem_keygen with valid seed."""
        seed = b"\x00" * 64
        ek, dk = MK.mlkem_keygen(parameter_set="ML-KEM-768", seed=seed)
        assert ek is not None
        assert dk is not None
        assert len(ek) == 1184

    def test_mlkem_keygen_no_seed(self):
        """Cover mlkem_keygen with random seed."""
        ek, dk = MK.mlkem_keygen(parameter_set="ML-KEM-768")
        assert ek is not None
        assert dk is not None

    def test_mlkem_keygen_1024(self):
        """Cover mlkem_keygen with ML-KEM-1024."""
        seed = b"\x00" * 64
        ek, dk = MK.mlkem_keygen(parameter_set="ML-KEM-1024", seed=seed)
        assert ek is not None
        assert len(ek) == 1568

    def test_mlkem_keygen_wrong_seed_size(self):
        """Cover mlkem_keygen with wrong seed size."""
        with pytest.raises(ValueError):
            MK.mlkem_keygen(parameter_set="ML-KEM-768", seed=b"\x00" * 32)

    def test_mlkem_keygen_wrong_seed_size_1024(self):
        """Cover mlkem_keygen with wrong seed size for 1024."""
        with pytest.raises(ValueError):
            MK.mlkem_keygen(parameter_set="ML-KEM-1024", seed=b"\x00" * 32)

    def test_mlkem_encapsulate(self):
        """Cover mlkem_encapsulate."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        ss, ct = MK.mlkem_encapsulate(ek, "ML-KEM-768")
        assert ss is not None
        assert ct is not None

    def test_mlkem_decapsulate(self):
        """Cover mlkem_decapsulate."""
        ek, dk = MK.mlkem_keygen("ML-KEM-768")
        ss, ct = MK.mlkem_encapsulate(ek, "ML-KEM-768")
        result = MK.mlkem_decapsulate(dk, ct, "ML-KEM-768")
        assert result == ss

    def test_get_key_sizes(self):
        """Cover get_key_sizes."""
        sizes = MKO.get_key_sizes("ML-KEM-768")
        assert sizes is not None

    def test_get_actual_key_sizes(self):
        """Cover get_actual_key_sizes."""
        sizes = MKO.get_actual_key_sizes("ML-KEM-768")
        assert sizes is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src", "--cov-report=term-missing", "--cov-fail-under=0"])
