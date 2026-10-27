"""Tests for S.6 parameter policy and subject-name matching (spec Section 2)."""
import datetime
import os

import pytest
from hypothesis import given, strategies as st
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519, ec

from pqblocks_csr_pop.policy import (
    infer_parameter_set,
    check_attestor_strength,
    check_subject_match,
    validate_csr_inputs,
)
from pqblocks_csr_pop.errors import PQCSRError


def _make_cert(cn="Test CA"):
    sk = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(sk.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(sk, None)
    )
    return cert, sk


def _p256_key():
    return ec.generate_private_key(ec.SECP256R1())


def _p384_key():
    return ec.generate_private_key(ec.SECP384R1())


def _p521_key():
    return ec.generate_private_key(ec.SECP521R1())


class TestInferParameterSet:
    def test_sizes_map(self):
        assert infer_parameter_set(ek_len=800) == "ML-KEM-512"
        assert infer_parameter_set(ek_len=1184) == "ML-KEM-768"
        assert infer_parameter_set(ek_len=1568) == "ML-KEM-1024"

    def test_bytes_input(self):
        assert infer_parameter_set(ek=b"x" * 800) == "ML-KEM-512"
        assert infer_parameter_set(ek=b"x" * 1184) == "ML-KEM-768"
        assert infer_parameter_set(ek=b"x" * 1568) == "ML-KEM-1024"

    def test_invalid_size_raises(self):
        with pytest.raises(ValueError):
            infer_parameter_set(ek_len=100)

    def test_explicit_override(self):
        assert infer_parameter_set(ek_len=100, explicit="ML-KEM-768") == "ML-KEM-768"

    @given(st.sampled_from([800, 1184, 1568]))
    def test_property_sizes_always_resolve(self, n):
        assert infer_parameter_set(ek=b"x" * n) in (
            "ML-KEM-512",
            "ML-KEM-768",
            "ML-KEM-1024",
        )

    @given(st.integers(min_value=0, max_value=2000))
    def test_property_invalid_sizes_raise_unless_known(self, n):
        if n in (800, 1184, 1568):
            infer_parameter_set(ek_len=n)
        else:
            with pytest.raises(ValueError):
                infer_parameter_set(ek_len=n)


class TestAttestorStrength:
    def test_ed25519_ok_for_512(self):
        assert (
            check_attestor_strength("ML-KEM-512", ed25519.Ed25519PrivateKey.generate())
            == PQCSRError.SUCCESS
        )

    def test_ed25519_weak_for_768(self):
        assert (
            check_attestor_strength("ML-KEM-768", ed25519.Ed25519PrivateKey.generate())
            == PQCSRError.ERR_ATTESTOR_WEAK
        )

    def test_ed25519_weak_for_1024(self):
        assert (
            check_attestor_strength("ML-KEM-1024", ed25519.Ed25519PrivateKey.generate())
            == PQCSRError.ERR_ATTESTOR_WEAK
        )

    def test_p384_ok_for_768(self):
        assert check_attestor_strength("ML-KEM-768", _p384_key()) == PQCSRError.SUCCESS

    def test_p521_ok_for_1024(self):
        assert check_attestor_strength("ML-KEM-1024", _p521_key()) == PQCSRError.SUCCESS

    def test_p256_weak_for_1024(self):
        assert (
            check_attestor_strength("ML-KEM-1024", _p256_key())
            == PQCSRError.ERR_ATTESTOR_WEAK
        )


class TestSubjectMatch:
    def test_exact_match(self):
        cert, _ = _make_cert("Test CA")
        csr = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        assert check_subject_match(csr, cert, "exact") == PQCSRError.SUCCESS

    def test_exact_mismatch(self):
        cert, _ = _make_cert("Test CA")
        csr = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other.example")])
        assert (
            check_subject_match(csr, cert, "exact") == PQCSRError.ERR_SUBJECT_MISMATCH
        )

    def test_ignore_policy(self):
        cert, _ = _make_cert("Test CA")
        csr = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other.example")])
        assert check_subject_match(csr, cert, "ignore") == PQCSRError.SUCCESS

    def test_empty_subject(self):
        cert, _ = _make_cert("Test CA")
        assert check_subject_match("", cert, "exact") == PQCSRError.ERR_EMPTY_SUBJECT

    def test_env_policy_ignore(self):
        os.environ["SUBJECT_MATCH_POLICY"] = "ignore"
        try:
            cert, _ = _make_cert("Test CA")
            csr = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])
            assert check_subject_match(csr, cert) == PQCSRError.SUCCESS
        finally:
            del os.environ["SUBJECT_MATCH_POLICY"]


class TestValidateInputs:
    def test_missing_cert(self):
        code = validate_csr_inputs(b"x" * 1568, "CN=a", None)
        assert code == PQCSRError.ERR_MISSING_ATTESTOR_CERT

    def test_empty_subject(self):
        cert, _ = _make_cert()
        assert validate_csr_inputs(b"x" * 1568, "", cert) == PQCSRError.ERR_EMPTY_SUBJECT

    def test_bad_key_size(self):
        cert, _ = _make_cert()
        assert (
            validate_csr_inputs(b"x" * 100, cert.subject, cert)
            == PQCSRError.ERR_INVALID_KEY_SIZE
        )

    def test_weak_attestor(self):
        cert, sk = _make_cert()
        csr = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        code = validate_csr_inputs(
            b"x" * 1568, csr, cert, attestor_key=sk, subject_policy="ignore"
        )
        assert code == PQCSRError.ERR_ATTESTOR_WEAK

    def test_success_path(self):
        _, sk = _make_cert()
        cert521_sk = _p521_key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert521 = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(cert521_sk.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(cert521_sk, __import__("cryptography").hazmat.primitives.hashes.SHA384())
        )
        _ = sk
        code = validate_csr_inputs(
            b"x" * 1568, name, cert521, attestor_key=cert521_sk
        )
        assert code == PQCSRError.SUCCESS


class TestInferEnvTieBreaker:
    """ML_KEM_PARAM env is the spec Section 2 tie-breaker (S.6)."""

    def _with_env(self, value):
        import contextlib

        @contextlib.contextmanager
        def _cm():
            old = os.environ.get("ML_KEM_PARAM")
            if value is None:
                os.environ.pop("ML_KEM_PARAM", None)
            else:
                os.environ["ML_KEM_PARAM"] = value
            try:
                yield
            finally:
                if old is None:
                    os.environ.pop("ML_KEM_PARAM", None)
                else:
                    os.environ["ML_KEM_PARAM"] = old

        return _cm()

    def test_env_resolves_unknown_size(self):
        with self._with_env("768"):
            assert infer_parameter_set(ek_len=100) == "ML-KEM-768"

    def test_env_overrides_known_size_on_conflict(self):
        # Spec: conflicting inputs -> ML_KEM_PARAM wins over size inference.
        with self._with_env("1024"):
            assert infer_parameter_set(ek_len=800) == "ML-KEM-1024"

    def test_no_env_keeps_size_inference(self):
        with self._with_env(None):
            assert infer_parameter_set(ek_len=800) == "ML-KEM-512"

    def test_invalid_explicit_raises(self):
        with pytest.raises(ValueError):
            infer_parameter_set(ek_len=800, explicit="ML-KEM-999")

    def test_explicit_arg_beats_env(self):
        with self._with_env("1024"):
            assert (
                infer_parameter_set(ek_len=800, explicit="ML-KEM-768")
                == "ML-KEM-768"
            )


class TestAttestorStrengthExtra:
    def test_cert_input_ed25519(self):
        cert, _ = _make_cert()
        assert (
            check_attestor_strength("ML-KEM-512", cert) == PQCSRError.SUCCESS
        )

    def test_unknown_key_type_is_weak(self):
        assert (
            check_attestor_strength("ML-KEM-512", object())
            == PQCSRError.ERR_ATTESTOR_WEAK
        )

    def test_rsa_key_size_fallback(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # Fallback maps key_size >= 512 -> 256 bits, so OK for ML-KEM-1024.
        assert (
            check_attestor_strength("ML-KEM-1024", key) == PQCSRError.SUCCESS
        )


class TestSubjectMatchExtra:
    def test_policy_defined_accepts_mismatch(self):
        cert, _ = _make_cert("Test CA")
        csr = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other")])
        assert (
            check_subject_match(csr, cert, "policy-defined")
            == PQCSRError.SUCCESS
        )

    def test_policy_defined_empty_cert_side(self):
        csr = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])
        assert (
            check_subject_match(csr, "", "policy-defined")
            == PQCSRError.ERR_MISSING_ATTESTOR_CERT
        )


class TestValidateExtra:
    def test_validate_subject_mismatch(self):
        cert, _ = _make_cert("Test CA")
        csr = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other")])
        code = validate_csr_inputs(
            b"x" * 800, csr, cert, attestor_key=None, subject_policy="exact"
        )
        assert code == PQCSRError.ERR_SUBJECT_MISMATCH

    def test_validate_env_tiebreaker_avoids_key_size_error(self):
        cert, _ = _make_cert("Test CA")
        old = os.environ.get("ML_KEM_PARAM")
        os.environ["ML_KEM_PARAM"] = "512"
        try:
            code = validate_csr_inputs(
                b"x" * 100, cert.subject, cert, subject_policy="exact"
            )
        finally:
            if old is None:
                os.environ.pop("ML_KEM_PARAM", None)
            else:
                os.environ["ML_KEM_PARAM"] = old
        # 100-byte key resolves via env tie-breaker; subject matches so no
        # ERR_INVALID_KEY_SIZE (attestor key not supplied -> strength skipped).
        assert code == PQCSRError.SUCCESS


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
