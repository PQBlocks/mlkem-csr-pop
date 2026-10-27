"""Tests for CSR builder and optimized CSR builder coverage."""
import datetime

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import NameAttribute, Name
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mlkem

from pqblocks_csr_pop.mlkem import mlkem_keygen, _get_public_key_class, get_key_sizes, get_actual_key_sizes
from pqblocks_csr_pop.mlkem_opt import mlkem_keygen as opt_keygen
from pqblocks_csr_pop.csr_builder import build_csr_with_pop, parse_csr, verify_csr_signature
from pqblocks_csr_pop.csr_opt import build_csr_with_pop as opt_build_csr_with_pop, parse_csr as opt_parse_csr, verify_csr_signature as opt_verify_csr_signature
from pqblocks_csr_pop.cri import build_private_key_possession_statement, CRIBuilder, MLKEMParameterSet, OIDs, build_cri
from pqblocks_csr_pop.errors import PQCSRError, get_error_message, is_success, is_failure


class TestCSRBuilder:
    """Tests for csr_builder.py functions."""

    def test_build_csr_with_pop(self):
        """Test building a CSR with PoP attribute."""
        ek, dk = mlkem_keygen("ML-KEM-1024")
        cert, attestor_key = _make_cert()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        
        csr_der = build_csr_with_pop(ek, "ML-KEM-1024", subject, attestor_key, cert)
        assert isinstance(csr_der, bytes)
        assert len(csr_der) > 0

    def test_build_csr_with_pop_wrong_key_size(self):
        """Test that wrong key size raises ValueError."""
        wrong_key = b"x" * 100
        cert, attestor_key = _make_cert()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        
        with pytest.raises(ValueError, match="ML-KEM public key must be"):
            build_csr_with_pop(wrong_key, "ML-KEM-1024", subject, attestor_key, cert)

    def test_parse_csr(self):
        """Test parsing a CSR."""
        ek, dk = mlkem_keygen("ML-KEM-1024")
        cert, attestor_key = _make_cert()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        
        csr_der = build_csr_with_pop(ek, "ML-KEM-1024", subject, attestor_key, cert)
        parsed = parse_csr(csr_der)
        assert parsed is not None
        assert hasattr(parsed, 'subject')

    def test_verify_csr_signature_valid(self):
        """Test verifying a valid CSR signature."""
        ek, dk = mlkem_keygen("ML-KEM-1024")
        cert, attestor_key = _make_cert()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        
        csr_der = build_csr_with_pop(ek, "ML-KEM-1024", subject, attestor_key, cert)
        result = verify_csr_signature(csr_der, cert)
        assert result is True

    def test_verify_csr_signature_invalid(self):
        """Test that tampered CSR fails verification."""
        ek, dk = mlkem_keygen("ML-KEM-1024")
        cert, attestor_key = _make_cert()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        csr_der = build_csr_with_pop(ek, "ML-KEM-1024", subject, attestor_key, cert)
        # Tamper with the signature bytes
        tampered = bytearray(csr_der)
        tampered[-1] ^= 0xFF
        result = verify_csr_signature(bytes(tampered), cert)
        assert result is False

    def test_build_csr_with_pop_mlkem512(self):
        """ML-KEM-512 is absent from cryptography 50.0.1: keygen must raise."""
        with pytest.raises(ValueError, match="not available"):
            mlkem_keygen("ML-KEM-512")


class TestCSROptBuilder:
    """Tests for csr_opt.py functions."""

    def test_opt_build_csr_with_pop(self):
        """Test optimized CSR building."""
        ek, dk = mlkem_keygen("ML-KEM-1024")
        cert, attestor_key = _make_cert()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        
        csr_der = opt_build_csr_with_pop(ek, "ML-KEM-1024", subject, attestor_key, cert)
        assert isinstance(csr_der, bytes)
        assert len(csr_der) > 0

    def test_opt_parse_csr(self):
        """Test optimized CSR parsing."""
        ek, dk = mlkem_keygen("ML-KEM-1024")
        cert, attestor_key = _make_cert()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        
        csr_der = opt_build_csr_with_pop(ek, "ML-KEM-1024", subject, attestor_key, cert)
        parsed = opt_parse_csr(csr_der)
        assert parsed is not None

    def test_opt_verify_csr_signature(self):
        """Test optimized signature verification."""
        ek, dk = mlkem_keygen("ML-KEM-1024")
        cert, attestor_key = _make_cert()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        
        csr_der = opt_build_csr_with_pop(ek, "ML-KEM-1024", subject, attestor_key, cert)
        result = opt_verify_csr_signature(csr_der, cert)
        assert result is True

    def test_opt_build_wrong_key_size(self):
        """Test optimized builder with wrong key size."""
        wrong_key = b"x" * 100
        cert, attestor_key = _make_cert()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        
        with pytest.raises(ValueError, match="ML-KEM public key must be"):
            opt_build_csr_with_pop(wrong_key, "ML-KEM-1024", subject, attestor_key, cert)


class TestCRIBuilderFull:
    """Tests for cri.py build_private_key_possession_statement and CRIBuilder methods."""

    def test_build_pop_statement(self):
        """Test building PrivateKeyPossessionStatement."""
        cert = _make_cert()[0]
        pop = build_private_key_possession_statement(cert)
        assert isinstance(pop, bytes)
        assert len(pop) > 0

    def test_build_pop_statement_with_cert(self):
        """Test building PoP statement with cert included."""
        cert = _make_cert()[0]
        pop = build_private_key_possession_statement(cert, include_cert=True)
        assert isinstance(pop, bytes)
        assert len(pop) > 0
        # With cert included, the DER should be longer than without
        pop_no_cert = build_private_key_possession_statement(cert, include_cert=False)
        assert len(pop) > len(pop_no_cert)

    def test_cri_builder_pop_method(self):
        """Test CRIBuilder's build_private_key_possession_statement path."""
        ek, dk = mlkem_keygen("ML-KEM-1024")
        cert = _make_cert()[0]
        builder = CRIBuilder(
            mlkem_public_key=ek,
            subject_name="CN=test.example.com",
            attestor_certificate=cert,
            parameter_set=MLKEMParameterSet.ML_KEM_1024,
        )
        # Verify the builder can build all components
        subject = builder.build_subject_name()
        assert subject is not None
        spki = builder.build_subject_public_key_info()
        assert isinstance(spki, bytes)
        assert len(spki) > 0
        attrs = builder.build_attributes()
        assert isinstance(attrs, bytes)
        assert len(attrs) > 0

    def test_cri_builder_full(self):
        """Test complete CRI building."""
        ek, dk = mlkem_keygen("ML-KEM-1024")
        cert = _make_cert()[0]
        cri_bytes = build_cri(ek, "CN=test.example.com", cert)
        assert isinstance(cri_bytes, bytes)
        assert len(cri_bytes) > 0

    def test_oid_constants(self):
        """Test OID constants are correct."""
        assert OIDs.ML_KEM_512 == "2.16.840.1.101.3.4.1.1"
        assert OIDs.ML_KEM_768 == "2.16.840.1.101.3.4.1.2"
        assert OIDs.ML_KEM_1024 == "2.16.840.1.101.3.4.1.3"
        assert OIDs.STATEMENT_OF_POSSESSION == "1.3.6.1.4.1.22112.2.1"


class TestMlkemErrorPaths:
    """Tests for mlkem.py error paths."""

    def test_invalid_parameter_set_raises(self):
        """Test that invalid parameter set raises ValueError."""
        with pytest.raises(ValueError):
            mlkem_keygen("INVALID")

    def test_wrong_seed_size_raises(self):
        """Test that wrong seed size raises ValueError."""
        with pytest.raises(ValueError):
            mlkem_keygen("ML-KEM-1024", b"\x00" * 32)

    def test_wrong_seed_size_mlkem768(self):
        """Test wrong seed size for ML-KEM-768."""
        with pytest.raises(ValueError):
            mlkem_keygen("ML-KEM-768", b"\x00" * 32)

    def test_get_key_sizes_invalid(self):
        """Test get_key_sizes with invalid parameter set."""
        from pqblocks_csr_pop.mlkem import get_key_sizes
        with pytest.raises(ValueError):
            get_key_sizes("INVALID")

    def test_get_actual_key_sizes_invalid(self):
        """Test get_actual_key_sizes with invalid parameter set."""
        from pqblocks_csr_pop.mlkem import get_actual_key_sizes
        with pytest.raises(ValueError):
            get_actual_key_sizes("INVALID")

    def test_encapsulate_invalid_param(self):
        """Test encapsulate with invalid parameter set."""
        from pqblocks_csr_pop.mlkem import mlkem_encapsulate
        with pytest.raises(ValueError):
            mlkem_encapsulate(b"x" * 100, "INVALID")

    def test_decapsulate_invalid_param(self):
        """Test decapsulate with invalid parameter set."""
        from pqblocks_csr_pop.mlkem import mlkem_decapsulate
        with pytest.raises(ValueError):
            mlkem_decapsulate(b"x" * 32, b"x" * 100, "INVALID")

    def test_decapsulate_wrong_dk_size(self):
        """Test decapsulate with wrong DK size."""
        from pqblocks_csr_pop.mlkem import mlkem_decapsulate
        with pytest.raises(ValueError):
            mlkem_decapsulate(b"\x00" * 32, b"x" * 100, "ML-KEM-1024")


class TestMlkemOptErrorPaths:
    """Tests for mlkem_opt.py error paths."""

    def test_opt_invalid_parameter_set(self):
        """Test that invalid parameter set raises ValueError in optimized kernel."""
        from pqblocks_csr_pop.mlkem_opt import mlkem_keygen as opt_keygen
        with pytest.raises(ValueError):
            opt_keygen("INVALID")

    def test_opt_wrong_seed_size(self):
        """Test that wrong seed size raises ValueError in optimized kernel."""
        from pqblocks_csr_pop.mlkem_opt import mlkem_keygen as opt_keygen
        with pytest.raises(ValueError):
            opt_keygen("ML-KEM-1024", b"\x00" * 32)

    def test_opt_encapsulate_invalid(self):
        """Test optimized encapsulate with invalid parameter set."""
        from pqblocks_csr_pop.mlkem_opt import mlkem_encapsulate
        with pytest.raises(ValueError):
            mlkem_encapsulate(b"x" * 100, "INVALID")

    def test_opt_decapsulate_invalid(self):
        """Test optimized decapsulate with invalid parameter set."""
        from pqblocks_csr_pop.mlkem_opt import mlkem_decapsulate
        with pytest.raises(ValueError):
            mlkem_decapsulate(b"x" * 32, b"x" * 100, "INVALID")

    def test_opt_decapsulate_wrong_dk_size(self):
        """Test optimized decapsulate with wrong DK size."""
        from pqblocks_csr_pop.mlkem_opt import mlkem_decapsulate
        with pytest.raises(ValueError):
            mlkem_decapsulate(b"\x00" * 32, b"x" * 100, "ML-KEM-1024")

    def test_opt_get_key_sizes_invalid(self):
        """Test optimized get_key_sizes with invalid parameter set."""
        from pqblocks_csr_pop.mlkem_opt import get_key_sizes
        with pytest.raises(ValueError):
            get_key_sizes("INVALID")


class TestErrorModuleMain:
    """Tests for errors.py __main__ block coverage."""

    def test_error_enum_all_values(self):
        """Test all error codes have proper values."""
        from pqblocks_csr_pop.errors import PQCSRError
        values = [e.value for e in PQCSRError]
        assert len(values) == len(set(values))  # No duplicates

    def test_error_code_range(self):
        """Test error codes are in expected range."""
        from pqblocks_csr_pop.errors import PQCSRError
        assert PQCSRError.SUCCESS.value == 0
        assert PQCSRError.ERR_MISSING_POP.value == 1
        assert PQCSRError.ERR_RNG_COLLISION.value == 9

    def test_is_success_and_failure(self):
        """Test success/failure checks."""
        from pqblocks_csr_pop.errors import is_success, is_failure
        assert is_success(0) is True
        assert is_failure(0) is False
        assert is_success(1) is False
        assert is_failure(1) is True


def _make_cert():
    """Create a self-signed Ed25519 certificate for testing."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - datetime.timedelta(days=1)
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).sign(private_key, None)
    return cert, private_key
