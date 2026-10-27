"""
Additional tests to cover uncovered lines in ML-KEM and related modules.
"""
import pytest
from pqblocks_csr_pop.mlkem import (
    mlkem_keygen, mlkem_encapsulate, mlkem_decapsulate,
    get_key_sizes, get_actual_key_sizes,
    _get_private_key_class, _get_public_key_class,
    SEED_SIZES, KEY_SIZES, PARAM_SET_CONFIG
)
from pqblocks_csr_pop.csr_builder import _encode_pi_value
from pqblocks_csr_pop.errors import PQCSRError, get_error_message, ERROR_MESSAGES
from pqblocks_csr_pop.policy import infer_parameter_set


def test_mlkem_keygen_invalid_parameter_set():
    """Test ML-KEM keygen with invalid parameter set - covers line 47."""
    with pytest.raises(ValueError, match="Invalid parameter set: ML-KEM-999"):
        mlkem_keygen("ML-KEM-999")


def test_mlkem_keygen_not_available_parameter_set():
    """Test ML-KEM keygen with ML-KEM-512 (not available) - covers line 50."""
    with pytest.raises(ValueError, match="Parameter set ML-KEM-512 not available"):
        mlkem_keygen("ML-KEM-512")


def test_mlkem_encapsulate_invalid_parameter_set():
    """Test ML-KEM encapsulate with invalid parameter set."""
    with pytest.raises(ValueError, match="Invalid parameter set: ML-KEM-999"):
        mlkem_encapsulate(b"", "ML-KEM-999")


def test_mlkem_encapsulate_not_available_parameter_set():
    """Test ML-KEM encapsulate with ML-KEM-512 (not available)."""
    with pytest.raises(ValueError, match="Parameter set ML-KEM-512 not available"):
        mlkem_encapsulate(b"", "ML-KEM-512")


def test_mlkem_decapsulate_invalid_parameter_set():
    """Test ML-KEM decapsulate with invalid parameter set."""
    with pytest.raises(ValueError, match="Invalid parameter set: ML-KEM-999"):
        mlkem_decapsulate(b"\x00" * 32, b"\x00" * 64, "ML-KEM-999")


def test_mlkem_decapsulate_not_available_parameter_set():
    """Test ML-KEM decapsulate with ML-KEM-512 (not available)."""
    # Must pass 32-byte DK to get past the size check and reach the _get_private_key_class call
    with pytest.raises(ValueError, match="Parameter set ML-KEM-512 not available"):
        mlkem_decapsulate(b"\x00" * 32, b"\x00" * 64, "ML-KEM-512")


def test_get_key_sizes_invalid_parameter_set():
    """Test get_key_sizes with invalid parameter set."""
    with pytest.raises(ValueError, match="Invalid parameter set: ML-KEM-999"):
        get_key_sizes("ML-KEM-999")


def test_get_actual_key_sizes_invalid_parameter_set():
    """Test get_actual_key_sizes with invalid parameter set."""
    with pytest.raises(ValueError, match="Invalid parameter set: ML-KEM-999"):
        get_actual_key_sizes("ML-KEM-999")


def test_get_private_key_class_invalid_parameter_set():
    """Test _get_private_key_class with invalid parameter set."""
    with pytest.raises(ValueError, match="Invalid parameter set: ML-KEM-999"):
        _get_private_key_class("ML-KEM-999")


def test_get_private_key_class_not_available():
    """Test _get_private_key_class for ML-KEM-512 (not available)."""
    with pytest.raises(ValueError, match="Parameter set ML-KEM-512 not available"):
        _get_private_key_class("ML-KEM-512")


def test_get_public_key_class_invalid_parameter_set():
    """Test _get_public_key_class with invalid parameter set."""
    with pytest.raises(ValueError, match="Invalid parameter set: ML-KEM-999"):
        _get_public_key_class("ML-KEM-999")


def test_get_public_key_class_not_available():
    """Test _get_public_key_class for ML-KEM-512 (not available)."""
    with pytest.raises(ValueError, match="Parameter set ML-KEM-512 not available"):
        _get_public_key_class("ML-KEM-512")


def test_encode_pi_value_with_none():
    """Test _encode_pi_value with None - should return empty bytes."""
    from pqblocks_csr_pop.csr_builder import _encode_pi_value
    result = _encode_pi_value(None)
    assert result == b""


def test_encode_pi_value_with_dotted_string():
    """Test _encode_pi_value with object that has 'dotted_string' attribute."""
    from pqblocks_csr_pop.csr_builder import _encode_pi_value

    # Create a mock object with 'dotted_string' attribute
    class MockDottedString:
        def __init__(self, dotted_string):
            self.dotted_string = dotted_string

    mock_obj = MockDottedString("1.2.3.4.5")
    # This should return _der_encode_oid(val) if hasattr(val, 'dotted_string') else b""
    result = _encode_pi_value(mock_obj)
    assert isinstance(result, bytes)


def test_infer_parameter_set_with_invalid_input():
    """Test infer_parameter_set with various invalid inputs."""
    # Test with None for both ek and ek_len
    assert infer_parameter_set(None, None) is None

    # Test with invalid explicit parameter
    with pytest.raises(ValueError, match="Unknown parameter set: ML-KEM-999"):
        infer_parameter_set(explicit="ML-KEM-999")

    # Test with invalid size that doesn't match any known EK size
    with pytest.raises(ValueError, match="Invalid key size: 999"):
        infer_parameter_set(ek_len=999)

    # Test with empty bytes (size 0)
    with pytest.raises(ValueError, match="Invalid key size: 0"):
        infer_parameter_set(ek=b"")


def test_error_messages_pqcsrerror_basic():
    """Test basic PQCSRError and error message functionality."""
    # Test that ERROR_MESSAGES dict is populated
    assert isinstance(ERROR_MESSAGES, dict)
    assert len(ERROR_MESSAGES) > 0

    # Test get_error_message function with valid error codes
    msg = get_error_message(PQCSRError.SUCCESS)
    assert isinstance(msg, str)
    assert msg == "Success"

    # Test with another valid error code
    msg = get_error_message(PQCSRError.ERR_MISSING_POP)
    assert isinstance(msg, str)
    assert msg == "Missing statementOfPossession attribute"

    # Test PQCSRError enum access
    assert PQCSRError.SUCCESS == 0
    assert PQCSRError.ERR_MISSING_POP == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
def test_encode_pi_value_with_value_only():
    """Test _encode_pi_value with object that has 'value' but not 'dotted_string' - covers lines 191, 199."""
    from pqblocks_csr_pop.csr_builder import _encode_pi_value
    
    class MockValueOnly:
        def __init__(self, value):
            self.value = value
    
    mock_obj = MockValueOnly("test")
    # Should return b"" because it has 'value' but not 'dotted_string'
    result = _encode_pi_value(mock_obj)
    assert result == b""


def test_encode_pi_value_with_dotted_string_csr_opt_returns_bytes():
    """Test _encode_pi_value when csr_opt._encode_pi_value returns bytes - covers lines 192-194."""
    from pqblocks_csr_pop.csr_builder import _encode_pi_value
    from pqblocks_csr_pop import csr_opt
    
    class MockDottedString:
        def __init__(self, dotted_string):
            self.dotted_string = dotted_string
            self.value = "test"
    
    # Mock csr_opt._encode_pi_value to return bytes
    original = csr_opt._encode_pi_value
    try:
        csr_opt._encode_pi_value = lambda val: b'\x06\x03\x02\x01\x01'
        mock_obj = MockDottedString("1.2.3.4.5")
        result = _encode_pi_value(mock_obj)
        # Should return the bytes from csr_opt (the mock)
        assert result == b'\x06\x03\x02\x01\x01'
    finally:
        csr_opt._encode_pi_value = original


def test_encode_pi_value_with_dotted_string_csr_opt_returns_none():
    """Test _encode_pi_value when csr_opt._encode_pi_value returns None - covers lines 192-194, 197-198."""
    from pqblocks_csr_pop.csr_builder import _encode_pi_value, _der_encode_oid
    from pqblocks_csr_pop import csr_opt
    
    class MockDottedString:
        def __init__(self, dotted_string):
            self.dotted_string = dotted_string
            self.value = "test"
    
    # Mock csr_opt._encode_pi_value to return None
    original = csr_opt._encode_pi_value
    try:
        csr_opt._encode_pi_value = lambda val: None
        mock_obj = MockDottedString("1.2.3.4.5")
        result = _encode_pi_value(mock_obj)
        # Should fall back to _der_encode_oid
        expected = _der_encode_oid(mock_obj)
        assert result == expected
    finally:
        csr_opt._encode_pi_value = original


def test_encode_pi_value_with_dotted_string_csr_opt_exception():
    """Test _encode_pi_value when csr_opt._encode_pi_value raises exception - covers lines 192, 195-196, 197-198."""
    from pqblocks_csr_pop.csr_builder import _encode_pi_value, _der_encode_oid
    from pqblocks_csr_pop import csr_opt
    
    class MockDottedString:
        def __init__(self, dotted_string):
            self.dotted_string = dotted_string
            self.value = "test"
    
    # Mock csr_opt._encode_pi_value to raise exception
    original = csr_opt._encode_pi_value
    try:
        csr_opt._encode_pi_value = lambda val: (_ for _ in ()).throw(ValueError("test"))
        mock_obj = MockDottedString("1.2.3.4.5")
        result = _encode_pi_value(mock_obj)
        # Should fall back to _der_encode_oid
        expected = _der_encode_oid(mock_obj)
        assert result == expected
    finally:
        csr_opt._encode_pi_value = original


def test_null_oid_regex():
    """Test _NullOidRegex class - covers lines 216-222."""
    from pqblocks_csr_pop.csr_builder import _NullOidRegex
    
    pattern = _NullOidRegex()
    assert pattern is not None
    assert str(pattern) == "OID"
    assert repr(pattern) == "<_NullOidRegex>"
    # The match method always returns None per the original code
    assert pattern.match(b"anything") is None


def test_build_issuer_record_exception_paths():
    """Test _build_issuer_record exception handling - covers lines 257-258, 269-270."""
    from pqblocks_csr_pop.csr_builder import _build_issuer_record
    
    # Test with None cert and is_issuer_cert=False
    result = _build_issuer_record(None, is_issuer_cert=False)
    assert result is not None
    assert result["issuer_der_bytes"] is None
    assert result["subject"] is None
    assert result["org"] is None
    
    # Test with None cert and is_issuer_cert=True (should still return dict with None values)
    result = _build_issuer_record(None, is_issuer_cert=True)
    assert result is not None
    assert result["issuer_der_bytes"] is None
    assert result["subject"] is None
    assert result["org"] is None


def test_sign_cri_standalone():
    """Test _sign_cri standalone function - covers lines 290-301."""
    from pqblocks_csr_pop.csr_builder import _sign_cri
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from unittest.mock import MagicMock
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
    pub = key.public_key()
    cri_bytes = b"\x30\x09\x02\x01\x01\x02\x01\x01\x30\x05\x02\x01\x01\x02\x01\x02"
    from cryptography.x509 import Certificate
    cert = MagicMock()
    cert.public_key.return_value = pub
    cert.public_bytes.return_value = b"\x30\x0a\x02\x01\x01"
    issuer = [("CN", "ca.example")]
    
    result = _sign_cri(cert, issuer, cri_bytes)
    assert result is not None
    assert hasattr(result, 'signature')
    assert isinstance(result.signature, bytes)


def test_build_subject_records_in_class():
    """Test CsrBuilder._build_subject_records method - covers lines 316-319."""
    from pqblocks_csr_pop.csr_builder import CsrBuilder
    from cryptography.x509 import Name
    from cryptography.x509.oid import NameOID
    
    builder = CsrBuilder()
    subject = [("CN", "test.example")]
    result = builder._build_subject_records(subject)
    assert isinstance(result, list)
    assert len(result) > 0
    assert result[0] == {"type": "CN", "value": "test.example"}


def test_build_issuer_record_in_class():
    """Test CsrBuilder._build_issuer_record method - covers lines 321-330, 338-350."""
    from pqblocks_csr_pop.csr_builder import CsrBuilder
    
    builder = CsrBuilder()
    
    # Test with None
    result = builder._build_issuer_record(None, is_issuer_cert=False)
    assert result is not None
    assert result["issuer_der_bytes"] is None
    assert result["subject"] is None
    assert result["org"] is None
    
    # Test with certificate mock
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    import datetime
    from cryptography import x509
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
    pub = key.public_key()
    # Add organizationName to the subject so org is extracted
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test.example"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Test Org")
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(pub).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1)).sign(key, hashes.SHA256(), default_backend())
    
    result = builder._build_issuer_record(cert, is_issuer_cert=True)
    assert result is not None
    assert result["issuer_der_bytes"] is not None
    assert isinstance(result["issuer_der_bytes"], bytes)
    assert result["subject"] is not None
    assert result["org"] is not None


def test_get_subject_regex():
    """Test _get_subject_regex function - covers lines 385-406."""
    from pqblocks_csr_pop.csr_builder import _get_subject_regex, _NullOidRegex
    import re
    
    # Test with known TLD
    m = _get_subject_regex("com")
    assert m is not None
    assert isinstance(m, type(re.compile("")))
    
    m = _get_subject_regex("org")
    assert m is not None
    assert isinstance(m, type(re.compile("")))
    
    m = _get_subject_regex("net")
    assert m is not None
    assert isinstance(m, type(re.compile("")))
    
    # Test with unknown TLD (should return _NullOidRegex)
    result = _get_subject_regex("unknown")
    assert isinstance(result, _NullOidRegex)
    
    # Test with the special case from original code
    result = _get_subject_regex("not-a-possible-tld")
    assert isinstance(result, _NullOidRegex)
