"""Tests for PQCSR error taxonomy."""

import pytest
from pqblocks_csr_pop.errors import PQCSRError, get_error_message, is_success, is_failure


class TestPQCSRError:
    """Test the error taxonomy enum."""

    def test_all_errors_have_messages(self):
        """Each error code should have a human-readable message."""
        for error in PQCSRError:
            msg = get_error_message(error)
            assert isinstance(msg, str)
            assert len(msg) > 0

    def test_success_is_zero(self):
        """SUCCESS should be 0 (IntEnum convention)."""
        assert PQCSRError.SUCCESS.value == 0

    def test_success_checks(self):
        """Test is_success and is_failure functions."""
        assert is_success(PQCSRError.SUCCESS) is True
        assert is_failure(PQCSRError.SUCCESS) is False
        assert is_success(PQCSRError.ERR_MISSING_POP) is False
        assert is_failure(PQCSRError.ERR_MISSING_POP) is True

    def test_error_enum_values(self):
        """Verify all error codes have unique values."""
        values = [error.value for error in PQCSRError]
        assert len(values) == len(set(values)), "Duplicate error values detected"


class TestErrorMessages:
    """Test error message mapping."""

    def test_missing_pop_message(self):
        """ERR_MISSING_POP should mention statementOfPossession."""
        msg = get_error_message(PQCSRError.ERR_MISSING_POP)
        assert "statementOfPossession" in msg

    def test_wrong_oid_message(self):
        """ERR_WRONG_OID should mention OID."""
        msg = get_error_message(PQCSRError.ERR_WRONG_OID)
        assert "OID" in msg

    def test_subject_mismatch_message(self):
        """ERR_SUBJECT_MISMATCH should mention subject."""
        msg = get_error_message(PQCSRError.ERR_SUBJECT_MISMATCH)
        assert "subject" in msg.lower()

    def test_attestor_weak_message(self):
        """ERR_ATTESTOR_WEAK should mention attestor and ML-KEM."""
        msg = get_error_message(PQCSRError.ERR_ATTESTOR_WEAK)
        assert "attestor" in msg.lower()
        assert "ML-KEM" in msg

    def test_invalid_key_size_message(self):
        """ERR_INVALID_KEY_SIZE should mention key size."""
        msg = get_error_message(PQCSRError.ERR_INVALID_KEY_SIZE)
        assert "key size" in msg.lower()

    def test_sig_verify_message(self):
        """ERR_SIG_VERIFY should mention signature."""
        msg = get_error_message(PQCSRError.ERR_SIG_VERIFY)
        assert "signature" in msg.lower()

    def test_missing_cert_message(self):
        """ERR_MISSING_ATTESTOR_CERT should mention certificate."""
        msg = get_error_message(PQCSRError.ERR_MISSING_ATTESTOR_CERT)
        assert "certificate" in msg.lower()

    def test_empty_subject_message(self):
        """ERR_EMPTY_SUBJECT should mention empty subject."""
        msg = get_error_message(PQCSRError.ERR_EMPTY_SUBJECT)
        assert "empty" in msg.lower()

    def test_rng_collision_message(self):
        """ERR_RNG_COLLISION should mention RNG."""
        msg = get_error_message(PQCSRError.ERR_RNG_COLLISION)
        assert "RNG" in msg


if __name__ == "__main__":
    pytest.main([__file__, "-v"])