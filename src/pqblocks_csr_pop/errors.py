"""
Error taxonomy for RFC 9883 PoP CSR construction with ML-KEM.

Implements S.4: Implement error taxonomy and edge-case ledger as return codes.
"""

from enum import IntEnum


class PQCSRError(IntEnum):
    """
    Error codes for ML-KEM PoP CSR construction per RFC 9883 edge-case ledger.
    """
    # Success
    SUCCESS = 0

    # Edge case errors from spec Section 3
    ERR_MISSING_POP = 1           # Missing statementOfPossession attribute
    ERR_WRONG_OID = 2             # Wrong OID for attribute
    ERR_SUBJECT_MISMATCH = 3      # Subject name mismatch (policy=enforced)
    ERR_ATTESTOR_WEAK = 4         # Attestor key too weak for ML-KEM param
    ERR_INVALID_KEY_SIZE = 5      # Invalid ML-KEM public key size
    ERR_SIG_VERIFY = 6            # Signature verification failure
    ERR_MISSING_ATTESTOR_CERT = 7 # Missing attestor certificate
    ERR_EMPTY_SUBJECT = 8         # Empty subject name
    ERR_RNG_COLLISION = 9         # Non-deterministic RNG reuse

    @property
    def message(self) -> str:
        """Get human-readable message for this error code."""
        return ERROR_MESSAGES.get(self, f"Unknown error code: {self}")


# Error code to message mapping
ERROR_MESSAGES = {
    PQCSRError.SUCCESS: "Success",
    PQCSRError.ERR_MISSING_POP: "Missing statementOfPossession attribute",
    PQCSRError.ERR_WRONG_OID: "Wrong OID for attribute",
    PQCSRError.ERR_SUBJECT_MISMATCH: "Subject name mismatch",
    PQCSRError.ERR_ATTESTOR_WEAK: "Attestor key too weak for ML-KEM parameter",
    PQCSRError.ERR_INVALID_KEY_SIZE: "Invalid ML-KEM public key size",
    PQCSRError.ERR_SIG_VERIFY: "Signature verification failure",
    PQCSRError.ERR_MISSING_ATTESTOR_CERT: "Missing attestor certificate",
    PQCSRError.ERR_EMPTY_SUBJECT: "Empty subject name",
    PQCSRError.ERR_RNG_COLLISION: "Non-deterministic RNG reuse",
}


def get_error_message(error_code: PQCSRError) -> str:
    """
    Get human-readable message for error code.
    
    Args:
        error_code: PQCSRError enum value
        
    Returns:
        Human-readable error message
    """
    return ERROR_MESSAGES.get(error_code, f"Unknown error code: {error_code}")


# Convenience functions for checking specific error conditions
def is_success(error_code: PQCSRError) -> bool:
    """Check if error code indicates success."""
    return error_code == PQCSRError.SUCCESS


def is_failure(error_code: PQCSRError) -> bool:
    """Check if error code indicates failure."""
    return error_code != PQCSRError.SUCCESS


if __name__ == "__main__":
    # Quick test
    print("PQCSR Error Taxonomy:")
    for error in PQCSRError:
        print(f"{error.name}: {error.value} - {get_error_message(error)}")
