"""Parameter policy and subject-name matching (S.6).

Auto-derives ML-KEM parameter set, enforces attestor-key strength
(RFC 9883 Section 6) and subject-name matching (RFC 9883 Section 3) as
pure functions returning PQCSRError codes. No user tuning: overrides come
only from ML_KEM_PARAM / SUBJECT_MATCH_POLICY environment variables as
the spec mandates. Ideas only, no GPL/proprietary code ported.
"""

import os
from typing import Optional, Union

from cryptography.x509 import Name, Certificate
from cryptography.hazmat.primitives.asymmetric import ed25519, ec

from pqblocks_csr_pop.errors import PQCSRError

EK_SIZE_TO_PARAM = {800: "ML-KEM-512", 1184: "ML-KEM-768", 1568: "ML-KEM-1024"}
PARAM_TO_EK_SIZE = {v: k for k, v in EK_SIZE_TO_PARAM.items()}
VALID_PARAMS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")

REQUIRED_STRENGTH_BITS = {
    "ML-KEM-512": 128,
    "ML-KEM-768": 192,
    "ML-KEM-1024": 256,
}


def _attestor_strength_bits(attestor_key_or_cert) -> Optional[int]:
    """Estimate attestor key strength in bits; None if unrecognized."""
    key = attestor_key_or_cert
    if isinstance(key, Certificate):
        key = key.public_key()
    from cryptography.hazmat.primitives.asymmetric import rsa
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        size = key.key_size
        if isinstance(size, int):
            if size >= 512:
                return 256
            if size >= 384:
                return 192
            if size >= 256:
                return 128
    if hasattr(key, "private_bytes"):
        key = key.public_key() if hasattr(key, "public_key") else key
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return 128
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    if isinstance(key, Ed25519PublicKey):
        return 128
    try:
        from cryptography.hazmat.primitives.asymmetric.x448 import (
            X448PrivateKey,
            X448PublicKey,
        )

        if isinstance(key, (X448PrivateKey, X448PublicKey)):
            return 224
    except ImportError:
        pass
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        name = key.curve.name
        return {"secp256r1": 128, "secp384r1": 192, "secp521r1": 256}.get(name)
    size = getattr(key, "key_size", None)
    if isinstance(size, int):
        if size >= 512:
            return 256
        if size >= 384:
            return 192
        if size >= 256:
            return 128
    return None


def infer_parameter_set(
    ek: Optional[bytes] = None,
    ek_len: Optional[int] = None,
    explicit: Optional[str] = None,
) -> Optional[str]:
    """Derive the ML-KEM parameter set from the public key size.

    Priority per spec Section 2: explicit arg, then ML_KEM_PARAM env var
    (512/768/1024) as tie-breaker on conflict, then size inference.
    Returns None when nothing resolves (no error raised).
    """
    if explicit is not None:
        if explicit not in VALID_PARAMS:
            raise ValueError(f"Unknown parameter set: {explicit}")
        return explicit
    env = os.environ.get("ML_KEM_PARAM")
    if env in ("512", "768", "1024"):
        return f"ML-KEM-{env}"
    size = len(ek) if ek is not None else ek_len
    if size in EK_SIZE_TO_PARAM:
        return EK_SIZE_TO_PARAM[size]
    if ek is None and ek_len is None:
        return None
    # size provided but not valid -> error
    raise ValueError(f"Invalid key size: {size}")


def check_attestor_strength(parameter_set: str, attestor_key_or_cert) -> PQCSRError:
    """Return SUCCESS or ERR_ATTESTOR_WEAK per RFC 9883 Section 6."""
    required = REQUIRED_STRENGTH_BITS[parameter_set]
    bits = _attestor_strength_bits(attestor_key_or_cert)
    if bits is None:
        return PQCSRError.ERR_ATTESTOR_WEAK
    return (
        PQCSRError.SUCCESS if bits >= required else PQCSRError.ERR_ATTESTOR_WEAK
    )


def check_subject_match(
    csr_subject: Union[Name, str],
    cert_subject: Union[Name, Certificate, str],
    policy: Optional[str] = None,
) -> PQCSRError:
    """Enforce subject-name matching per RFC 9883 Section 3.

    policy: exact (default) | ignore | policy-defined. policy-defined
    accepts any non-empty pair and defers to external CA policy.
    """
    mode = policy or os.environ.get("SUBJECT_MATCH_POLICY", "exact")
    if mode == "ignore":
        return PQCSRError.SUCCESS

    def _norm(v) -> str:
        if isinstance(v, Certificate):
            v = v.subject
        if isinstance(v, Name):
            return v.rfc4514_string()
        return str(v).strip()

    a, b = _norm(csr_subject), _norm(cert_subject)
    if not a:
        return PQCSRError.ERR_EMPTY_SUBJECT
    if mode == "policy-defined":
        return PQCSRError.SUCCESS if b else PQCSRError.ERR_MISSING_ATTESTOR_CERT
    return (
        PQCSRError.SUCCESS if a == b else PQCSRError.ERR_SUBJECT_MISMATCH
    )


def validate_csr_inputs(
    ek: Optional[bytes],
    subject: Union[Name, str, None],
    attestor_certificate: Optional[Certificate],
    attestor_key=None,
    parameter_set: Optional[str] = None,
    subject_policy: Optional[str] = None,
) -> PQCSRError:
    """First-failing error code for CSR inputs, SUCCESS if all checks pass."""
    if attestor_certificate is None:
        return PQCSRError.ERR_MISSING_ATTESTOR_CERT
    if subject is None or (isinstance(subject, str) and not subject.strip()):
        return PQCSRError.ERR_EMPTY_SUBJECT
    try:
        param = infer_parameter_set(
            ek=ek,
            explicit=parameter_set,
        )
    except ValueError:
        return PQCSRError.ERR_INVALID_KEY_SIZE
    if attestor_key is not None:
        if check_attestor_strength(param, attestor_key) != PQCSRError.SUCCESS:
            return PQCSRError.ERR_ATTESTOR_WEAK
    csr_name = subject
    code = check_subject_match(csr_name, attestor_certificate, subject_policy)
    if code != PQCSRError.SUCCESS:
        return code
    return PQCSRError.SUCCESS


def validate_inputs(
    ek: Optional[bytes],
    subject: Union[Name, str, None],
    attestor_certificate: Optional[Certificate],
    attestor_key=None,
    parameter_set: Optional[str] = None,
    subject_policy: Optional[str] = None,
) -> PQCSRError:
    return validate_csr_inputs(
        ek=ek, subject=subject,
        attestor_certificate=attestor_certificate,
        attestor_key=attestor_key,
        parameter_set=parameter_set,
        subject_policy=subject_policy,
    )


def is_strong_attestor(attestor_key) -> bool:
    """Return True if attestor key meets minimum strength requirement."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    size = getattr(attestor_key, "key_size", None)
    if isinstance(size, int):
        return size >= 2048
    try:
        if isinstance(attestor_key, rsa.RSAPublicKey):
            return True
    except (ImportError, AttributeError):
        pass
    return False
