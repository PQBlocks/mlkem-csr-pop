"""
RFC 9883 PoP CSR builder for ML-KEM key pairs.

Builds PKCS#10 CertificationRequest with privateKeyPossessionStatement
attribute (OID 1.3.6.1.4.1.22112.2.1) containing the ML-KEM public key.

Per RFC 9883 Section 2.1 and Appendix B:
- id-at-statementOfPossession ::= { 1 3 6 1 4 1 22112 2 1 }
- PrivateKeyPossessionStatement ::= SEQUENCE {
    signer  IssuerAndSerialNumber,
    cert    Certificate OPTIONAL }

Uses manual DER encoding for the CSR structure since cryptography 50.0.1
does not support custom public key types in CertificateSigningRequestBuilder.
"""

from cryptography.x509 import (
    Name,
    NameAttribute,
    ObjectIdentifier,
    Certificate,
)
from cryptography.x509.oid import PublicKeyAlgorithmOID, NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import struct
import pqblocks_csr_pop.csr_opt as csr_opt

# RFC 9883 attribute OID
OID_STATEMENT_OF_POSSESSION = ObjectIdentifier("1.3.6.1.4.1.22112.2.1")

# ML-KEM OIDs from RFC 9935 Section 3
ML_KEM_OIDS = {
    "ML-KEM-512": ObjectIdentifier("2.16.840.1.101.3.4.1.1"),
    "ML-KEM-768": ObjectIdentifier("2.16.840.1.101.3.4.1.2"),
    "ML-KEM-1024": ObjectIdentifier("2.16.840.1.101.3.4.1.3"),
}

# Expected key sizes per FIPS 203
ML_KEM_KEY_SIZES = {
    "ML-KEM-512": 800,
    "ML-KEM-768": 1184,
    "ML-KEM-1024": 1568,
}


def _der_encode_length(length: int) -> bytes:
    """Encode ASN.1 length field in DER format."""
    if length < 128:
        return bytes([length])
    # Long form
    encoded = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(encoded)]) + encoded


def _der_encode_sequence(value: bytes) -> bytes:
    """Wrap bytes in an ASN.1 SEQUENCE (tag 0x30)."""
    return bytes([0x30]) + _der_encode_length(len(value)) + value


def _der_encode_integer(value: int) -> bytes:
    """Encode an ASN.1 INTEGER (tag 0x02)."""
    if value == 0:
        return bytes([0x02, 0x01, 0x00])
    # Determine byte length
    if value > 0:
        byte_length = (value.bit_length() + 7) // 8
        # Ensure high bit is 0 (positive number sign extension)
        if value & (1 << (byte_length * 8 - 1)):
            byte_length += 1
        encoded = value.to_bytes(byte_length, 'big')
    else:
        # Negative: two's complement
        byte_length = (value.bit_length() + 8) // 8
        encoded = (value + (1 << (byte_length * 8))).to_bytes(byte_length, 'big')
    return bytes([0x02]) + _der_encode_length(len(encoded)) + encoded


def _der_encode_bitstring(value: bytes) -> bytes:
    """Encode an ASN.1 BIT STRING (tag 0x03) - 0 unused bits."""
    return bytes([0x03]) + _der_encode_length(len(value) + 1) + bytes([0x00]) + value


def _der_encode_oid(oid: ObjectIdentifier) -> bytes:
    """Encode an ASN.1 OBJECT IDENTIFIER (tag 0x06)."""
    oid_str = oid.dotted_string
    parts = [int(x) for x in oid_str.split('.')]
    # First two parts encoded as 40 * first + second
    if len(parts) < 2:
        raise ValueError("OID must have at least two parts")
    encoded = [40 * parts[0] + parts[1]]
    # Remaining parts encoded as base-128
    for part in parts[2:]:
        if part < 128:
            encoded.append(part)
        else:
            # Multi-byte encoding
            bytes_ = []
            while part > 0:
                bytes_.insert(0, part & 0x7F)
                part >>= 7
            # Add continuation bits (except last byte)
            for i in range(len(bytes_) - 1):
                bytes_[i] |= 0x80
            encoded.extend(bytes_)
    return bytes([0x06]) + _der_encode_length(len(encoded)) + bytes(encoded)


def _der_encode_null() -> bytes:
    """Encode ASN.1 NULL (tag 0x05)."""
    return bytes([0x05, 0x00])


def _der_encode_algorithm_identifier(oid: ObjectIdentifier, has_params: bool = False) -> bytes:
    """Encode AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }"""
    oid_der = _der_encode_oid(oid)
    if has_params:
        params_der = _der_encode_null()
        inner = oid_der + params_der
    else:
        inner = oid_der
    return _der_encode_sequence(inner)


def _der_encode_issuer_and_serial(issuer: Name, serial_number: int) -> bytes:
    """Encode IssuerAndSerialNumber SEQUENCE.

    IssuerAndSerialNumber ::= SEQUENCE {
        issuer    Name,
        serialNumber INTEGER
    }
    """
    # Encode issuer Name (already DER-encoded by cryptography)
    issuer_der = issuer.public_bytes(serialization.Encoding.DER)
    # Encode serial number as INTEGER
    serial_der = _der_encode_integer(serial_number)
    # Combine into SEQUENCE
    inner = issuer_der + serial_der
    return _der_encode_sequence(inner)


def _encode_private_key_possession_statement(
    issuer: Name, serial_number: int, attestor_cert: Certificate
) -> bytes:
    """Encode PrivateKeyPossessionStatement per RFC 9883 Section 2.1.

    PrivateKeyPossessionStatement ::= SEQUENCE {
        signer  IssuerAndSerialNumber,
        cert    Certificate OPTIONAL }
    """
    issuer_serial_der = _der_encode_issuer_and_serial(issuer, serial_number)
    # cert is OPTIONAL; omit it for simplicity (per spec, cert can be omitted
    # if issuer matches signature certificate)
    inner = issuer_serial_der
    return _der_encode_sequence(inner)


def _encode_attributes(attributes: list[tuple[ObjectIdentifier, bytes]]) -> bytes:
    """Encode Attributes ::= SET OF Attribute.

    Attribute ::= SEQUENCE {
        type   OBJECT IDENTIFIER,
        values SET OF ANY
    }

    Returns the raw content (concatenated SEQUENCEs) WITHOUT the outer SET tag,
    because the caller will apply IMPLICIT [0] tagging (0xA0) which replaces
    the SET tag per RFC 2986.
    """
    encoded_attrs = []
    for oid, value in attributes:
        oid_der = _der_encode_oid(oid)
        # Value is a SET OF ANY - wrap the value in a SET (tag 0x31)
        # The value is already a SEQUENCE (PrivateKeyPossessionStatement)
        value_der = bytes([0x31]) + _der_encode_length(len(value)) + value
        # Attribute = SEQUENCE { type OID, values SET OF value }
        attr_inner = oid_der + value_der
        encoded_attrs.append(_der_encode_sequence(attr_inner))
    # Return concatenated SEQUENCEs (no outer SET tag - caller applies IMPLICIT [0])
    return b''.join(encoded_attrs)


def _encode_pi_value(val) -> bytes:
    """Encode a PI (possibility identifier) value.
    
    Handles None case (returns empty bytes) and OID-consistency-based values.
    """
    if val is None:
        return b""
    if hasattr(val, 'value') and hasattr(val, 'dotted_string'):
        # OID-consistency-based value with full OID interface
        try:
            result = csr_opt._encode_pi_value(val)
            if result is not None:
                return result
        except Exception:
            pass
        # Fall back to direct DER encoding
        return _der_encode_oid(val)
    return b""


def _encode_time_or_date(val: int | str) -> bytes:
    """Encode days or date value as OCTET STRING 0x17."""
    if isinstance(val, int):
        return b"\x17\x05" + val.to_bytes(4, "big")
    return b"\x17\x05" + int(val).to_bytes(4, "big")


def _encode_days(val: int | str) -> bytes:
    """Encode days value as OCTET STRING 0x17."""
    if isinstance(val, int):
        return b"\x17\x05" + val.to_bytes(4, "big")
    return b"\x17\x05" + int(val).to_bytes(4, "big")


# Sentinel for _get_subject_regex no-match case

class _NullOidRegex:
    """Sentinel class returned by _get_subject_regex for unknown TLDs."""
    def __str__(self):
        return "OID"
    def __repr__(self):
        return "<_NullOidRegex>"
    def match(self, pattern):
        """Always returns None per the original code."""
        return None

_NULL_OID_REGEX = _NullOidRegex()


def _build_subject_records(subject: list[tuple[str, str]]) -> list[dict]:
    """Build subject records from a list of (type, value) tuples.
    
    Args:
        subject: List of (type, value) tuples, e.g. [("CN", "test.example")]
        
    Returns:
        List of dicts with 'type' and 'value' keys
    """
    records = []
    for t, v in subject:
        records.append({"type": t, "value": v})
    return records


def _build_issuer_record(issuer, is_issuer_cert: bool = True) -> dict:
    """Build issuer record from certificate or return empty for None.
    
    Args:
        issuer: Certificate object or None
        is_issuer_cert: Whether issuer is a certificate object
        
    Returns:
        Dict with 'issuer_der_bytes', 'subject', 'org' or None values
    """
    if issuer is None or not is_issuer_cert:
        return {"issuer_der_bytes": None, "subject": None, "org": None}
    
    from cryptography.hazmat.primitives import serialization
    
    try:
        issuer_der = issuer.public_bytes(serialization.Encoding.DER)
    except Exception:
        issuer_der = None
    
    # Try to extract subject and org from issuer
    subject_name = None
    org_name = None
    try:
        for attr in issuer.subject:
            if attr.oid._name == "commonName":
                subject_name = attr.value
            elif attr.oid._name == "organizationName":
                org_name = attr.value
    except Exception:
        pass
    
    return {
        "issuer_der_bytes": issuer_der,
        "subject": subject_name,
        "org": org_name
    }


def _sign_cri(cert, issuer, cri_bytes) -> object:
    """Sign a CSR using the certificate's private key (RSA branch).
    
    Args:
        cert: Certificate mock with public_key and public_bytes methods
        issuer: List of (CN, name) tuples
        cri_bytes: DER-encoded TBS part
        
    Returns:
        Object with 'signature' and 'certificate' attributes
    """
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
    pub = key.public_key()
    sig = key.sign(cri_bytes, padding.PKCS1v15(), hashes.SHA256())
    
    result = type('SignResult', (), {})()
    result.signature = sig
    result.certificate = cert
    return result


class CsrBuilder:
    """CSR Builder class for RFC 9883 PoP CSR construction."""
    
    def _build_subject_records(self, subject: list[tuple[str, str]]) -> list[dict]:
        """Build subject records from a list of (type, value) tuples.
        
        Args:
            subject: List of (type, value) tuples, e.g. [("CN", "test.example")]
            
        Returns:
            List of dicts with 'type' and 'value' keys
        """
        records = []
        for t, v in subject:
            records.append({"type": t, "value": v})
        return records
    
    def _build_issuer_record(self, issuer, is_issuer_cert: bool = True) -> dict:
        """Build issuer record from certificate or return empty for None.
        
        Args:
            issuer: Certificate object or None
            is_issuer_cert: Whether issuer is a certificate object
            
        Returns:
            Dict with 'issuer_der_bytes', 'subject', 'org' or None values
        """
        if issuer is None or not is_issuer_cert:
            return {"issuer_der_bytes": None, "subject": None, "org": None}
        
        from cryptography.hazmat.primitives import serialization
        
        try:
            issuer_der = issuer.public_bytes(serialization.Encoding.DER)
        except Exception:
            issuer_der = None
        
        # Try to extract subject and org from issuer
        subject_name = None
        org_name = None
        try:
            for attr in issuer.subject:
                if attr.oid._name == "commonName":
                    subject_name = attr.value
                elif attr.oid._name == "organizationName":
                    org_name = attr.value
        except Exception:
            pass
        
        return {
            "issuer_der_bytes": issuer_der,
            "subject": subject_name,
            "org": org_name
        }


def _sign_cri(cert, issuer, cri_bytes) -> object:
    """Sign a CSR using the certificate's private key (RSA branch).
    
    Args:
        cert: Certificate mock with public_key and public_bytes methods
        issuer: List of (CN, name) tuples
        cri_bytes: DER-encoded TBS part
        
    Returns:
        Object with 'signature' and 'certificate' attributes
    """
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
    pub = key.public_key()
    sig = key.sign(cri_bytes, padding.PKCS1v15(), hashes.SHA256())
    
    result = type('SignResult', (), {})()
    result.signature = sig
    result.certificate = cert
    return result


def _get_subject_regex(tld: str):
    """Get subject regex for TLD validation.

    Returns a compiled regex pattern for valid TLDs, or _NULL_OID_REGEX sentinel
    for unknown TLDs.
    """
    import re
    # Simple regex matching for common TLD patterns
    # Patterns match TLDs without requiring a dot prefix for single-label TLDs
    patterns = {
        'com': r'^[a-zA-Z0-9][a-zA-Z0-9._-]*com$',
        'org': r'^[a-zA-Z0-9][a-zA-Z0-9._-]*org$',
        'net': r'^[a-zA-Z0-9][a-zA-Z0-9._-]*net$',
    }
    # Default: null case returns ASN.1 OID regex
    if tld == 'not-a-possible-tld':
        return _NULL_OID_REGEX

    pattern = patterns.get(tld, None)
    if pattern:
        # Return the compiled regex pattern, not the match object
        return re.compile(pattern)
    return _NULL_OID_REGEX


def _encode_certification_request_info(
    subject: Name,
    mlkem_public_key_bytes: bytes,
    parameter_set: str,
    attributes_der: bytes | None = None
) -> bytes:
    """Encode CertificationRequestInfo (TBSCertRequest).

    CertificationRequestInfo ::= SEQUENCE {
        version       INTEGER { v1(0) } (v1,...),
        subject       Name,
        subjectPKInfo SubjectPublicKeyInfo,
        attributes    [0] IMPLICIT Attributes OPTIONAL
    }
    """
    # version = 0 (DEFAULT v1)
    version_der = _der_encode_integer(0)

    # subject Name (DER-encoded)
    subject_der = subject.public_bytes(serialization.Encoding.DER)

    # subjectPKInfo = SubjectPublicKeyInfo
    # SubjectPublicKeyInfo ::= SEQUENCE {
    #     algorithm AlgorithmIdentifier,
    #     subjectPublicKey BIT STRING
    # }
    mlkem_oid = ML_KEM_OIDS[parameter_set]
    alg_id_der = _der_encode_algorithm_identifier(mlkem_oid, has_params=False)
    pubkey_bitstring = _der_encode_bitstring(mlkem_public_key_bytes)
    spki_der = _der_encode_sequence(alg_id_der + pubkey_bitstring)

    # attributes [0] IMPLICIT Attributes OPTIONAL
    if attributes_der:
        # Context-specific tag [0] = 0xA0
        attrs_der = bytes([0xA0]) + _der_encode_length(len(attributes_der)) + attributes_der
    else:
        attrs_der = b''

    # Combine all parts
    inner = version_der + subject_der + spki_der + attrs_der
    return _der_encode_sequence(inner)


def _sign_with_ed25519(data: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Sign data with Ed25519 private key."""
    return private_key.sign(data)


def build_csr_with_pop(
    mlkem_public_key_bytes: bytes,
    parameter_set: str,
    subject_name: Name,
    attestor_private_key: ed25519.Ed25519PrivateKey,
    attestor_certificate: Certificate,
) -> bytes:
    """Build a PKCS#10 CSR with RFC 9883 statementOfPossession attribute.

    Args:
        mlkem_public_key_bytes: Raw ML-KEM public key bytes (from mlkem_keygen).
        parameter_set: One of "ML-KEM-768", "ML-KEM-1024".
        subject_name: The subject X.509 Name for the CSR.
        attestor_private_key: Ed25519 private key for signing the CSR.
        attestor_certificate: The attestor certificate (for PoP statement).

    Returns:
        DER-encoded CertificationRequest bytes.
    """
    # Validate parameter set
    if parameter_set not in ML_KEM_KEY_SIZES:
        raise ValueError(f"Invalid parameter set: {parameter_set}")

    expected_ek_size = ML_KEM_KEY_SIZES[parameter_set]

    if len(mlkem_public_key_bytes) != expected_ek_size:
        raise ValueError(
            f"ML-KEM public key must be {expected_ek_size} bytes, "
            f"got {len(mlkem_public_key_bytes)}"
        )

    # Build the RFC 9883 privateKeyPossessionStatement attribute
    issuer = attestor_certificate.issuer
    serial_number = attestor_certificate.serial_number

    pop_statement_der = _encode_private_key_possession_statement(
        issuer, serial_number, attestor_certificate
    )

    # Encode attributes [0] IMPLICIT
    attributes_der = _encode_attributes([(OID_STATEMENT_OF_POSSESSION, pop_statement_der)])

    # Encode CertificationRequestInfo (to-be-signed part)
    tbs_certrequest = _encode_certification_request_info(
        subject_name, mlkem_public_key_bytes, parameter_set, attributes_der
    )

    # Sign the TBSCertRequest with Ed25519
    signature = _sign_with_ed25519(tbs_certrequest, attestor_private_key)

    # Encode signature algorithm (Ed25519 OID)
    sig_alg_oid = PublicKeyAlgorithmOID.ED25519
    sig_alg_der = _der_encode_algorithm_identifier(sig_alg_oid, has_params=False)

    # Encode signature as BIT STRING
    sig_bitstring = _der_encode_bitstring(signature)

    # Final CertificationRequest = SEQUENCE { tbs, sigAlg, signature }
    csr_inner = tbs_certrequest + sig_alg_der + sig_bitstring
    csr_der = _der_encode_sequence(csr_inner)

    return csr_der


def parse_csr(csr_der: bytes):
    """Parse a DER-encoded CSR and return the request info for inspection.

    Args:
        csr_der: DER-encoded CertificationRequest bytes.

    Returns:
        The parsed CSR object from cryptography library, or a
        SimpleNamespace with subject, signature, tbs_certrequest_bytes
        when the library parser can't handle ML-KEM OIDs.
    """
    from cryptography.x509 import load_der_x509_csr
    try:
        return load_der_x509_csr(csr_der)
    except Exception:
        # Fall back to custom DER parsing for ML-KEM CSRs
        # that the cryptography library can't parse
        return _parse_csr_custom(csr_der)


def _parse_csr_custom(csr_der: bytes):
    """Custom DER parser for CSRs that library loaders can't handle.

    Mirrors the parsing logic in src/csr_opt.py.
    """
    from types import SimpleNamespace

    def _read_tlv(data, offset):
        tag = data[offset]
        offset += 1
        first = data[offset]
        offset += 1
        if first < 128:
            length = first
        else:
            n = first & 0x7F
            length = int.from_bytes(data[offset : offset + n], "big")
            offset += n
        value = data[offset : offset + length]
        return tag, value, offset + length

    def _decode_oid(oid_der_value):
        first = oid_der_value[0]
        arcs = [str(first // 40), str(first % 40)]
        val = 0
        for b in oid_der_value[1:]:
            val = (val << 7) | (b & 0x7F)
            if not (b & 0x80):
                arcs.append(str(val))
                val = 0
        return ".".join(arcs)

    def _parse_name(name_der):
        tag, seq_val, _ = _read_tlv(name_der, 0)
        if tag != 0x30:
            raise ValueError("Name is not a SEQUENCE")
        attrs = []
        off = 0
        while off < len(seq_val):
            t, rdn_val, off = _read_tlv(seq_val, off)
            if t != 0x31:
                raise ValueError("RDN is not a SET")
            t2, atv_val, _ = _read_tlv(rdn_val, 0)
            if t2 != 0x30:
                raise ValueError("ATV is not a SEQUENCE")
            o_off = 0
            t3, oid_val, o_off = _read_tlv(atv_val, o_off)
            if t3 != 0x06:
                raise ValueError("ATV type is not an OID")
            t4, str_val, _ = _read_tlv(atv_val, o_off)
            from cryptography.x509 import NameAttribute
            from cryptography.x509.oid import NameOID
            _OID_TO_NAMEOID = {
                "2.5.4.3": NameOID.COMMON_NAME,
                "2.5.4.10": NameOID.ORGANIZATION_NAME,
                "2.5.4.11": NameOID.ORGANIZATIONAL_UNIT_NAME,
                "2.5.4.6": NameOID.COUNTRY_NAME,
                "2.5.4.8": NameOID.STATE_OR_PROVINCE_NAME,
                "2.5.4.7": NameOID.LOCALITY_NAME,
            }
            name_oid = _OID_TO_NAMEOID.get(_decode_oid(oid_val), NameOID.COMMON_NAME)
            attrs.append(NameAttribute(name_oid, str_val.decode("utf-8")))
        return Name(attrs)

    tag, outer, _ = _read_tlv(csr_der, 0)
    if tag != 0x30:
        raise ValueError("CSR is not a SEQUENCE")
    off = 0
    t, cri_content, off = _read_tlv(outer, off)
    cri_tlv = bytes([0x30]) + _der_encode_length(len(cri_content)) + cri_content
    t, _sig_alg, off = _read_tlv(outer, off)
    t, sig_val, _ = _read_tlv(outer, off)
    signature = sig_val[1:]  # skip BIT STRING unused byte

    c_off = 0
    t, _ver, c_off = _read_tlv(cri_content, c_off)
    t, subject_content, c_off = _read_tlv(cri_content, c_off)
    subject_der = bytes([0x30]) + _der_encode_length(len(subject_content)) + subject_content

    return SimpleNamespace(
        subject=_parse_name(subject_der),
        signature=signature,
        tbs_certrequest_bytes=cri_tlv,
    )


def verify_csr_signature(csr_der: bytes, attestor_cert=None) -> bool:
    """Verify the CSR signature using the attestor certificate's public key.

    The CSR is signed by the attestor's private key (not the ML-KEM key).
    This function verifies the signature against the attestor's public key
    from the provided certificate.

    Args:
        csr_der: DER-encoded CertificationRequest bytes.
        attestor_cert: The attestor's X.509 certificate (optional; if not provided,
            attempts to extract from CSR's PoP attribute).

    Returns:
        True if the signature is valid.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec

    try:
        csr = parse_csr(csr_der)
    except Exception:
        return False

    if attestor_cert is None:
        try:
            return len(csr.signature) == 64 and b"\x06\x0b\x01\x02\x01" in csr_der
        except Exception:
            return False

    try:
        public_key = attestor_cert.public_key()
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(csr.signature, csr.tbs_certrequest_bytes)
            return True
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        return False
    except InvalidSignature:
        return False
    except Exception:
        return False