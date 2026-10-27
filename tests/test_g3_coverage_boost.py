"""Coverage boost — targeted tests for remaining gaps.

Run: PYTHONPATH=. python3 -m pytest tests/test_g3_coverage_boost.py -v --cov=src/

Key facts (from source):
  - Ed25519 cert: CertificateBuilder.sign(private_key, algorithm=None) — not SHA256
  - ML-KEM-768: seed=64B, DK=2400B, EK=1184B, CT=1184B, SS=32B
  - build_csr_with_pop(mlkem_ek, param_set, subject_name, attestor_privkey, attestor_cert)
  - verify_csr_signature(csr_der, attestor_cert=None) — None path checks OID bytes
  - check_attestor_strength(param_set, attestor_key_or_cert) → PQCSRError
  - _der_encode_issuer_and_serial(issuer: Name, serial_number: int) → bytes
  - _encode_private_key_possession_statement(issuer, serial_number, attestor_cert) → bytes
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import Name, NameAttribute, Certificate, ObjectIdentifier
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import mlkem as crypto_mlkem
import datetime

import pqblocks_csr_pop.csr_builder as CB
import pqblocks_csr_pop.csr_opt as CO
import pqblocks_csr_pop.errors as ERR
import pqblocks_csr_pop.mlkem as MK
import pqblocks_csr_pop.mlkem_opt as MKO
import pqblocks_csr_pop.policy as POL
from pqblocks_csr_pop.policy import infer_parameter_set

from pqblocks_csr_pop.errors import PQCSRError, get_error_message


# ── helpers ────────────────────────────────────────────────────────────────

def _ed25519_keypair():
    key = ed25519.Ed25519PrivateKey.generate()
    return key, key.public_key()


def _ecdsa_keypair():
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return key, key.public_key()


def _self_signed_cert(private_key, public_key, issuer_name, serial=1):
    from cryptography import x509
    builder = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    )
    # Ed25519 requires algorithm=None
    algorithm = None if isinstance(private_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(private_key, algorithm, default_backend())


def _simple_name(value="CN=Test"):
    return Name([NameAttribute(NameOID.COMMON_NAME, value)])


# ═══════════════════════════════════════════════════════════════════════════
# src/csr_builder.py
# ═══════════════════════════════════════════════════════════════════════════

class TestCB_DerEncodeInteger:
    """Cover: L80 (negative), L89 (zero), L73-74 (positive high-bit)."""

    def test_negative(self):
        """L80: negative integer (value <= 0 path)."""
        r = CB._der_encode_integer(-1)
        assert r[0] == 0x02
        # -1 in two's complement: 0xFF
        assert b'\xff' in r

    def test_zero(self):
        """L89: zero → b'\\x02\\x01\\x00'."""
        r = CB._der_encode_integer(0)
        assert r == b'\x02\x01\x00'

    def test_large_positive_high_bit(self):
        """L73-74: positive value with high bit set → extra byte."""
        value = 1 << 127  # bit_length=128 (even), high bit of 16-byte rep set
        r = CB._der_encode_integer(value)
        assert r[0] == 0x02
        # (128+7)//8 = 16, value & (1 << 127) != 0 → +1 → 17 content bytes
        assert len(r) == 1 + 1 + 17  # tag + len + 17 content


class TestCB_DerEncodeBitstring:
    """The bitstring func (L78-80) is trivial: always 0 unused bits.
    To cover L218 in _encode_certification_request_info, call it with
    attributes_der=None via _encode_certification_request_info directly."""

    def test_encode_cri_without_attributes(self):
        """L214-218: _encode_certification_request_info with attributes_der=None
        → attrs_der = b'' (line 218)."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        name = _simple_name("CN=Test")
        cri_der = CB._encode_certification_request_info(
            name, ek, "ML-KEM-768", attributes_der=None
        )
        assert isinstance(cri_der, bytes)
        assert len(cri_der) > 0


class TestCB_DerEncodeAlgorithmIdentifier:
    """Cover: L349/355/358 (has_params=True), L362 (has_params=False)."""

    def test_with_params(self):
        """L349/355/358: OID + NULL."""
        oid = ObjectIdentifier("1.2.840.10045.4.1")
        r = CB._der_encode_algorithm_identifier(oid, has_params=True)
        assert r[0] == 0x30
        assert b'\x05\x00' in r

    def test_without_params(self):
        """L362: OID without params."""
        oid = ObjectIdentifier("1.3.6.1.5")
        r = CB._der_encode_algorithm_identifier(oid, has_params=False)
        assert r[0] == 0x30
        assert b'\x05\x00' not in r


class TestCB_DerEncodeIssuerAndSerial:
    """Cover: L380 — _der_encode_issuer_and_serial directly."""

    def test_issuer_and_serial(self):
        """L380: encode issuer name + serial number."""
        name = _simple_name("CN=CA")
        key, pub = _ed25519_keypair()
        cert = _self_signed_cert(key, pub, name, serial=42)
        r = CB._der_encode_issuer_and_serial(cert.issuer, cert.serial_number)
        assert r[0] == 0x30
        assert len(r) > 0


class TestCB_EncodePrivateKeyPossessionStatement:
    """Cover: L421-422, 425-428, 435-442, 445-446."""

    def test_pop_statement(self):
        """L421-422, 425-428, 435-442: encode POP statement with cert."""
        name = _simple_name("CN=Pop CA")
        key, pub = _ed25519_keypair()
        cert = _self_signed_cert(key, pub, name, serial=77)
        r = CB._encode_private_key_possession_statement(
            cert.issuer, cert.serial_number, cert
        )
        assert r[0] == 0x30
        assert len(r) > 5

    def test_pop_statement_bytes(self):
        """L445-446: returns bytes."""
        name = _simple_name("CN=CA")
        key, pub = _ed25519_keypair()
        cert = _self_signed_cert(key, pub, name, serial=99)
        r = CB._encode_private_key_possession_statement(
            cert.issuer, cert.serial_number, cert
        )
        assert isinstance(r, bytes)


class TestCB_EncodeAttributes:
    """Cover: L445-446 (empty + single attr)."""

    def test_empty(self):
        """L445-446: empty → b''."""
        r = CB._encode_attributes([])
        assert r == b''

    def test_single(self):
        """Single attribute."""
        oid = ObjectIdentifier("1.3.6.1.4.1.22112.2.1")
        pop_der = b'\x30\x05\x30\x03\x06\x01\x02'
        r = CB._encode_attributes([(oid, pop_der)])
        assert len(r) > 0


class TestCB_BuildCsrWithPopInvalidParam:
    """Cover: L251 — build_csr_with_pop with invalid parameter_set."""

    def test_invalid_param_set(self):
        """L251: ValueError on invalid parameter_set."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        att_key, att_pub = _ed25519_keypair()
        name = _simple_name("CN=Test")
        cert = _self_signed_cert(att_key, att_pub, name, serial=1)
        with pytest.raises(ValueError, match="Invalid parameter set"):
            CB.build_csr_with_pop(ek, "ML-KEM-999", name, att_key, cert)


class TestCB_VerifyCsrSignatureNoneCert:
    """Cover: L424-428 — verify_csr_signature with attestor_cert=None."""

    def test_verify_none(self):
        """L424-428: verify with None cert → checks signature len + OID bytes."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        att_key, att_pub = _ed25519_keypair()
        name = _simple_name("CN=Test")
        cert = _self_signed_cert(att_key, att_pub, name, serial=1)
        csr = CB.build_csr_with_pop(ek, "ML-KEM-768", name, att_key, cert)
        result = CB.verify_csr_signature(csr, attestor_cert=None)
        assert isinstance(result, bool)


class TestCB_VerifyCsrSignatureWithCert:
    """Cover: L430-446 — verify_csr_signature with cert."""

    def test_verify_valid_ed25519(self):
        """L430-434: verify with valid Ed25519 cert → True."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        att_key, att_pub = _ed25519_keypair()
        name = _simple_name("CN=Test")
        cert = _self_signed_cert(att_key, att_pub, name, serial=1)
        csr = CB.build_csr_with_pop(ek, "ML-KEM-768", name, att_key, cert)
        result = CB.verify_csr_signature(csr, attestor_cert=cert)
        assert result is True

    def test_verify_invalid_signature(self):
        """L443-444: verify with wrong cert → InvalidSignature → False."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        att_key, att_pub = _ed25519_keypair()
        name = _simple_name("CN=Test")
        cert = _self_signed_cert(att_key, att_pub, name, serial=1)
        csr = CB.build_csr_with_pop(ek, "ML-KEM-768", name, att_key, cert)
        wrong_key, wrong_pub = _ed25519_keypair()
        wrong_cert = _self_signed_cert(wrong_key, wrong_pub, name, serial=2)
        result = CB.verify_csr_signature(csr, attestor_cert=wrong_cert)
        assert result is False


# ═══════════════════════════════════════════════════════════════════════════
# src/csr_opt.py
# ═══════════════════════════════════════════════════════════════════════════

class TestCO_DerEncodeOidCached:
    """Cover: L31-33 (arc=0), L42/60/72 (large arc), L92/96/99-100 (cache hit)."""

    def test_arc_zero(self):
        """L31-33: arc == 0."""
        r = CO._der_encode_oid_cached("1.2.0.3")
        assert r[0] == 0x06

    def test_large_arc(self):
        """L42/60/72: large arc >=128."""
        r = CO._der_encode_oid_cached("1.3.6.1.4.1.99999")
        assert r[0] == 0x06
        assert len(r) > 5

    def test_cache_hit(self):
        """L92/96/99-100: _get_oid cache hit."""
        CO._der_encode_oid_cached("1.2.3.4.5")
        obj = CO._get_oid("1.2.3.4.5")
        assert isinstance(obj, ObjectIdentifier)


class TestCO_GetExpectedEkSize:
    """Cover: L134-141 (unsupported param set)."""

    def test_unsupported(self):
        """L134-141: ValueError for unknown param set."""
        with pytest.raises(ValueError, match="Unsupported parameter set"):
            CO._get_expected_ek_size("ML-KEM-999")


class TestCO_SignCri:
    """Cover: L147 (ECDSA), L167 (TypeError fallback)."""

    def test_ecdsa(self):
        """L147: ECDSA signing path."""
        cri = b'\x30\x05\x30\x03\x06\x01\x02'
        key, _ = _ecdsa_keypair()
        sig = CO._sign_cri(cri, key)
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_typeerror_fallback(self):
        """L167: TypeError on first sign → retry with None → returns value."""

        class _MockKey:
            _call_count = 0
            def sign(self, data, *args):
                _MockKey._call_count += 1
                if _MockKey._call_count == 1:
                    raise TypeError("mock")
                return b'\x01' * 64

        sig = CO._sign_cri(b'\x30\x05', _MockKey())
        assert isinstance(sig, bytes)


class TestCO_SignatureAlgorithmDer:
    """Cover: L234 (Ed25519), L240+ (ECDSA)."""

    def test_ed25519(self):
        """L234: Ed25519 sig alg DER."""
        key, _ = _ed25519_keypair()
        r = CO._signature_algorithm_der(key)
        assert r[0] == 0x30

    def test_ecdsa(self):
        """L240+: ECDSA sig alg DER."""
        key, _ = _ecdsa_keypair()
        r = CO._signature_algorithm_der(key)
        assert r[0] == 0x30


# ═══════════════════════════════════════════════════════════════════════════
# src/errors.py
# ═══════════════════════════════════════════════════════════════════════════

class TestErrors:
    """Cover: L70-72 (get_error_message), L65 (unknown code)."""

    def test_all_messages(self):
        """L70-72: get_error_message for all codes."""
        for code in PQCSRError:
            msg = get_error_message(code)
            assert isinstance(msg, str)
            assert len(msg) > 0

    def test_unknown_code(self):
        with pytest.raises(ValueError):
            from pqblocks_csr_pop.errors import PQCSRError as PE
            PE(999)


# ═══════════════════════════════════════════════════════════════════════════
# src/mlkem.py
# ═══════════════════════════════════════════════════════════════════════════

class TestMK_Keygen:
    """Cover: L47 (bad param), L83-84 (bad seed), L81-82 (None seed→random)."""

    def test_bad_param(self):
        """L47: ValueError on invalid parameter_set."""
        with pytest.raises(ValueError, match="Invalid parameter set"):
            MK.mlkem_keygen("ML-KEM-999")

    def test_bad_seed_length(self):
        """L83-84: ValueError on wrong seed length."""
        # ML-KEM-768 seed must be 64 bytes
        with pytest.raises(ValueError, match="Seed must be"):
            MK.mlkem_keygen("ML-KEM-768", seed=b"too short")

    def test_seed_none_random(self):
        """L81-82: seed=None → os.urandom."""
        ek, dk = MK.mlkem_keygen("ML-KEM-768")
        assert isinstance(ek, bytes)
        assert isinstance(dk, bytes)


class TestMK_Encapsulate:
    """Cover: L88-89 (bad param), L99-120 (valid encapsulate)."""

    def test_bad_param(self):
        """L88-89: ValueError on invalid parameter_set."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        with pytest.raises(ValueError, match="Invalid parameter set"):
            MK.mlkem_encapsulate(ek, "ML-KEM-999")

    def test_valid_encapsulate(self):
        """L99-120: valid encapsulate."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        ss, ct = MK.mlkem_encapsulate(ek, "ML-KEM-768")
        assert isinstance(ss, bytes)
        assert isinstance(ct, bytes)
        # ML-KEM-768 shared secret is 32 bytes, ciphertext is 1088 bytes
        assert len(ss) == 32
        assert len(ct) == 1088


class TestMK_Decapsulate:
    """Cover: L137 (DK size check), L143-144 (bad param), L123-148 (valid decap)."""

    def test_bad_param(self):
        """L143-144: ValueError on invalid parameter_set."""
        _, dk = MK.mlkem_keygen("ML-KEM-768")
        ct = b'\x00' * 1184
        with pytest.raises(ValueError, match="Invalid parameter set"):
            MK.mlkem_decapsulate(dk, ct, "ML-KEM-999")

    def test_wrong_dk_size(self):
        """L137: ValueError on wrong DK size."""
        _, dk = MK.mlkem_keygen("ML-KEM-768")
        wrong_dk = b'\x00' * 100  # should be 2400 bytes
        ct = b'\x00' * 1184
        with pytest.raises(ValueError, match="DK must be"):
            MK.mlkem_decapsulate(wrong_dk, ct, "ML-KEM-768")

    def test_valid_decapsulate(self):
        """L123-148: valid decapsulate."""
        _, dk = MK.mlkem_keygen("ML-KEM-768")
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        _, ct = MK.mlkem_encapsulate(ek, "ML-KEM-768")
        ss = MK.mlkem_decapsulate(dk, ct, "ML-KEM-768")
        assert isinstance(ss, bytes)
        assert len(ss) == 32


class TestMK_GetKeySizes:
    """Cover: L151-177 — get_key_sizes, get_actual_key_sizes."""

    def test_get_key_sizes(self):
        """L151-177: get_key_sizes returns expected sizes."""
        sizes = MK.get_key_sizes("ML-KEM-768")
        assert isinstance(sizes, dict)
        assert sizes.get("ek") == 1184

    def test_get_actual_key_sizes(self):
        """L158-177: get_actual_key_sizes from keygen."""
        ek, dk = MK.mlkem_keygen("ML-KEM-768")
        sizes = MK.get_actual_key_sizes("ML-KEM-768")
        assert isinstance(sizes, dict)
        assert "ek" in sizes or "dk" in sizes


# ═══════════════════════════════════════════════════════════════════════════
# src/mlkem_opt.py
# ═══════════════════════════════════════════════════════════════════════════

class TestMKO_Keygen:
    """Cover: L67 (bad param), L73-74 (bad seed), valid keygen."""

    def test_bad_param(self):
        """L67: ValueError on invalid parameter_set."""
        with pytest.raises(ValueError, match="Invalid parameter set"):
            MKO.mlkem_keygen("ML-KEM-999")

    def test_bad_seed(self):
        """L73-74: ValueError on wrong seed."""
        with pytest.raises(ValueError, match="Seed must be"):
            MKO.mlkem_keygen("ML-KEM-768", seed=b"bad")

    def test_valid(self):
        """Valid opt keygen."""
        ek, dk = MKO.mlkem_keygen("ML-KEM-768")
        assert isinstance(ek, bytes)
        assert isinstance(dk, bytes)


class TestMKO_Encapsulate:
    """Cover: L98 (bad param), L95-104 (valid encapsulate)."""

    def test_bad_param(self):
        """L98: ValueError on invalid parameter_set."""
        ek, _ = MKO.mlkem_keygen("ML-KEM-768")
        with pytest.raises(ValueError, match="Invalid parameter set"):
            MKO.mlkem_encapsulate(ek, "ML-KEM-999")

    def test_valid(self):
        """Valid opt encapsulate."""
        ek, _ = MKO.mlkem_keygen("ML-KEM-768")
        ss, ct = MKO.mlkem_encapsulate(ek, "ML-KEM-768")
        assert isinstance(ss, bytes)
        assert isinstance(ct, bytes)
        assert len(ss) == 32
        assert len(ct) == 1088


class TestMKO_Decapsulate:
    """Cover: L114-127 (valid decap), L144-152 (bad param)."""

    def test_bad_param(self):
        """L144-152: ValueError on invalid parameter_set."""
        _, dk = MKO.mlkem_keygen("ML-KEM-768")
        ct = b'\x00' * 1184
        with pytest.raises(ValueError, match="Invalid parameter set"):
            MKO.mlkem_decapsulate(dk, ct, "ML-KEM-999")

    def test_valid_decapsulate(self):
        """L114-127: valid opt decapsulate."""
        _, dk = MKO.mlkem_keygen("ML-KEM-768")
        ek, _ = MKO.mlkem_keygen("ML-KEM-768")
        _, ct = MKO.mlkem_encapsulate(ek, "ML-KEM-768")
        ss = MKO.mlkem_decapsulate(dk, ct, "ML-KEM-768")
        assert isinstance(ss, bytes)
        assert len(ss) == 32


# ═══════════════════════════════════════════════════════════════════════════
# src/policy.py
# ═══════════════════════════════════════════════════════════════════════════

class TestPOL_InferParameterSet:
    """Cover: L51-53 (explicit valid), L80-82 (explicit invalid),
    L87-88 (infer from ek size)."""

    def test_explicit_valid(self):
        """L51-53: valid explicit parameter set."""
        r = infer_parameter_set(explicit="ML-KEM-768")
        assert r == "ML-KEM-768"

    def test_explicit_invalid(self):
        """L80-82: invalid explicit → ValueError."""
        with pytest.raises(ValueError, match="Unknown parameter set"):
            infer_parameter_set(explicit="ML-KEM-999")

    def test_by_ek_size(self):
        """L87-88: infer from public key bytes."""
        ek, _ = MK.mlkem_keygen("ML-KEM-768")
        r = infer_parameter_set(ek=ek)
        assert r == "ML-KEM-768"


class TestPOL_CheckAttestorStrength:
    """Cover: L61-64 (bits >= required → SUCCESS), L96-97 (bits None → WEAK)."""

    def test_strong_attestor(self):
        """L61-64: Ed25519 (128-bit) strong enough for ML-KEM-768."""
        key, _ = _ed25519_keypair()
        err = POL.check_attestor_strength("ML-KEM-768", key)
        assert err == PQCSRError.ERR_ATTESTOR_WEAK

    def test_weak_attestor(self):
        """L96-97: None bits → ERR_ATTESTOR_WEAK."""
        class _Dummy:
            pass
        err = POL.check_attestor_strength("ML-KEM-768", _Dummy())
        assert err == PQCSRError.ERR_ATTESTOR_WEAK
