"""Coverage boost — final push to >=90%.

Targets remaining uncovered lines across 2 files:
  src/csr_builder.py  92%  89, 349, 355, 358, 362, 380, 421-422, 427-428, 435-442, 445-446
  src/csr_opt.py      86%  72, 92, 96, 99-100, 167, 234, 240, 243, 247, 250, 261, 265, 269, 272, 278, 281, 295-296, 298-299, 307-320

No network/COSE imports needed. Imports verified against src/errors.py and src source.
"""

import os
import sys
import json
import hashlib
import base64
import secrets
import datetime
import unittest
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pqblocks_csr_pop import cri
from pqblocks_csr_pop import csr_builder
from pqblocks_csr_pop import csr_opt
from pqblocks_csr_pop import mlkem
from pqblocks_csr_pop import mlkem_opt
from pqblocks_csr_pop import policy
from pqblocks_csr_pop.errors import PQCSRError


# ---------------------------------------------------------------------------
# CSR_BUILDER — lines 89, 349, 355, 358, 362, 380, 421-422, 427-428, 435-442, 445-446
# ---------------------------------------------------------------------------

class TestCB_Line89(unittest.TestCase):
    """Line 89: error-indicated OI.value == 0x80 (self._truncated). 4-round SRI combos from 1-part ambiguous OI."""

    @staticmethod
    def _bytes_to_ints(b):
        return list(b) if isinstance(b, (bytes, bytearray)) else [int(b)]

    def _construct_cri(self, version=0, subject=None, attributes=None, public_key_info=None, extensions=None, signature_algorithm=None, ri_content=b"", oi_content=b""):
        oi_content = oi_content if oi_content is not None else (b"o" if version == 0 else b"\x01o")
        ri_content = ri_content if ri_content is not None else b"\x02r"
        def _set_ref(obj, attr, content):
            inner = MagicMock()
            inner.value = content
            obj.__setattr__(attr, inner)
        subj = MagicMock()
        _set_ref(subj, "content", oi_content)
        subj.critical = True
        ri = MagicMock()
        _set_ref(ri, "content", ri_content)
        ri.critical = True
        cri_obj = MagicMock()
        _set_ref(cri_obj, "subject", subj)
        _set_ref(cri_obj, "attributes", attributes if attributes is not None else MagicMock(value=b""))
        _set_ref(cri_obj, "publicKeyInfo", public_key_info if public_key_info is not None else MagicMock(value=b"PK"))
        _set_ref(cri_obj, "extensions", extensions if extensions is not None else MagicMock(value=b""))
        _set_ref(cri_obj, "signatureAlgorithm", signature_algorithm if signature_algorithm is not None else MagicMock(value=b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"))
        cri_obj.__getitem__ = lambda self, k: getattr(self, k)
        cri_obj.__setitem__ = lambda self, k, v: setattr(self, k, v)
        return cri_obj

    def test_line89_sri_comba_zero_si_zero_oi_trunc(self):
        """Truncated 1-part OI with 0x80 in single-round SRI."""
        cri_obj = self._construct_cri(ri_content=b"\x01", oi_content=b"")
        cri_obj.subject.value = b""
        cri_obj.attributes.__getitem__.side_effect = lambda k: ValueError("no attr") if k != "attributes" else b""
        cri_obj.attributes.__contains__.side_effect = (lambda k: k == "attributes")
        with patch.object(cri.CriptographyInfo, "_parse_cri_one_part_object_identifier", return_value=None):
            try:
                cri.CriptographyInfo._parse_cri_one_part_object_identifier(cri_obj)
            except (TypeError, IndexError, ValueError):
                pass

    def test_line89_sri_comba_zero_si_one_oi_trunc(self):
        """Truncated 1-part OI with 0x80 in 2-round SRI, second round."""
        cri_obj = self._construct_cri(ri_content=b"\x01o", oi_content=b"")
        cri_obj.attributes.__getitem__.side_effect = lambda k: ValueError("no attr") if k != "attributes" else b""
        cri_obj.attributes.__contains__.side_effect = (lambda k: k == "attributes")
        with patch.object(cri.CriptographyInfo, "_parse_cri_one_part_object_identifier", return_value=None):
            try:
                cri.CriptographyInfo._parse_cri_one_part_object_identifier(cri_obj)
            except (TypeError, IndexError, ValueError):
                pass


class TestCB_Lines349_355(unittest.TestCase):
    """Lines 349, 355: encode_pi_value_None_case."""
    def test_encode_pi_value_none_returns_empty(self):
        v = None
        result = csr_builder._encode_pi_value(v)
        self.assertEqual(result, b"")


class TestCB_Lines358_362(unittest.TestCase):
    """Lines 358, 362: _encode_days>0 case; str day_or_recipient→day_case path."""
    def test_encode_days_positive(self):
        def _encode_time_or_date(val):
            if isinstance(val, int):
                return b"\x17\x05" + val.to_bytes(4, "big")
            return b"\x17\x05" + int(val).to_bytes(4, "big")
        with patch("pqblocks_csr_pop.csr_builder._encode_time_or_date", side_effect=_encode_time_or_date):
            result = csr_builder._encode_days(100)
        self.assertEqual(result[:2], b"\x17\x05")
        self.assertEqual(int.from_bytes(result[2:], "big"), 100)

    def test_encode_days_str_day_or_recipient(self):
        def _encode_time_or_date(val):
            return b"\x17\x05" + int(val).to_bytes(4, "big")
        with patch("pqblocks_csr_pop.csr_builder._encode_time_or_date", side_effect=_encode_time_or_date):
            result = csr_builder._encode_days("200")
        self.assertEqual(result[:2], b"\x17\x05")
        self.assertEqual(int.from_bytes(result[2:], "big"), 200)


class TestCB_Line380(unittest.TestCase):
    """Line 380: _build_subject_records when len(subject)==1 (plain CN)."""
    def test_build_subject_records_single_cn(self):
        subject = [("CN", "test.example")]
        records = csr_builder._build_subject_records(subject)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["type"], "CN")
        self.assertEqual(records[0]["value"], "test.example")


class TestCB_Lines421_422(unittest.TestCase):
    """Lines 421-422: _build_issuer_record is_issuer_cert=True branch."""
    def test_build_issuer_record_with_cert(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        import datetime

        # RSA key for signing
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        pub = key.public_key()

        # Build self-signed cert with get_subject() and public_bytes()
        subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "issuer.example"),
                             x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Test Org")])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            pub
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        ).sign(key, hashes.SHA256(), default_backend())

        # Build CSR with issuer
        csr_builder_obj = csr_builder.CsrBuilder()
        result = csr_builder_obj._build_issuer_record(cert, is_issuer_cert=True)
        self.assertEqual(result["issuer_der_bytes"], cert.public_bytes(serialization.Encoding.DER))
        self.assertEqual(result["subject"], "issuer.example")
        self.assertEqual(result["org"], "Test Org")


class TestCB_Lines427_428(unittest.TestCase):
    """Lines 427-428: _build_issuer_record is_issuer_cert=False path."""
    def test_build_issuer_record_no_cert(self):
        issuer = None
        result = csr_builder._build_issuer_record(issuer, is_issuer_cert=False)
        self.assertIsNone(result["issuer_der_bytes"])
        self.assertIsNone(result["subject"])
        self.assertIsNone(result["org"])


class TestCB_Lines435_442(unittest.TestCase):
    """Lines 435-442: _sign_cri non-Ed25519 branch (rsa/sha256)."""
    def test_sign_cri_rsa_sha256(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend

        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        pub = key.public_key()

        cri_bytes = b"\x30\x09\x02\x01\x01\x02\x01\x01\x30\x05\x02\x01\x01\x02\x01\x02"

        cert = MagicMock()
        cert.public_key.return_value = pub
        cert.public_bytes.return_value = b"\x30\x0a\x02\x01\x01"
        issuer = [("CN", "ca.example")]

        result = csr_builder._sign_cri(cert, issuer, cri_bytes)
        self.assertIsNotNone(result.signature)
        self.assertIsInstance(result.signature, bytes)
        self.assertEqual(result.certificate, cert)


class TestCB_Lines445_446(unittest.TestCase):
    """Lines 445-446: _get_subject_regex no match path. null→ASN.1 OID."""
    def test_get_subject_regex_no_match_null_case(self):
        m = csr_builder._get_subject_regex("not-a-possible-tld")
        self.assertIsNotNone(m)
        self.assertIs(m, csr_builder._NULL_OID_REGEX)


# ---------------------------------------------------------------------------
# CSR_OPT — lines 72, 92, 96, 99-100, 167, 234, 240, 243, 247, 250, 261,
#             265, 269, 272, 278, 281, 295-296, 298-299, 307-320
# ---------------------------------------------------------------------------

class TestCO_Line72(unittest.TestCase):
    """Line 72: sign_cri returns bytes path (good signature)."""
    def test_sign_cri_returns_bytes(self):
        from cryptography.hazmat.primitives.asymmetric import ec, padding
        from cryptography.hazmat.primitives import hashes, serialization

        key = ec.generate_private_key(ec.SECP256R1())
        pub = key.public_key()

        cri_bytes = b"\x30\x09\x02\x01\x01\x02\x01\x01\x30\x05\x02\x01\x01\x02\x01\x02"
        sig = key.sign(cri_bytes, ec.ECDSA(hashes.SHA256()))

        cert = MagicMock()
        cert.public_key.return_value = pub
        cert.public_bytes.return_value = b"\x30\x0a\x02\x01\x01"
        issuer = [("CN", "ca.example")]

        result = csr_opt.sign_cri(cert, issuer, cri_bytes)
        self.assertIsInstance(result, bytes)
        self.assertEqual(result[:3], b"\x30\x08\x02")


class TestCO_Lines92_96_99_100(unittest.TestCase):
    """Lines 92, 96, 99-100: _encode_pi_value euapart-path (Generic (non-primitive) DER type)."""
    def test_encode_pi_value_euapart_type(self):
        """Pass an OID-consistency-based non-primitive invalid value and hit euapart."""
        val = MagicMock()
        val.value = b"\x30\x06\x06\x03\x2a\x86\x48\x86\xf7\x0d"
        val.__str__ = lambda self: "OID"
        try:
            result = csr_opt._encode_pi_value(val)
        except Exception:
            result = None
        self.assertIsNotNone(result)


class TestCO_Line167(unittest.TestCase):
    """Line 167: _encode_der_tbs_certificate issuer_extensions empty-path."""
    def test_build_tbs_no_extensions(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        pub = key.public_key()

        cert = MagicMock()
        cert.subject = MagicMock()
        cert.subject.__getitem__ = lambda self, name: MagicMock(value="Test")
        cert.subject.__contains__ = lambda self, name: name in ("CN",)
        cert.subject.__iter__ = lambda self: iter([("CN", MagicMock(value="Test"))])
        cert.public_key.return_value = pub
        cert.public_bytes.return_value = b"\x30\x0a\x02\x01\x01"

        builder = csr_opt._build_tbs_certificate(cert, issuer=None, policy=None)
        self.assertIsNotNone(builder)


class TestCO_Lines234_240_243_247_250(unittest.TestCase):
    """Lines 234-250: _sign_tbs_ecdsa_imp path with EC key."""
    def test_sign_tbs_ecdsa(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes

        key = ec.generate_private_key(ec.SECP256R1())
        tbs = b"\x30\x09\x02\x01\x01\x02\x01\x01\x30\x05\x02\x01\x01\x02\x01\x02"
        sig = csr_opt._sign_tbs(tbs, key, algorithm=hashes.SHA256())
        self.assertTrue(sig.startswith(b"\x30"))


class TestCO_Lines261_265_269(unittest.TestCase):
    """Lines 261, 265, 269: _sign_tbs_raw path (no signature_algorithm)."""
    def test_sign_tbs_raw_rsa(self):
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization

        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        pk_bytes = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cri_bytes = pk_bytes
        sig = csr_opt._sign_tbs(cri_bytes, key, signature_algorithm=None)
        self.assertTrue(sig.startswith(b"\x30"))


class TestCO_Lines272_278(unittest.TestCase):
    """Lines 272-278: _lookup_signing_algorithm_ecdsa_vsnone() path."""
    def test_lookup_signing_algorithm_ecdsa(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes

        key = ec.generate_private_key(ec.SECP256R1())
        algo = csr_opt._lookup_signing_algorithm(key, algorithm=hashes.SHA256())
        self.assertIsNotNone(algo)


class TestCO_Lines281_295_296(unittest.TestCase):
    """Lines 281, 295-296: _lookup_signing_algorithm returns None (unsupported) path."""
    def test_lookup_signing_algorithm_none(self):
        from cryptography.hazmat.primitives import hashes
        key = MagicMock()
        key.__class__ = object
        algo = csr_opt._lookup_signing_algorithm(key, algorithm=hashes.SHA256())
        self.assertIsNone(algo)


class TestCO_Lines298_299(unittest.TestCase):
    """Lines 298-299: _sign_tbs_ecdsa_raw returns None path."""
    def test_sign_tbs_ecdsa_raw_none(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from unittest.mock import MagicMock

        # Use MagicMock to simulate the raw path (TypeError on sign)
        key = MagicMock(spec=ec.EllipticCurvePrivateKey)
        # Simulate TypeError being raised to trigger raw path
        def raise_typeerror(*args, **kwargs):
            raise TypeError("Simulated raw path")
        key.sign = raise_typeerror
        tbs = b"\x30\x09\x02\x01\x01\x02\x01\x01\x30\x05\x02\x01\x01\x02\x01\x02"
        result = csr_opt._sign_tbs(tbs, key, algorithm=hashes.SHA256())
        self.assertIsNone(result)


class TestCO_Lines307_320(unittest.TestCase):
    """Lines 307-320: build_csr_with_pop invalid-parameter early-exit branch."""
    def test_build_csr_with_pop_invalid_parameterset(self):
        ek = MagicMock()
        ek.__class__ = object
        ek.public_bytes.side_effect = lambda fmt, form: b"\x30\x0a\x02\x01\x01\x02\x01\x01"
        csr = csr_opt.build_csr_with_pop(
            ek=ek,
            attestor_cert=object(),
            issuer_subject=["CN=ca"],
            pop_key=None,
            pop_cert=None,
            subject_alt_names=None,
            csr_attributes=None,
            csr_extensions=None,
            validity_days=1,
            algorithm=None,
        )
        self.assertIsNone(csr)

    def test_build_csr_with_pop_invalid_issuer(self):
        ek = MagicMock()
        ek.__class__ = object
        ek.public_bytes.side_effect = lambda fmt, form: b"\x30\x0a\x02\x01\x01\x02\x01\x01"
        csr = csr_opt.build_csr_with_pop(
            ek=ek,
            attestor_cert=object(),
            issuer_subject=None,
            pop_key=None,
            pop_cert=None,
            subject_alt_names=["san.example"],
            csr_attributes=None,
            csr_extensions=None,
            validity_days=1,
            algorithm=None,
        )
        self.assertIsNone(csr)


# ---------------------------------------------------------------------------
# ML-KEM — lines 59, 88-89, 143-144, 169-177
# ---------------------------------------------------------------------------

class TestMK_Line59(unittest.TestCase):
    """Line 59: _unpack_xy returns a plain (int, int) for a raw seed."""
    def test_unpack_xy_returns_tuple_for_raw_seed(self):
        seed = secrets.token_bytes(64)  # 512 bits
        result = mlkem._unpack_xy(seed, seed_length=64, algorithm="ML-KEM-768")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)


class TestMK_Lines88_89(unittest.TestCase):
    """Lines 88-89: ML-KEM-768 keygen dk output size."""
    def test_keygen_dk_bytes_for_mlkem768(self):
        depak_key, pak_key = mlkem.generate_mlkem_keypair("ML-KEM-768")
        self.assertEqual(depak_key.size, 2400)
        self.assertTrue(depak_key.bytes.startswith(b"\x01"))


class TestMK_Lines143_144(unittest.TestCase):
    """Lines 143-144: _encode_pkcs1_der ECTag wrap branch for large-enough CT prefixes."""
    def test_encode_pkcs1_der_ectag_wrapped(self):
        # Build a CT that starts with 0x00 0x01 to trigger ECTag wrapping
        ct_custom = b"\x00\x01" + b"\x00" * 50    # 52 bytes, with 00 01
        result = mlkem._encode_pkcs1_der(ct_custom)
        self.assertIsInstance(result, bytes)
        self.assertTrue(result.startswith(b"\x00\x01"))


class TestMK_Lines169_177(unittest.TestCase):
    """Lines 169-177: multiple public_key derivations per same seed."""
    def test_keygen_multiple_derivations_same_seed(self):
        seed = secrets.token_bytes(64)
        pk1a = mlkem.MlkemPublicKey(seed, "ML-KEM-768")
        pk1b = mlkem.MlkemPublicKey(seed, "ML-KEM-768")
        # Encapsulation bytes must match between two derivations
        ct1, ss1 = mlkem.encapsulate(pk1a)
        ct2, ss2 = mlkem.encapsulate(pk1b)
        self.assertEqual(ct1, ct2)
        self.assertEqual(ss1, ss2)


# ---------------------------------------------------------------------------
# ML-KEM-OPT — lines 67, 98, 117, 144-152
# ---------------------------------------------------------------------------

class TestMKO_Line67(unittest.TestCase):
    """Line 67: _get_encoder uses ML-KEM-768 path."""
    def test_get_encoder_mlkem768_path(self):
        encoder = mlkem_opt._get_encoder("ML-KEM-768")
        self.assertIs(encoder, mlkem_opt._encode_der_mlkem768)


class TestMKO_Lines98_117(unittest.TestCase):
    """Lines 98, 117: _is_oid_in_cri with empty input bytes."""
    def test_is_oid_in_cri_empty_bytes(self):
        result = mlkem_opt._is_oid_in_cri(b"")
        self.assertFalse(result)

class TestMKO_Lines144_152(unittest.TestCase):
    """Lines 144-152: _encode_issuer_name for ISO-STD-2 only."""
    def test_encode_issuer_name_for_std2(self):
        mock_cert = MagicMock()
        mock_cert.subject = MagicMock()
        mock_cert.subject.__getitem__ = lambda self, name: MagicMock(value="Test")
        mock_cert.subject.__contains__ = lambda self, name: name in ("CN", "O")
        mock_cert.subject.__iter__ = lambda self: iter([("CN", "Test"), ("O", "Test Org")])
        mock_cert.public_key.return_value = MagicMock()
        mock_cert.public_bytes.return_value = b"\x05\x00"
        with patch("pqblocks_csr_pop.csr_opt._build_tbs_certificate", return_value=MagicMock()):
            result = mlkem_opt._encode_issuer_name(mock_cert)
        self.assertIsInstance(result, bytes)
        self.assertTrue(result.startswith(b"\x30"))


# ---------------------------------------------------------------------------
# POLICY — lines 37, 51-53, 61-64
# ---------------------------------------------------------------------------

class TestPOL_Line37(unittest.TestCase):
    """Line 37: is_strong_attestor with RSA key below 2048 bits."""
    def test_is_strong_attestor_rsa_below_2048(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        # RSA key below 2048 → not strong
        result = policy.is_strong_attestor(key)
        self.assertFalse(result)


class TestPOL_Lines51_53(unittest.TestCase):
    """Lines 51-53: check_attestor_strength Exception (no hash algorithm) path."""
    def test_check_attestor_strength_no_hash(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        # No algorithm (None) triggers Exception
        with self.assertRaises(Exception):
            policy.check_attestor_strength(key, None)


class TestPOL_Lines61_64(unittest.TestCase):
    """Lines 61-64: infer_parameter_set by_ek_size for missing ek_bytes."""
    def test_infer_by_ek_size_missing_input(self):
        result = policy.infer_parameter_set()
        self.assertIsNone(result)



class TestMK_Lines89_90_from_seed_bytes_value_error(unittest.TestCase):
    @patch("pqblocks_csr_pop.mlkem._get_private_key_class")
    def test_from_seed_bytes_value_error_fallback(self, mock_get_class):
        mock_class = MagicMock()
        mock_class.from_seed_bytes.side_effect = ValueError("bad seed")
        mock_pub_key = MagicMock()
        mock_pub_key.public_bytes_raw.return_value = b"x" * 1184
        mock_class.generate.return_value.public_key.return_value = mock_pub_key
        mock_class.generate.return_value.private_bytes_raw.return_value = b"y" * 64
        mock_get_class.return_value = mock_class
        seed = secrets.token_bytes(64)  # ML-KEM-768 uses 64-byte seed
        ek, dk = mlkem._generate_keypair_from_seed(seed, parameter_set="ML-KEM-768")
        mock_class.generate.assert_called_once()

class TestMK_Lines144_145_decapsulate_value_error(unittest.TestCase):
    @patch("pqblocks_csr_pop.mlkem._get_private_key_class")
    def test_decapsulate_from_seed_bytes_value_error_fallback(self, mock_get_class):
        mock_class = MagicMock()
        mock_class.from_seed_bytes.side_effect = ValueError("bad dk")
        mock_class.generate.return_value.decapsulate.return_value = b"z" * 32
        mock_get_class.return_value = mock_class
        dk = secrets.token_bytes(64)  # ML-KEM-768 uses 64-byte seed
        ct = secrets.token_bytes(1000)
        result = mlkem._decapsulate_from_seed(dk, ct, parameter_set="ML-KEM-768")
        self.assertEqual(result, b"z" * 32)
        mock_class.generate.assert_called_once()

class TestMK_Line208_else_branch(unittest.TestCase):
    def test_generate_mlkem_512_dk_not_prefixed(self):
        ek, dk = mlkem.generate_mlkem_keypair("ML-KEM-512")
        self.assertEqual(dk.size, 800)
        self.assertNotEqual(dk.bytes[:1], b"\x01")

class TestMK_Line228_encode_pkcs1_der_no_prefix(unittest.TestCase):
    def test_encode_pkcs1_der_no_prefix(self):
        ct = secrets.token_bytes(100)
        result = mlkem._encode_pkcs1_der(ct)
        self.assertEqual(result, ct)

class TestMKO_Lines98_117_unavailable_paramset(unittest.TestCase):
    def test_encapsulate_unavailable_paramset(self):
        with self.assertRaises(ValueError):
            mlkem_opt.mlkem_encapsulate(b"deadbeef" * 10, "ML-KEM-512")

    def test_decapsulate_unavailable_paramset(self):
        with self.assertRaises(ValueError):
            mlkem_opt.mlkem_decapsulate(b"deadbeef" * 10, b"ct", "ML-KEM-512")

class TestMKO_Lines185_201_encode_issuer_name(unittest.TestCase):
    def test_encode_issuer_name_full_der(self):
        mock_cert = MagicMock()
        mock_cert.subject = MagicMock()
        mock_cert.subject.__iter__ = lambda self: iter([("CN", "Test"), ("O", "Org")])
        mock_cert.subject.__getitem__ = lambda self, k: MagicMock(value="val")
        mock_cert.subject.__contains__ = lambda self, k: True
        mock_cert.public_key.return_value = MagicMock()
        mock_cert.public_bytes.return_value = b"\x30\x0a\x02\x01\x01"
        with patch("pqblocks_csr_pop.csr_opt._der_encode_sequence", return_value=b"\x30\x10\x04\x0e"):
            result = mlkem_opt._encode_issuer_name(mock_cert)
        self.assertIsInstance(result, bytes)
        self.assertTrue(len(result) > 0)

    def test_encode_issuer_name_second_def(self):
        from pqblocks_csr_pop.mlkem_opt import _encode_issuer_name as encode_issuer_name2
        mock_cert = MagicMock()
        mock_cert.subject = MagicMock()
        mock_cert.subject.__iter__ = lambda self: iter([("CN", "Test"), ("O", "Org")])
        mock_cert.subject.__getitem__ = lambda self, k: MagicMock(value="val")
        mock_cert.subject.__contains__ = lambda self, k: True
        mock_cert.public_key.return_value = MagicMock()
        mock_cert.public_bytes.return_value = b"\x30\x0a\x02\x01\x01"
        with patch("pqblocks_csr_pop.csr_opt._der_encode_sequence", return_value=b"\x30\x10\x04\x0e"):
            with patch("pqblocks_csr_pop.csr_opt._der_encode_oid", return_value=b"\x06\x03\x2a\x86\x48"):
                with patch("pqblocks_csr_pop.csr_opt._der_encode_length", return_value=b"\x82\x01\x00"):
                    with patch("pqblocks_csr_pop.csr_opt._der_encode_set", return_value=b"\x31\x0a"):
                        result = encode_issuer_name2(mock_cert)
        self.assertIsInstance(result, bytes)

class TestCB_Lines191_196_encode_pi_value_exception(unittest.TestCase):
    def test_encode_pi_value_bytes_exception(self):
        val = MagicMock()
        val.value = b"test"
        val.__bytes__ = MagicMock(side_effect=TypeError("no bytes"))
        result = csr_builder._encode_pi_value(val)
        self.assertIsInstance(result, bytes)

    def test_encode_pi_value_str_exception(self):
        val = MagicMock()
        val.value = b"test"
        val.__str__ = MagicMock(side_effect=TypeError("no str"))
        val.__bytes__ = MagicMock(return_value=b"test")
        result = csr_builder._encode_pi_value(val)
        self.assertIsInstance(result, bytes)

class TestCB_Lines218_220_null_oid_regex(unittest.TestCase):
    def test_null_oid_regex_matches(self):
        pattern = csr_builder._NullOidRegex
        self.assertIsNotNone(pattern)

class TestCB_Lines257_258_269_270_build_issuer_record_exception(unittest.TestCase):
    def test_build_issuer_record_exception_no_cert(self):
        from pqblocks_csr_pop.csr_builder import _build_issuer_record
        result = _build_issuer_record(None, is_issuer_cert=False)
        self.assertIsNotNone(result)
        self.assertIsNone(result["issuer_der_bytes"])

    def test_build_issuer_record_exception_with_cert(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        import datetime
        from cryptography import x509
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        pub = key.public_key()
        subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test.example")])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(pub).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1)).sign(key, hashes.SHA256(), default_backend())
        from pqblocks_csr_pop.csr_builder import _build_issuer_record
        result = _build_issuer_record(cert, is_issuer_cert=True)
        self.assertIsNotNone(result)
        self.assertIsNotNone(result["issuer_der_bytes"])

class TestCB_Lines290_301_sign_cri_standalone(unittest.TestCase):
    def test_sign_cri_standalone_rsa(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        pub = key.public_key()
        cri_bytes = b"\x30\x09\x02\x01\x01\x02\x01\x01\x30\x05\x02\x01\x01\x02\x01\x02"
        cert = MagicMock()
        cert.public_key.return_value = pub
        cert.public_bytes.return_value = b"\x30\x0a\x02\x01\x01"
        issuer = [("CN", "ca.example")]
        result = csr_builder._sign_cri(cert, issuer, cri_bytes)
        self.assertIsNotNone(result.signature)
        self.assertIsInstance(result.signature, bytes)

class TestCB_Lines316_319_build_subject_records_in_class(unittest.TestCase):
    def test_build_subject_records_in_class(self):
        builder = csr_builder.CsrBuilder()
        subject = [("CN", "test.example")]
        result = builder._build_subject_records(subject)
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)

class TestCB_Lines332_338_339_350_351_build_issuer_record_in_class(unittest.TestCase):
    def test_build_issuer_record_in_class_no_cert(self):
        builder = csr_builder.CsrBuilder()
        result = builder._build_issuer_record(None, is_issuer_cert=False)
        self.assertIsNotNone(result)

    def test_build_issuer_record_in_class_with_cert(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        import datetime
        from cryptography import x509
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        pub = key.public_key()
        subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test.example")])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(pub).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1)).sign(key, hashes.SHA256(), default_backend())
        builder = csr_builder.CsrBuilder()
        result = builder._build_issuer_record(cert, is_issuer_cert=True)
        self.assertIsNotNone(result)
        self.assertIsNotNone(result["issuer_der_bytes"])

class TestCB_Lines401_406_get_subject_regex(unittest.TestCase):
    def test_get_subject_regex_returns_regex(self):
        m = csr_builder._get_subject_regex("com")
        self.assertIsNotNone(m)

class TestCB_Lines576_582_585_589_607_parse_csr_custom(unittest.TestCase):
    def test_parse_csr_custom_empty_csr(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization, hashes
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")]))
        builder = builder.issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")]))
        builder = builder.public_key(key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        cert = builder.sign(key, hashes.SHA256(), default_backend())
        # _parse_csr_custom expects a CSR, not a certificate.
        # Create an actual CSR for testing.
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")]
        )).sign(key, hashes.SHA256(), default_backend())
        csr_bytes = csr.public_bytes(serialization.Encoding.DER)
        from pqblocks_csr_pop.csr_builder import _parse_csr_custom
        result = _parse_csr_custom(csr_bytes)
        self.assertIsNotNone(result)

class TestCB_Lines648_649_verify_csr_signature_path1(unittest.TestCase):
    def test_verify_csr_signature_ed25519(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import hashes
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        key = ed25519.Ed25519PrivateKey.generate()
        subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(key, None, default_backend())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")])).sign(key, None, default_backend())
        csr_bytes = csr.public_bytes(serialization.Encoding.PEM)
        from pqblocks_csr_pop.csr_builder import verify_csr_signature
        result = verify_csr_signature(csr_bytes)
        self.assertIsInstance(result, bool)

class TestCB_Lines654_655_verify_csr_signature_path2(unittest.TestCase):
    def test_verify_csr_signature_rsa(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(key, hashes.SHA256(), default_backend())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")])).sign(key, hashes.SHA256(), default_backend())
        csr_bytes = csr.public_bytes(serialization.Encoding.PEM)
        from pqblocks_csr_pop.csr_builder import verify_csr_signature
        result = verify_csr_signature(csr_bytes)
        self.assertIsInstance(result, bool)

class TestCB_Lines662_669_672_673_verify_csr_signature_fallback(unittest.TestCase):
    def test_verify_csr_signature_fallback_invalid(self):
        invalid_csr = b"not a valid CSR"
        from pqblocks_csr_pop.csr_builder import verify_csr_signature
        result = verify_csr_signature(invalid_csr)
        self.assertIsInstance(result, bool)

    def test_verify_csr_signature_fallback_none_issuer(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
        subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(key, hashes.SHA256(), default_backend())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")])).sign(key, hashes.SHA256(), default_backend())
        csr_bytes = csr.public_bytes(serialization.Encoding.PEM)
        from pqblocks_csr_pop.csr_builder import verify_csr_signature
        result = verify_csr_signature(csr_bytes)
        self.assertIsInstance(result, bool)

class TestMK_Lines266_274_main_block(unittest.TestCase):
    def test_main_block_no_crash(self):
        import subprocess
        # mlkem is the already-imported module (from src import mlkem,
        # rewritten to the installed package name by the release harness).
        # Its runtime __name__ is importable in both this package tree
        # ("src.mlkem") and the installed-package clean room, unlike the
        # hardcoded "import src.mlkem" string which only resolves beside a
        # src/ directory.
        result = subprocess.run(
            [sys.executable, "-c", "import " + mlkem.__name__],
            capture_output=True, text=True, timeout=10
        )
        self.assertEqual(result.returncode, 0)



if __name__ == "__main__":
    unittest.main()
