"""
Equivalence test harness for ML-KEM PoP CSR construction.
Implements S.5: Integrate reference oracle and write equivalence test harness.

Tests that reference and optimized kernels are bit-identical when seeded,
and statistically equivalent when non-deterministic (KS-test p > 0.01).
"""

import pytest
import numpy as np
from scipy import stats

from pqblocks_csr_pop.mlkem import mlkem_keygen as ref_keygen
from pqblocks_csr_pop.mlkem import mlkem_encapsulate as ref_encap
from pqblocks_csr_pop.mlkem import mlkem_decapsulate as ref_decap
from pqblocks_csr_pop.mlkem import get_key_sizes as ref_get_sizes
from pqblocks_csr_pop.mlkem import get_actual_key_sizes as ref_get_actual_sizes

from pqblocks_csr_pop.mlkem_opt import mlkem_keygen as opt_keygen
from pqblocks_csr_pop.mlkem_opt import mlkem_encapsulate as opt_encap
from pqblocks_csr_pop.mlkem_opt import mlkem_decapsulate as opt_decap
from pqblocks_csr_pop.mlkem_opt import get_key_sizes as opt_get_sizes
from pqblocks_csr_pop.mlkem_opt import get_actual_key_sizes as opt_get_actual_sizes

from pqblocks_csr_pop.csr_builder import build_csr_with_pop as ref_build_csr
from pqblocks_csr_pop.csr_builder import verify_csr_signature as ref_verify_csr
from pqblocks_csr_pop.csr_opt import build_csr_with_pop as opt_build_csr
from pqblocks_csr_pop.csr_opt import verify_csr_signature as opt_verify_csr


class TestEquivalenceHarness:
    """Test harness for reference vs optimized kernel equivalence."""

    def test_keygen_bit_identical_mlkem1024(self):
        """Test that KeyGen with same seed produces bit-identical output."""
        seed = b"\x00" * 64
        
        ref_ek, ref_dk = ref_keygen("ML-KEM-1024", seed)
        opt_ek, opt_dk = opt_keygen("ML-KEM-1024", seed)
        
        assert ref_ek == opt_ek, "Reference and optimized ek must be bit-identical"
        assert ref_dk == opt_dk, "Reference and optimized dk must be bit-identical"

    def test_keygen_bit_identical_mlkem768(self):
        """Test that KeyGen with same seed produces bit-identical output for ML-KEM-768."""
        seed = b"\x00" * 64
        
        ref_ek, ref_dk = ref_keygen("ML-KEM-768", seed)
        opt_ek, opt_dk = opt_keygen("ML-KEM-768", seed)
        
        assert ref_ek == opt_ek, "Reference and optimized ek must be bit-identical"
        assert ref_dk == opt_dk, "Reference and optimized dk must be bit-identical"

    def test_keygen_bit_identical_multiple_seeds(self):
        """Test bit-identity across multiple seeds."""
        seeds = [
            b"\x00" * 64,
            b"\x01" * 64,
            b"\xff" * 64,
            bytes(range(64)),
        ]
        
        for seed in seeds:
            ref_ek, ref_dk = ref_keygen("ML-KEM-1024", seed)
            opt_ek, opt_dk = opt_keygen("ML-KEM-1024", seed)
            
            assert ref_ek == opt_ek, f"KeyGen not bit-identical for seed {seed.hex()}"
            assert ref_dk == opt_dk, f"KeyGen not bit-identical for seed {seed.hex()}"

    def test_key_sizes_equivalent(self):
        """Test that key size lookups are equivalent."""
        for param in ["ML-KEM-768", "ML-KEM-1024"]:
            ref_sizes = ref_get_sizes(param)
            opt_sizes = opt_get_sizes(param)
            
            assert ref_sizes == opt_sizes, f"Key sizes mismatch for {param}"

    def test_actual_key_sizes_equivalent(self):
        """Test that actual key size lookups are equivalent."""
        for param in ["ML-KEM-768", "ML-KEM-1024"]:
            ref_sizes = ref_get_actual_sizes(param)
            opt_sizes = opt_get_actual_sizes(param)
            
            assert ref_sizes == opt_sizes, f"Actual key sizes mismatch for {param}"

    def test_encapsulation_statistical_equivalence(self):
        """Test that encapsulation is statistically equivalent (KS-test p > 0.01).
        
        Since encapsulation uses randomness, we compare distributions
        of shared secret lengths and ciphertext lengths over multiple runs.
        """
        seed = b"\x00" * 64
        ref_ek, _ = ref_keygen("ML-KEM-1024", seed)
        opt_ek, _ = opt_keygen("ML-KEM-1024", seed)
        
        # Collect samples
        n_runs = 200
        ref_ss_lens = []
        ref_ct_lens = []
        opt_ss_lens = []
        opt_ct_lens = []
        
        for _ in range(n_runs):
            ref_ss, ref_ct = ref_encap(ref_ek, "ML-KEM-1024")
            opt_ss, opt_ct = opt_encap(opt_ek, "ML-KEM-1024")
            
            ref_ss_lens.append(len(ref_ss))
            ref_ct_lens.append(len(ref_ct))
            opt_ss_lens.append(len(opt_ss))
            opt_ct_lens.append(len(opt_ct))
        
        # All lengths should be constant
        assert all(l == 32 for l in ref_ss_lens), "Reference shared secret length should be 32"
        assert all(l == 1568 for l in ref_ct_lens), "Reference ciphertext length should be 1568"
        assert all(l == 32 for l in opt_ss_lens), "Optimized shared secret length should be 32"
        assert all(l == 1568 for l in opt_ct_lens), "Optimized ciphertext length should be 1568"
        
        # KS-test on shared secret content (should be uniform random)
        ref_ss_samples = []
        opt_ss_samples = []
        
        for _ in range(200):
            ref_ss, _ = ref_encap(ref_ek, "ML-KEM-1024")
            opt_ss, _ = opt_encap(opt_ek, "ML-KEM-1024")
            ref_ss_samples.append(int.from_bytes(ref_ss[:4], 'big'))
            opt_ss_samples.append(int.from_bytes(opt_ss[:4], 'big'))
        
        # KS-test for distribution similarity
        ks_stat, p_value = stats.ks_2samp(ref_ss_samples, opt_ss_samples)
        assert p_value > 0.01, f"KS-test failed: p={p_value}, expected > 0.01"

    def test_decapsulation_consistency(self):
        """Test that decapsulation produces consistent results."""
        seed = b"\x00" * 64
        
        # Generate keys with same seed
        ref_ek, ref_dk = ref_keygen("ML-KEM-1024", seed)
        opt_ek, opt_dk = opt_keygen("ML-KEM-1024", seed)
        
        # Keys should be identical
        assert ref_ek == opt_ek
        assert ref_dk == opt_dk
        
        # Encapsulate with reference, decapsulate with optimized and vice versa
        ref_ss, ref_ct = ref_encap(ref_ek, "ML-KEM-1024")
        opt_ss, opt_ct = opt_encap(opt_ek, "ML-KEM-1024")
        
        # Decapsulate reference ciphertext with optimized
        ss_cross1 = opt_decap(ref_dk, ref_ct, "ML-KEM-1024")
        assert ss_cross1 == ref_ss, "Optimized decap should match reference encap"
        
        # Decapsulate optimized ciphertext with reference
        ss_cross2 = ref_decap(opt_dk, opt_ct, "ML-KEM-1024")
        assert ss_cross2 == opt_ss, "Reference decap should match optimized encap"


class TestReferenceOracleIntegration:
    """Integration tests for the reference oracle."""

    def test_reference_keygen_deterministic(self):
        """Test that reference KeyGen is deterministic with same seed."""
        seed = b"\x00" * 64
        
        ek1, dk1 = ref_keygen("ML-KEM-1024", seed)
        ek2, dk2 = ref_keygen("ML-KEM-1024", seed)
        
        assert ek1 == ek2, "Reference KeyGen should be deterministic"
        assert dk1 == dk2, "Reference KeyGen should be deterministic"

    def test_reference_encapsulation_deterministic(self):
        """Test that reference encapsulation produces consistent structure."""
        seed = b"\x00" * 64
        ek, _ = ref_keygen("ML-KEM-1024", seed)
        
        ss1, ct1 = ref_encap(ek, "ML-KEM-1024")
        ss2, ct2 = ref_encap(ek, "ML-KEM-1024")
        
        # Different runs should produce different ciphertexts (randomized)
        assert ct1 != ct2, "Encapsulation should be randomized"
        assert len(ss1) == len(ss2) == 32
        assert len(ct1) == len(ct2) == 1568

    def test_reference_decapsulation_deterministic(self):
        """Test that reference decapsulation is deterministic for same input."""
        seed = b"\x00" * 64
        ek, dk = ref_keygen("ML-KEM-1024", seed)
        
        ss, ct = ref_encap(ek, "ML-KEM-1024")
        
        # Decapsulate twice
        ss1 = ref_decap(dk, ct, "ML-KEM-1024")
        ss2 = ref_decap(dk, ct, "ML-KEM-1024")
        
        assert ss1 == ss2, "Decapsulation should be deterministic for same input"
        assert ss1 == ss, "Decapsulation should recover shared secret"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestCSRKernelEquivalence:
    """Reference vs optimized CSR kernel: seeded bit-identity (S.5 contract)."""

    def _make_cert(self):
        import datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.asymmetric import ed25519

        sk = ed25519.Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
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

    def test_csr_bit_identical_seeded(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        seed = b"\x42" * 64
        ref_ek, _ = ref_keygen("ML-KEM-1024", seed)
        opt_ek, _ = opt_keygen("ML-KEM-1024", seed)
        assert ref_ek == opt_ek
        cert, sk = self._make_cert()
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")]
        )
        ref_csr = ref_build_csr(ref_ek, "ML-KEM-1024", subject, sk, cert)
        opt_csr = opt_build_csr(opt_ek, "ML-KEM-1024", subject, sk, cert)
        assert ref_csr == opt_csr, "CSR kernels must be bit-identical when seeded"
        assert ref_verify_csr(ref_csr, cert) is True
        assert opt_verify_csr(opt_csr, cert) is True

    def test_csr_cross_verify(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        seed = b"\x07" * 64
        ek, _ = ref_keygen("ML-KEM-768", seed)
        cert, sk = self._make_cert()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cross.test")])
        ref_csr = ref_build_csr(ek, "ML-KEM-768", subject, sk, cert)
        assert opt_verify_csr(ref_csr, cert) is True
        opt_csr = opt_build_csr(ek, "ML-KEM-768", subject, sk, cert)
        assert ref_verify_csr(opt_csr, cert) is True