"""
Tests for ML-KEM key generation and encapsulation.
"""
import pytest
from pqblocks_csr_pop.mlkem import mlkem_keygen, mlkem_encapsulate, mlkem_decapsulate, get_key_sizes, get_actual_key_sizes


class TestMLKEMKeygen:
    """Test ML-KEM key generation per FIPS 203."""
    
    def test_mlkem_1024_keygen_random(self):
        """Test ML-KEM-1024 key generation with random seed."""
        ek, dk = mlkem_keygen("ML-KEM-1024")
        assert len(ek) == 1568, f"Expected ek=1568, got {len(ek)}"
        assert len(dk) == 64, f"Expected dk=64 (seed), got {len(dk)}"
    
    def test_mlkem_1024_keygen_deterministic(self):
        """Test ML-KEM-1024 key generation with fixed seed produces same output."""
        seed = b"\x00" * 64
        ek1, dk1 = mlkem_keygen("ML-KEM-1024", seed)
        ek2, dk2 = mlkem_keygen("ML-KEM-1024", seed)
        assert ek1 == ek2, "Deterministic keygen should produce identical ek"
        assert dk1 == dk2, "Deterministic keygen should produce identical dk"
    
    def test_mlkem_invalid_parameter_set(self):
        """Test that invalid parameter set raises ValueError."""
        with pytest.raises(ValueError):
            mlkem_keygen("ML-KEM-999")
    
    def test_mlkem_wrong_seed_size(self):
        """Test that wrong seed size raises ValueError."""
        with pytest.raises(ValueError):
            mlkem_keygen("ML-KEM-1024", b"\x00" * 32)  # Should be 64 bytes

    def test_mlkem_keygen_random_seed(self):
        """Test ML-KEM key generation with random seed (seed=None branch)."""
        ek, dk = mlkem_keygen("ML-KEM-1024", seed=None)
        assert len(ek) == 1568
        assert len(dk) == 64

        ek2, dk2 = mlkem_keygen("ML-KEM-768", seed=None)
        assert len(ek2) == 1184
        assert len(dk2) == 64


class TestMLKEMEncapsulation:
    """Test ML-KEM encapsulation and decapsulation."""
    
    def test_encapsulation_decapsulation_roundtrip(self):
        """Test that encapsulation/decapsulation roundtrip works."""
        ek, dk = mlkem_keygen("ML-KEM-1024")
        ss, ct = mlkem_encapsulate(ek, "ML-KEM-1024")
        # For round-trip: encapsulate returns (shared_secret, ciphertext)
        # But mlkem_encapsulate returns (ss, ct) where ss is shared_secret, ct is ciphertext
        # To decrypt, we need to pass the ciphertext (ct) to decapsulate
        ss2 = mlkem_decapsulate(dk, ct, "ML-KEM-1024")  # Pass ciphertext, get back shared_secret
        
        assert len(ss) == 32, f"Shared secret should be 32 bytes, got {len(ss)}"
        assert len(ct) == 1568, f"Ciphertext should be 1568 bytes, got {len(ct)}"
        assert ss == ss2, "Decapsulated secret must match encapsulated secret"


class TestKeySizes:
    """Test expected key sizes per FIPS 203 Table 3."""

    def test_key_sizes_1024(self):
        sizes = get_key_sizes("ML-KEM-1024")
        assert sizes["ek"] == 1568
        assert sizes["dk"] == 3168  # Expanded private key per FIPS 203 Table 3

    def test_key_sizes_768(self):
        sizes = get_key_sizes("ML-KEM-768")
        assert sizes["ek"] == 1184
        assert sizes["dk"] == 2400  # Expanded private key per FIPS 203 Table 3

    def test_key_sizes_512(self):
        sizes = get_key_sizes("ML-KEM-512")
        assert sizes["ek"] == 800
        assert sizes["dk"] == 1632  # Expanded private key per FIPS 203 Table 3


class TestActualKeySizes:
    """Test actual key sizes returned by the library (seed sizes)."""
    
    def test_actual_ek_size_1024(self):
        ek, dk = mlkem_keygen("ML-KEM-1024")
        assert len(ek) == 1568  # Raw public key size
    
    def test_actual_dk_size_1024(self):
        ek, dk = mlkem_keygen("ML-KEM-1024")
        assert len(dk) == 64  # Seed size (not expanded private key)
    
    def test_actual_sizes_via_function_1024(self):
        sizes = get_actual_key_sizes("ML-KEM-1024")
        assert sizes["ek"] == 1568
        assert sizes["dk"] == 64
    
    def test_actual_sizes_via_function_768(self):
        sizes = get_actual_key_sizes("ML-KEM-768")
        assert sizes["ek"] == 1184
        assert sizes["dk"] == 64
    
    def test_actual_sizes_via_function_512(self):
        sizes = get_actual_key_sizes("ML-KEM-512")
        assert sizes["ek"] == 800
        assert sizes["dk"] == 32


if __name__ == "__main__":
    pytest.main([__file__, "-v"])