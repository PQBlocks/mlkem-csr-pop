"""Wycheproof ML-KEM KATs (Check 5 (adversarial review) adversarial requirement).

Structural + keygen known-answer checks against the real Wycheproof
vectors in tests/kats/wycheproof/. Keygen KATs run through the
cryptography library ML-KEM bindings via src.mlkem, the same audited
backend the product uses: seed -> mlkem_keygen == recorded ek.

Decaps vectors with full 2400B dk are structural-only here (the backend
reconstructs keys from 64B seeds); functional decaps equality is proven
in test_kat_acvp.py against package-generated roundtrip vectors.

This is a regression net, not a verification claim.
"""

import json
import os

from pqblocks_csr_pop.mlkem import mlkem_keygen

KATS_DIR = os.path.join(os.path.dirname(__file__), "kats", "wycheproof")

EK_SIZE = 1184
DK_FULL_SIZE = 2400
C_SIZE = 1088
SEED_SIZE = 64


def _load(name: str) -> dict:
    with open(os.path.join(KATS_DIR, name), encoding="utf-8") as fh:
        return json.load(fh)


def _all_tests(doc: dict) -> list:
    out = []
    for group in doc["testGroups"]:
        out.extend(group.get("tests", []))
    return out


def _b(hexstr: str, nbytes: int, label: str) -> bytes:
    raw = bytes.fromhex(hexstr)
    assert len(raw) == nbytes, "%s: %d bytes, want %d" % (label, len(raw), nbytes)
    return raw


def test_wycheproof_keygen_seed_sizes() -> None:
    """Seed keygen vectors carry seed 64B, ek 1184B, dk 2400B."""
    tests = _all_tests(_load("mlkem_768_keygen_seed_test.json"))
    assert len(tests) > 0
    for t in tests:
        if t.get("result", "valid") != "valid":
            continue
        _b(t["seed"], SEED_SIZE, f"tc{t['tcId']} seed")
        _b(t["ek"], EK_SIZE, f"tc{t['tcId']} ek")
        _b(t["dk"], DK_FULL_SIZE, f"tc{t['tcId']} dk")


def test_wycheproof_keygen_kat() -> None:
    """Seed -> mlkem_keygen reproduces the recorded ek exactly."""
    tests = _all_tests(_load("mlkem_768_keygen_seed_test.json"))
    assert len(tests) > 0
    n_checked = 0
    for t in tests:
        if t.get("result", "valid") != "valid":
            continue
        seed = _b(t["seed"], SEED_SIZE, f"tc{t['tcId']} seed")
        expected_ek = _b(t["ek"], EK_SIZE, f"tc{t['tcId']} ek")
        ek_got, _ = mlkem_keygen("ML-KEM-768", seed)
        assert ek_got == expected_ek, f"tc{t['tcId']} ek mismatch"
        n_checked += 1
    assert n_checked > 0, "no keygen vectors checked"


def test_wycheproof_encaps_vector_sizes() -> None:
    """Valid encaps vectors carry full-size ek/c/K; invalid ones are marked."""
    tests = _all_tests(_load("mlkem_768_encaps_test.json"))
    assert len(tests) > 0
    n_valid = 0
    for t in tests:
        if t.get("result", "valid") != "valid":
            assert (
                not t.get("c")
                or not t.get("K")
                or t.get("flags")
                or t.get("comment")
            ), "tc%d invalid without marker" % t["tcId"]
            continue
        n_valid += 1
        _b(t["ek"], EK_SIZE, f"tc{t['tcId']} ek")
        _b(t["c"], C_SIZE, f"tc{t['tcId']} c")
        _b(t["K"], 32, f"tc{t['tcId']} K")
    assert n_valid > 0, "no valid encaps vectors found"


def test_wycheproof_ml_kem_vector_sizes() -> None:
    """Main ml_kem vectors: sizes hold where fields are present."""
    tests = _all_tests(_load("mlkem_768_test.json"))
    assert len(tests) > 0
    for t in tests:
        if t.get("result", "valid") != "valid":
            continue
        if t.get("seed"):
            _b(t["seed"], SEED_SIZE, f"tc{t['tcId']} seed")
        _b(t["ek"], EK_SIZE, f"tc{t['tcId']} ek")
        _b(t["c"], C_SIZE, f"tc{t['tcId']} c")
        _b(t["K"], 32, f"tc{t['tcId']} K")


def test_wycheproof_decaps_vector_sizes() -> None:
    """Semi-expanded decaps vectors carry full dk 2400B, c 1088B, K 32B."""
    tests = _all_tests(_load("mlkem_768_semi_expanded_decaps_test.json"))
    assert len(tests) > 0
    n_valid = 0
    for t in tests:
        if t.get("result", "valid") != "valid":
            continue
        if t.get("flags"):
            continue
        _b(t["dk"], DK_FULL_SIZE, f"tc{t['tcId']} dk")
        _b(t["c"], C_SIZE, f"tc{t['tcId']} c")
        _b(t["K"], 32, f"tc{t['tcId']} K")
        n_valid += 1
    assert n_valid > 0, "no valid decaps vectors found"


def test_wycheproof() -> None:
    """Suite entry: all Wycheproof files present with test groups."""
    for name in (
        "mlkem_768_test.json",
        "mlkem_768_keygen_seed_test.json",
        "mlkem_768_encaps_test.json",
        "mlkem_768_semi_expanded_decaps_test.json",
    ):
        doc = _load(name)
        assert doc["testGroups"], name
