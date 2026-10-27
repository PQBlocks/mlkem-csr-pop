"""NIST ACVP ML-KEM KATs (spec section 5; Check 5 (adversarial review) adversarial requirement).

Structural + decapsulation known-answer checks against the ACVP-style
vectors in tests/kats/acvp/. Keygen/decap functional KATs run through the
cryptography library backend (src/mlkem.py), the same audited backend the
product uses.

Backend note: cryptography's MLKEM private key reconstructs only from the
64B seed (from_seed_bytes); there is no from_private_bytes for the full
2400/3168B dk. ACVP encapDecap vectors carrying full dk are therefore
structural (size) checks; functional decaps equality runs against
lane_generated_roundtrip.json seed vectors (seed->ek recorded from this
backend, c/k from a real encaps), plus Wycheproof seed->ek keygen KATs.
This is a regression net, not a verification claim.
"""

import json
import os

from pqblocks_csr_pop.mlkem import (
    mlkem_decapsulate,
    mlkem_keygen,
    KEY_SIZES,
)


KATS_DIR = os.path.join(os.path.dirname(__file__), "kats", "acvp")
ENCAP_FILE = "internalProjection.json"
KEYGEN_FILE = "keyGen.json"
ROUNDTRIP_FILE = "lane_generated_roundtrip.json"

CT_SIZES = {"ML-KEM-512": 768, "ML-KEM-768": 1088, "ML-KEM-1024": 1568}


def _load(rel: str) -> dict:
    with open(os.path.join(KATS_DIR, rel), encoding="utf-8") as fh:
        return json.load(fh)


def _b(hexstr: str, nbytes: int, label: str) -> bytes:
    raw = bytes.fromhex(hexstr)
    assert len(raw) == nbytes, f"{label}: {len(raw)} bytes, want {nbytes}"
    return raw


def _group_tests(doc: dict, param: str) -> list:
    out = []
    for group in doc["testGroups"]:
        if group.get("parameterSet") != param:
            continue
        out.extend(group.get("tests", []))
    return out


def test_acvp_keygen_sizes_768() -> None:
    """ACVP keyGen vectors have ML-KEM-768 sizes (z/d 32B, ek 1184B, dk 2400B)."""
    tests = [t for t in _group_tests(_load(KEYGEN_FILE), "ML-KEM-768")
             if all(f in t for f in ("z", "d", "ek", "dk")) and not t.get("deferred")]
    assert len(tests) > 0
    for t in tests:
        _b(t["z"], 32, f"tc{t['tcId']} z")
        _b(t["d"], 32, f"tc{t['tcId']} d")
        _b(t["ek"], KEY_SIZES["ML-KEM-768"]["ek"], f"tc{t['tcId']} ek")
        _b(t["dk"], KEY_SIZES["ML-KEM-768"]["dk"], f"tc{t['tcId']} dk")


def test_acvp_keygen_sizes_1024() -> None:
    """ACVP keyGen vectors have ML-KEM-1024 sizes (z/d 32B, ek 1568B, dk 3168B)."""
    tests = [t for t in _group_tests(_load(KEYGEN_FILE), "ML-KEM-1024")
             if all(f in t for f in ("z", "d", "ek", "dk")) and not t.get("deferred")]
    assert len(tests) > 0
    for t in tests:
        _b(t["z"], 32, f"tc{t['tcId']} z")
        _b(t["d"], 32, f"tc{t['tcId']} d")
        _b(t["ek"], KEY_SIZES["ML-KEM-1024"]["ek"], f"tc{t['tcId']} ek")
        _b(t["dk"], KEY_SIZES["ML-KEM-1024"]["dk"], f"tc{t['tcId']} dk")


def test_acvp_encapdecap_sizes_768() -> None:
    """ACVP encapDecap vectors have ML-KEM-768 sizes (ek 1184, dk 2400, c 1088, k/m 32B)."""
    tests = [t for t in _group_tests(_load(ENCAP_FILE), "ML-KEM-768")
             if all(f in t for f in ("ek", "dk", "c", "k", "m")) and not t.get("deferred")]
    assert len(tests) > 0
    for t in tests:
        _b(t["ek"], KEY_SIZES["ML-KEM-768"]["ek"], f"tc{t['tcId']} ek")
        _b(t["dk"], KEY_SIZES["ML-KEM-768"]["dk"], f"tc{t['tcId']} dk")
        _b(t["c"], CT_SIZES["ML-KEM-768"], f"tc{t['tcId']} c")
        _b(t["k"], 32, f"tc{t['tcId']} k")
        _b(t["m"], 32, f"tc{t['tcId']} m")


def test_acvp_encapdecap_sizes_1024() -> None:
    """ACVP encapDecap vectors have ML-KEM-1024 sizes (ek 1568, dk 3168, c 1568, k/m 32B)."""
    tests = [t for t in _group_tests(_load(ENCAP_FILE), "ML-KEM-1024")
             if all(f in t for f in ("ek", "dk", "c", "k", "m")) and not t.get("deferred")]
    assert len(tests) > 0
    for t in tests:
        _b(t["ek"], KEY_SIZES["ML-KEM-1024"]["ek"], f"tc{t['tcId']} ek")
        _b(t["dk"], KEY_SIZES["ML-KEM-1024"]["dk"], f"tc{t['tcId']} dk")
        _b(t["c"], CT_SIZES["ML-KEM-1024"], f"tc{t['tcId']} c")
        _b(t["k"], 32, f"tc{t['tcId']} k")
        _b(t["m"], 32, f"tc{t['tcId']} m")


def _roundtrip_tests(param: str) -> list:
    doc = json.load(open(os.path.join(KATS_DIR, ROUNDTRIP_FILE), encoding="utf-8"))
    out = []
    for group in doc["testGroups"]:
        for t in group.get("tests", []):
            if t.get("parameterSet") == param and all(
                f in t for f in ("seed", "dk_seed", "ek", "c", "k")
            ):
                out.append(t)
    return out


def test_acvp_decap_kat_768() -> None:
    """Seed-vector decaps of ML-KEM-768 roundtrip vectors reproduces k exactly."""
    tests = _roundtrip_tests("ML-KEM-768")
    assert len(tests) > 0, "no ML-KEM-768 roundtrip vectors"
    n_checked = 0
    for t in tests:
        seed = _b(t["seed"], 64, "seed")
        dk_seed = _b(t["dk_seed"], 64, "dk_seed")
        expected_ek = _b(t["ek"], KEY_SIZES["ML-KEM-768"]["ek"], "ek")
        c = _b(t["c"], CT_SIZES["ML-KEM-768"], "c")
        expected_k = _b(t["k"], 32, "k")
        ek_got, _ = mlkem_keygen("ML-KEM-768", seed)
        assert ek_got == expected_ek, "seed->ek mismatch"
        assert mlkem_decapsulate(dk_seed, c, "ML-KEM-768") == expected_k, "decaps k mismatch"
        n_checked += 1
    assert n_checked > 0, "no ACVP ML-KEM-768 decap vectors checked"


def test_acvp_decap_kat_1024() -> None:
    """Seed-vector decaps of ML-KEM-1024 roundtrip vectors reproduces k exactly."""
    tests = _roundtrip_tests("ML-KEM-1024")
    assert len(tests) > 0, "no ML-KEM-1024 roundtrip vectors"
    n_checked = 0
    for t in tests:
        seed = _b(t["seed"], 64, "seed")
        dk_seed = _b(t["dk_seed"], 64, "dk_seed")
        expected_ek = _b(t["ek"], KEY_SIZES["ML-KEM-1024"]["ek"], "ek")
        c = _b(t["c"], CT_SIZES["ML-KEM-1024"], "c")
        expected_k = _b(t["k"], 32, "k")
        ek_got, _ = mlkem_keygen("ML-KEM-1024", seed)
        assert ek_got == expected_ek, "seed->ek mismatch"
        assert mlkem_decapsulate(dk_seed, c, "ML-KEM-1024") == expected_k, "decaps k mismatch"
        n_checked += 1
    assert n_checked > 0, "no ACVP ML-KEM-1024 decap vectors checked"


def test_acvp_suite_entry() -> None:
    """Suite entry: ACVP vector files present with test groups."""
    for rel in (ENCAP_FILE, KEYGEN_FILE, ROUNDTRIP_FILE):
        doc = _load(rel)
        assert doc["testGroups"], rel
