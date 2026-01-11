import sys

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.vault import VaultManager


def test_generate_suffix_basics() -> None:
    # We need a dummy vault to instantiate MaskingEngine
    vault = VaultManager()
    engine = MaskingEngine(vault)

    assert engine._generate_suffix(0) == "A"
    assert engine._generate_suffix(1) == "B"
    assert engine._generate_suffix(25) == "Z"


def test_generate_suffix_boundaries() -> None:
    vault = VaultManager()
    engine = MaskingEngine(vault)

    # These are expected to fail with the current implementation
    assert engine._generate_suffix(26) == "AA"
    assert engine._generate_suffix(27) == "AB"
    assert engine._generate_suffix(51) == "AZ"
    assert engine._generate_suffix(52) == "BA"
    assert engine._generate_suffix(701) == "ZZ"
    assert engine._generate_suffix(702) == "AAA"


def test_generate_suffix_negative() -> None:
    vault = VaultManager()
    engine = MaskingEngine(vault)
    import pytest

    with pytest.raises(ValueError):
        engine._generate_suffix(-1)


def test_generate_suffix_large_numbers() -> None:
    vault = VaultManager()
    engine = MaskingEngine(vault)

    # 26^3 + 26^2 + 26 = 17576 + 676 + 26 = 18278 (approx)
    # Just checking it doesn't crash and returns something reasonable

    # Check a known large value if possible, or just property
    # 18277 -> ZZZ
    assert engine._generate_suffix(18277) == "ZZZ"
    assert engine._generate_suffix(18278) == "AAAA"

    # Very large number
    large_suffix = engine._generate_suffix(sys.maxsize)
    assert len(large_suffix) > 0
    assert large_suffix.isupper()
    assert large_suffix.isalpha()
