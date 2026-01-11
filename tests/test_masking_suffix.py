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
