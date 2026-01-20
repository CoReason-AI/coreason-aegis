# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

import pytest

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.vault import VaultManager


@pytest.fixture
def masking_engine() -> MaskingEngine:
    return MaskingEngine(VaultManager())


def test_base_cases() -> None:
    assert MaskingEngine._generate_suffix(0) == "A"
    assert MaskingEngine._generate_suffix(25) == "Z"


def test_rollover() -> None:
    assert MaskingEngine._generate_suffix(26) == "AA"
    assert MaskingEngine._generate_suffix(27) == "AB"
    assert MaskingEngine._generate_suffix(51) == "AZ"
    assert MaskingEngine._generate_suffix(52) == "BA"


def test_large_number() -> None:
    # 26^2 + 26 = 676 + 26 = 702 -> AAA
    # 0 -> A (1 digit)
    # 26 -> AA (2 digits)
    # 702 -> AAA (3 digits)
    assert MaskingEngine._generate_suffix(702) == "AAA"


def test_negative_input() -> None:
    with pytest.raises(ValueError):
        MaskingEngine._generate_suffix(-1)
