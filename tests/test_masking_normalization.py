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


def test_standard_normalizations(masking_engine: MaskingEngine) -> None:
    # Test specific mappings
    assert MaskingEngine._normalize_entity_type("PERSON") == "PATIENT"
    assert MaskingEngine._normalize_entity_type("DATE_TIME") == "DATE"
    assert MaskingEngine._normalize_entity_type("EMAIL_ADDRESS") == "EMAIL"
    assert MaskingEngine._normalize_entity_type("PHONE_NUMBER") == "PHONE"
    assert MaskingEngine._normalize_entity_type("IP_ADDRESS") == "IP"
    # Changed per PRD Story B: SECRET_KEY should redact to [SECRET_KEY], not [KEY]
    assert MaskingEngine._normalize_entity_type("SECRET_KEY") == "SECRET_KEY"


def test_unknown_normalization(masking_engine: MaskingEngine) -> None:
    # Should pass through
    assert MaskingEngine._normalize_entity_type("CUSTOM_TYPE") == "CUSTOM_TYPE"
