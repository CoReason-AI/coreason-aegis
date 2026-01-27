# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from coreason_identity.models import UserContext
from presidio_analyzer import RecognizerResult

from coreason_aegis.main import Aegis


@pytest.fixture
def mock_scanner_engine() -> Generator[MagicMock, None, None]:
    # Mock the internal AnalyzerEngine to avoid loading models
    with patch("coreason_aegis.scanner.AnalyzerEngine") as mock:
        with patch("coreason_aegis.scanner._ANALYZER_ENGINE_CACHE", None):
            yield mock


@pytest.fixture
def aegis(mock_scanner_engine: MagicMock) -> Aegis:
    return Aegis()


@pytest.fixture
def real_aegis() -> Generator[Aegis, None, None]:
    aegis_instance = Aegis()
    yield aegis_instance


@pytest.fixture
def user_context():
    uc = MagicMock(spec=UserContext)
    uc.sub = "test_user"
    uc.permissions = []
    return uc


def test_multiple_distinct_keys(aegis: Aegis, mock_scanner_engine: MagicMock, user_context) -> None:
    """
    Test that two different keys map to [SECRET_KEY_A] and [SECRET_KEY_B].
    """
    mock_instance = mock_scanner_engine.return_value

    key1 = "sk-11111111111111111111"
    key2 = "sk-22222222222222222222"
    text = f"Key1: {key1}, Key2: {key2}"

    # Mock results:
    # Key1 at index 6 (len 23) -> 6-29
    # Key2 at index 37 (len 23) -> 37-60
    results = [
        RecognizerResult("SECRET_KEY", 6, 29, 1.0),
        RecognizerResult("SECRET_KEY", 37, 60, 1.0),
    ]
    mock_instance.analyze.return_value = results

    session_id = "edge_case_multi_keys"
    masked_text, deid_map = aegis.sanitize(text, user_context, session_id=session_id)

    assert "Key1: [SECRET_KEY_A], Key2: [SECRET_KEY_B]" == masked_text
    assert deid_map.mappings["[SECRET_KEY_A]"] == key1
    assert deid_map.mappings["[SECRET_KEY_B]"] == key2


def test_repeated_keys(aegis: Aegis, mock_scanner_engine: MagicMock, user_context) -> None:
    """
    Test that the same key repeated maps to the same token [SECRET_KEY_A].
    """
    mock_instance = mock_scanner_engine.return_value

    key1 = "sk-11111111111111111111"
    text = f"Key1: {key1}, Again: {key1}"

    # Mock results:
    results = [
        RecognizerResult("SECRET_KEY", 6, 29, 1.0),
        RecognizerResult("SECRET_KEY", 38, 61, 1.0),
    ]
    mock_instance.analyze.return_value = results

    session_id = "edge_case_repeat_keys"
    masked_text, deid_map = aegis.sanitize(text, user_context, session_id=session_id)

    assert "Key1: [SECRET_KEY_A], Again: [SECRET_KEY_A]" == masked_text
    assert len(deid_map.mappings) == 1
    assert deid_map.mappings["[SECRET_KEY_A]"] == key1


def test_mixed_entities_counters(aegis: Aegis, mock_scanner_engine: MagicMock, user_context) -> None:
    """
    Test that SECRET_KEY counters are independent from PATIENT counters.
    Expected: [PATIENT_A] and [SECRET_KEY_A].
    """
    mock_instance = mock_scanner_engine.return_value

    key1 = "sk-11111111111111111111"
    person = "John Doe"
    text = f"User {person} has key {key1}"

    # User John Doe has key ...
    # 012345
    # John Doe: 5-13
    # key ...: 22-...

    results = [
        RecognizerResult("PERSON", 5, 13, 1.0),
        RecognizerResult("SECRET_KEY", 22, 45, 1.0),
    ]
    mock_instance.analyze.return_value = results

    session_id = "edge_case_mixed"
    masked_text, deid_map = aegis.sanitize(text, user_context, session_id=session_id)

    # Should be [PATIENT_A] and [SECRET_KEY_A], not [SECRET_KEY_B]
    assert "[PATIENT_A]" in masked_text
    assert "[SECRET_KEY_A]" in masked_text
    assert deid_map.mappings["[PATIENT_A]"] == person
    assert deid_map.mappings["[SECRET_KEY_A]"] == key1


@pytest.mark.integration
def test_real_regex_detection(real_aegis: Aegis, user_context) -> None:
    """
    Test with the REAL scanner to verify the regex for SECRET_KEY works as expected.
    "sk-" followed by 20+ chars.
    """
    valid_key = "sk-abcdef1234567890abcdef"  # 3+22 = 25 chars.
    invalid_key = "sk-short"

    text = f"Here is a valid key: {valid_key} and an invalid one: {invalid_key}."
    session_id = "edge_case_real_regex"

    masked_text, deid_map = real_aegis.sanitize(text, user_context, session_id=session_id)

    # Valid key should be redacted
    assert valid_key not in masked_text
    assert "[SECRET_KEY_A]" in masked_text

    # Invalid key should REMAIN (assuming it's not detected as something else)
    assert invalid_key in masked_text

    # Verify mapping
    assert deid_map.mappings["[SECRET_KEY_A]"] == valid_key


@pytest.mark.integration
def test_complex_scenario_mixed_real(real_aegis: Aegis, user_context) -> None:
    """
    Complex scenario with real scanner:
    - Text with Person, Date, Secret Key.
    - Verify all are detected and masked correctly with proper prefixes.
    """
    person = "Alice Wonderland"
    date = "12/12/2024"
    key = "sk-98765432109876543210"

    text = f"User {person} created key {key} on {date}."
    session_id = "complex_real_scenario"

    masked_text, deid_map = real_aegis.sanitize(text, user_context, session_id=session_id)

    # Check absence of PII
    assert person not in masked_text
    assert key not in masked_text
    assert date not in masked_text

    # Check presence of tokens
    # Note: Person -> [PATIENT_A]
    # Date -> [DATE_A] (normalized from DATE_TIME)
    # Key -> [SECRET_KEY_A]

    assert "[PATIENT_A]" in masked_text
    assert "[SECRET_KEY_A]" in masked_text
    assert "[DATE_A]" in masked_text

    # Verify Desanitization
    restored = real_aegis.desanitize(masked_text, session_id, user_context)
    assert restored == text
