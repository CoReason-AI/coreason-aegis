# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

import json
from typing import Any, Generator, List

import pytest
from coreason_aegis.main import Aegis
from coreason_identity.models import UserContext
from loguru import logger as loguru_logger


@pytest.fixture
def real_aegis() -> Generator[Aegis, None, None]:
    """
    Fixture that provides an Aegis instance with the REAL Scanner (no mocks).
    """
    # Initializing Aegis triggers Scanner initialization (which loads the heavy model)
    with Aegis() as aegis_instance:
        yield aegis_instance


@pytest.fixture
def capture_logs() -> Generator[List[str], None, None]:
    """
    Fixture to capture loguru logs.
    Returns a list of log messages.
    """
    logs = []

    def sink(message: Any) -> None:
        logs.append(message.record["message"])

    handler_id = loguru_logger.add(sink, level="WARNING")
    yield logs
    loguru_logger.remove(handler_id)


@pytest.mark.integration
def test_credential_exposure_attempt(real_aegis: Aegis, capture_logs: List[str], mock_context: UserContext) -> None:
    """
    User Story B: The 'Leak Prevention' (Credential Exposure)

    Verifies that API keys are redacted and attempts are logged securely.
    """
    # 1. Input Data
    # An API key pattern: sk- followed by >20 chars.
    api_key = "sk-12345abcdefghijklmnopqrstuvwxyz"
    user_prompt = f"Here is the API Key: {api_key} for the app."
    session_id = "session_story_b_real"

    # 2. Sanitize
    sanitized_prompt, deid_map = real_aegis.sanitize(user_prompt, session_id, context=mock_context)

    # Assert 1 (Redaction): The output must contain [SECRET_KEY] token and not the key.
    # Based on masking.py, SECRET_KEY maps to SECRET_KEY token prefix.
    # Default mode is REPLACE, so it should be [SECRET_KEY_A].
    assert api_key not in sanitized_prompt
    assert "[SECRET_KEY_A]" in sanitized_prompt
    assert sanitized_prompt == "Here is the API Key: [SECRET_KEY_A] for the app."

    # Assert 2 (Logging): Verify a WARNING was logged containing "Credential Exposure Attempt".
    found_warning = False
    for message in capture_logs:
        if "Credential Exposure Attempt" in message:
            found_warning = True
            # Assert 3 (Safety): Verify the log message does not contain the actual key.
            assert api_key not in message
            break

    assert found_warning, "Expected 'Credential Exposure Attempt' warning log not found."


@pytest.mark.integration
def test_multiple_credentials(real_aegis: Aegis, capture_logs: List[str], mock_context: UserContext) -> None:
    """
    Verifies detection of multiple distinct API keys in a single input.
    """
    key_1 = "sk-11111abcdefghijklmnopqrstuvwxyz"
    key_2 = "sk-22222abcdefghijklmnopqrstuvwxyz"
    user_prompt = f"Keys: {key_1} and {key_2}"
    session_id = "session_story_b_multi"

    sanitized, deid_map = real_aegis.sanitize(user_prompt, session_id, context=mock_context)

    assert key_1 not in sanitized
    assert key_2 not in sanitized
    assert "[SECRET_KEY_A]" in sanitized
    assert "[SECRET_KEY_B]" in sanitized

    # Check logs: Should have warnings.
    warning_count = sum(1 for msg in capture_logs if "Credential Exposure Attempt" in msg)
    assert warning_count >= 1


@pytest.mark.integration
def test_credential_in_json(real_aegis: Aegis, capture_logs: List[str], mock_context: UserContext) -> None:
    """
    Verifies detection of API keys embedded within a JSON string.
    """
    api_key = "sk-json12345abcdefghijklmnop"
    payload = {"config": {"api_key": api_key, "timeout": 30}}
    user_prompt = json.dumps(payload)
    session_id = "session_story_b_json"

    sanitized, _ = real_aegis.sanitize(user_prompt, session_id, context=mock_context)

    assert api_key not in sanitized
    assert "[SECRET_KEY_A]" in sanitized

    # Verify the JSON structure is preserved (roughly)
    assert '"api_key": "[SECRET_KEY_A]"' in sanitized


@pytest.mark.integration
def test_false_positive_credential(real_aegis: Aegis, mock_context: UserContext) -> None:
    """
    Verifies that short strings starting with 'sk-' are NOT detected as keys.
    """
    # Too short (scanner expects sk- + 20 chars)
    safe_text = "The skier (sk-ier) went down the slope."
    session_id = "session_story_b_fp"

    sanitized, _ = real_aegis.sanitize(safe_text, session_id, context=mock_context)

    # Should remain unchanged
    assert sanitized == safe_text
    assert "[SECRET_KEY_A]" not in sanitized


@pytest.mark.integration
def test_mixed_pii_and_credential(real_aegis: Aegis, capture_logs: List[str], mock_context: UserContext) -> None:
    """
    Verifies correct handling of standard PII alongside credentials.
    """
    api_key = "sk-mixed12345abcdefghijklmn"
    user_prompt = f"John Doe posted {api_key} on 01/01/2025."
    session_id = "session_story_b_mixed"

    sanitized, deid_map = real_aegis.sanitize(user_prompt, session_id, context=mock_context)

    # PII Check
    assert "John Doe" not in sanitized
    assert "[PATIENT_A]" in sanitized

    assert "01/01/2025" not in sanitized
    # Date logic might assign [DATE_A]
    assert "[DATE_A]" in sanitized

    # Key Check
    assert api_key not in sanitized
    assert "[SECRET_KEY_A]" in sanitized
