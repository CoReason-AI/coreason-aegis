# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

import logging
from typing import Generator, List

import pytest
from loguru import logger as loguru_logger

from coreason_aegis.main import Aegis


@pytest.fixture
def real_aegis() -> Generator[Aegis, None, None]:
    """
    Fixture that provides an Aegis instance with the REAL Scanner (no mocks).
    """
    # Initializing Aegis triggers Scanner initialization (which loads the heavy model)
    aegis_instance = Aegis()
    yield aegis_instance


@pytest.fixture
def capture_logs() -> Generator[List[str], None, None]:
    """
    Fixture to capture loguru logs.
    Returns a list of log messages.
    """
    logs = []

    def sink(message):
        logs.append(message.record["message"])

    handler_id = loguru_logger.add(sink, level="WARNING")
    yield logs
    loguru_logger.remove(handler_id)


@pytest.mark.integration
def test_credential_exposure_attempt(real_aegis: Aegis, capture_logs: List[str]) -> None:
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
    sanitized_prompt, deid_map = real_aegis.sanitize(user_prompt, session_id)

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
