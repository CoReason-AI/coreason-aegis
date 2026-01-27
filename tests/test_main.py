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
from typing import AsyncGenerator, Generator
from unittest.mock import MagicMock, patch

import pytest
from coreason_identity.models import UserContext
from loguru import logger
from presidio_analyzer import RecognizerResult

from coreason_aegis.exceptions import SecurityException
from coreason_aegis.main import Aegis, AegisAsync


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
async def aegis_async(mock_scanner_engine: MagicMock) -> AsyncGenerator[AegisAsync, None]:
    async with AegisAsync() as svc:
        yield svc


@pytest.fixture
def capture_logs(caplog: pytest.LogCaptureFixture) -> Generator[pytest.LogCaptureFixture, None, None]:
    """Fixture to capture loguru logs using standard logging handler."""

    class PropagateHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            logging.getLogger(record.name).handle(record)

    handler_id = logger.add(PropagateHandler(), format="{message}")
    yield caplog
    logger.remove(handler_id)


@pytest.fixture
def log_sink() -> Generator[list[str], None, None]:
    logs: list[str] = []
    handler_id = logger.add(lambda msg: logs.append(str(msg)), level="WARNING")
    yield logs
    logger.remove(handler_id)


@pytest.fixture
def user_context():
    uc = MagicMock(spec=UserContext)
    uc.sub = "user-test"
    uc.permissions = []
    return uc


def test_sanitize_flow(aegis: Aegis, mock_scanner_engine: MagicMock, user_context) -> None:
    # Setup mock scanner results
    mock_instance = mock_scanner_engine.return_value
    mock_results = [RecognizerResult("PERSON", 0, 4, 1.0)]  # "John"
    mock_instance.analyze.return_value = mock_results

    text = "John has a secret."

    with aegis:
        masked_text, deid_map = aegis.sanitize(text, user_context)

    # Check masking occurred
    assert masked_text == "[PATIENT_A] has a secret."
    assert deid_map.mappings["[PATIENT_A]"] == "John"
    assert deid_map.owner_id == user_context.sub
    assert deid_map.session_id is not None

    # Verify scan call
    mock_instance.analyze.assert_called_once()


@pytest.mark.asyncio
async def test_sanitize_flow_async(aegis_async: AegisAsync, mock_scanner_engine: MagicMock, user_context) -> None:
    # Setup mock scanner results
    mock_instance = mock_scanner_engine.return_value
    mock_results = [RecognizerResult("PERSON", 0, 4, 1.0)]  # "John"
    mock_instance.analyze.return_value = mock_results

    text = "John has a secret."

    masked_text, deid_map = await aegis_async.sanitize(text, user_context)

    # Check masking occurred
    assert masked_text == "[PATIENT_A] has a secret."
    assert deid_map.mappings["[PATIENT_A]"] == "John"

    # Verify scan call
    mock_instance.analyze.assert_called_once()


def test_desanitize_flow_authorized(aegis: Aegis, mock_scanner_engine: MagicMock, user_context) -> None:
    # First sanitize to populate vault
    mock_instance = mock_scanner_engine.return_value
    mock_results = [RecognizerResult("PERSON", 0, 4, 1.0)]
    mock_instance.analyze.return_value = mock_results

    text = "John"
    with aegis:
        _, deid_map = aegis.sanitize(text, user_context)
        session_id = deid_map.session_id

        # Now desanitize
        llm_response = "Hello [PATIENT_A]."
        result = aegis.desanitize(llm_response, session_id, user_context)

    assert result == "Hello John."


def test_desanitize_flow_unauthorized(aegis: Aegis, mock_scanner_engine: MagicMock, user_context) -> None:
    # First sanitize to populate vault
    mock_instance = mock_scanner_engine.return_value
    mock_results = [RecognizerResult("PERSON", 0, 4, 1.0)]
    mock_instance.analyze.return_value = mock_results

    text = "John"

    other_context = MagicMock(spec=UserContext)
    other_context.sub = "attacker"
    other_context.permissions = []

    with aegis:
        _, deid_map = aegis.sanitize(text, user_context)
        session_id = deid_map.session_id

        # Now desanitize with wrong context
        llm_response = "Hello [PATIENT_A]."

        with pytest.raises(SecurityException):
            aegis.desanitize(llm_response, session_id, other_context)


def test_sanitize_fail_closed(aegis: Aegis, mock_scanner_engine: MagicMock, user_context) -> None:
    mock_instance = mock_scanner_engine.return_value
    mock_instance.analyze.side_effect = Exception("Critical Failure")

    with aegis:
        with pytest.raises(RuntimeError, match="Scan operation failed"):
            aegis.sanitize("input", user_context)


def test_story_a_safe_consultation(aegis: Aegis, mock_scanner_engine: MagicMock, user_context) -> None:
    # Implementation of Story A from PRD
    mock_instance = mock_scanner_engine.return_value

    results = [
        RecognizerResult("PERSON", 8, 16, 0.9),
        RecognizerResult("DATE_TIME", 23, 33, 0.9),
    ]
    mock_instance.analyze.return_value = results

    user_prompt = "Patient John Doe (DOB: 12/01/1980) has a rash."

    with aegis:
        # 1. Sanitize
        sanitized_prompt, deid_map = aegis.sanitize(user_prompt, user_context)
        session_id = deid_map.session_id

        # Expect: "Patient [PATIENT_A] (DOB: [DATE_A]) has a rash."
        assert "[PATIENT_A]" in sanitized_prompt
        assert "[DATE_A]" in sanitized_prompt
        assert "John Doe" not in sanitized_prompt

        # 2. LLM Response
        llm_response = "For [PATIENT_A], considering the rash..."

        # 3. Desanitize
        final_output = aegis.desanitize(llm_response, session_id, user_context)

    assert final_output == "For John Doe, considering the rash..."


def test_desanitize_exception(aegis: Aegis, mock_scanner_engine: MagicMock, user_context) -> None:
    # Force exception during re-identification
    with aegis:
        # Need to mock get_map to return something valid first to pass auth check?
        # Or just mock reidentify.
        # But desanitize checks auth first.
        # So we sanitize first to get a valid map.
        _, deid_map = aegis.sanitize("text", user_context)
        session_id = deid_map.session_id

        with patch.object(aegis._async.reidentifier, "reidentify", side_effect=Exception("Re-id error")):
            with pytest.raises(Exception, match="Re-id error"):
                aegis.desanitize("text", session_id, user_context)


def test_story_b_leak_prevention(
    aegis: Aegis, mock_scanner_engine: MagicMock, log_sink: list[str], user_context
) -> None:
    # Story B: "Here is the API Key: sk-12345..."

    mock_instance = mock_scanner_engine.return_value
    results = [RecognizerResult("SECRET_KEY", 21, 41, 1.0)]
    mock_instance.analyze.return_value = results

    text = "Here is the API Key: sk-1234567890abcdef12345."

    with aegis:
        # Run sanitize
        masked_text, _ = aegis.sanitize(text, user_context)

    # Verify masking
    assert "[SECRET_KEY_A]" in masked_text
    assert "sk-12345" not in masked_text

    # Verify Alert
    found_alert = False
    for message in log_sink:
        if "Credential Exposure Attempt detected. Redacting API Key." in str(message):
            found_alert = True
            # Ensure key is NOT in logs
            assert "sk-12345" not in str(message)

    assert found_alert, "Expected alert not found in logs"


def test_desanitize_missing_map(aegis: Aegis, user_context) -> None:
    session_id = "missing_session"
    text = "Some text"

    with aegis:
        # Should return text as is and log warning
        result = aegis.desanitize(text, session_id, user_context)
        assert result == text
