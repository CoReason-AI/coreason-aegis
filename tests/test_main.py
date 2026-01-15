import logging
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from loguru import logger
from presidio_analyzer import RecognizerResult

from coreason_aegis.main import Aegis


@pytest.fixture
def mock_scanner_engine() -> Generator[MagicMock, None, None]:
    # Mock the internal AnalyzerEngine to avoid loading models
    # Patch the class so that if instantiated, it returns a mock.
    with patch("coreason_aegis.scanner.AnalyzerEngine") as mock:
        # Crucial: Ensure the module-level cache is None so that Scanner
        # calls AnalyzerEngine() (hitting our mock) instead of using a cached real instance.
        with patch("coreason_aegis.scanner._ANALYZER_ENGINE_CACHE", None):
            yield mock


@pytest.fixture
def aegis(mock_scanner_engine: MagicMock) -> Aegis:
    # No singleton reset needed for Scanner anymore, but we need to ensure
    # Aegis uses a fresh scanner (which uses the mocked engine).
    # Since Aegis() calls Scanner(), and Scanner() uses _get_analyzer_engine(),
    # and we cleared the cache in mock_scanner_engine, this should work.
    return Aegis()


@pytest.fixture
def capture_logs(caplog: pytest.LogCaptureFixture) -> Generator[pytest.LogCaptureFixture, None, None]:
    """Fixture to capture loguru logs using standard logging handler."""

    class PropagateHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            logging.getLogger(record.name).handle(record)

    handler_id = logger.add(PropagateHandler(), format="{message}")
    yield caplog
    logger.remove(handler_id)


# For test_story_b_leak_prevention, we need to manually hook loguru to caplog
# Or simpler: Add a sink that appends to a list.


@pytest.fixture
def log_sink() -> Generator[list[str], None, None]:
    logs: list[str] = []
    handler_id = logger.add(lambda msg: logs.append(str(msg)), level="WARNING")
    yield logs
    logger.remove(handler_id)


def test_sanitize_flow(aegis: Aegis, mock_scanner_engine: MagicMock) -> None:
    # Setup mock scanner results
    mock_instance = mock_scanner_engine.return_value
    mock_results = [RecognizerResult("PERSON", 0, 4, 1.0)]  # "John"
    mock_instance.analyze.return_value = mock_results

    text = "John has a secret."
    session_id = "sess_main_1"

    masked_text, deid_map = aegis.sanitize(text, session_id)

    # Check masking occurred
    assert masked_text == "[PATIENT_A] has a secret."
    assert deid_map.mappings["[PATIENT_A]"] == "John"

    # Verify scan call
    mock_instance.analyze.assert_called_once()


def test_desanitize_flow_authorized(aegis: Aegis, mock_scanner_engine: MagicMock) -> None:
    # First sanitize to populate vault
    mock_instance = mock_scanner_engine.return_value
    mock_results = [RecognizerResult("PERSON", 0, 4, 1.0)]
    mock_instance.analyze.return_value = mock_results

    text = "John"
    session_id = "sess_main_2"
    aegis.sanitize(text, session_id)

    # Now desanitize
    llm_response = "Hello [PATIENT_A]."
    result = aegis.desanitize(llm_response, session_id, authorized=True)

    assert result == "Hello John."


def test_desanitize_flow_unauthorized(aegis: Aegis, mock_scanner_engine: MagicMock) -> None:
    # First sanitize to populate vault
    mock_instance = mock_scanner_engine.return_value
    mock_results = [RecognizerResult("PERSON", 0, 4, 1.0)]
    mock_instance.analyze.return_value = mock_results

    text = "John"
    session_id = "sess_main_3"
    aegis.sanitize(text, session_id)

    # Now desanitize
    llm_response = "Hello [PATIENT_A]."
    result = aegis.desanitize(llm_response, session_id, authorized=False)

    assert result == "Hello [PATIENT_A]."


def test_sanitize_fail_closed(aegis: Aegis, mock_scanner_engine: MagicMock) -> None:
    mock_instance = mock_scanner_engine.return_value
    mock_instance.analyze.side_effect = Exception("Critical Failure")

    with pytest.raises(RuntimeError, match="Scan operation failed"):
        aegis.sanitize("input", "sess_fail")


def test_story_a_safe_consultation(aegis: Aegis, mock_scanner_engine: MagicMock) -> None:
    # Implementation of Story A from PRD
    # User Prompt: "Patient John Doe (DOB: 12/01/1980) has a rash."

    # Mock scanner to return multiple entities
    mock_instance = mock_scanner_engine.return_value

    # "Patient John Doe (DOB: 12/01/1980) has a rash."
    #          01234567
    # John Doe starts at 8, len 8 -> 8-16
    # 12/01/1980 starts at 23, len 10 -> 23-33

    results = [
        RecognizerResult("PERSON", 8, 16, 0.9),
        RecognizerResult("DATE_TIME", 23, 33, 0.9),
    ]
    mock_instance.analyze.return_value = results

    user_prompt = "Patient John Doe (DOB: 12/01/1980) has a rash."
    session_id = "story_a"

    # 1. Sanitize
    sanitized_prompt, _ = aegis.sanitize(user_prompt, session_id)

    # Expect: "Patient [PATIENT_A] (DOB: [DATE_A]) has a rash."
    # Note: Our default policy uses REPLACE.
    assert "[PATIENT_A]" in sanitized_prompt
    assert "[DATE_A]" in sanitized_prompt
    assert "John Doe" not in sanitized_prompt

    # 2. LLM Response
    llm_response = "For [PATIENT_A], considering the rash..."

    # 3. Desanitize
    final_output = aegis.desanitize(llm_response, session_id, authorized=True)

    assert final_output == "For John Doe, considering the rash..."


def test_desanitize_exception(aegis: Aegis, mock_scanner_engine: MagicMock) -> None:
    # Force exception during re-identification
    with patch.object(aegis.reidentifier, "reidentify", side_effect=Exception("Re-id error")):
        with pytest.raises(Exception, match="Re-id error"):
            aegis.desanitize("text", "sess_err")


def test_story_b_leak_prevention(aegis: Aegis, mock_scanner_engine: MagicMock, log_sink: list[str]) -> None:
    # Story B: "Here is the API Key: sk-12345..."

    mock_instance = mock_scanner_engine.return_value

    # "Here is the API Key: sk-12345..."
    # API Key starts at 21. Let's assume it matches.
    results = [RecognizerResult("SECRET_KEY", 21, 41, 1.0)]
    mock_instance.analyze.return_value = results

    text = "Here is the API Key: sk-1234567890abcdef12345."
    session_id = "story_b"

    # Run sanitize
    masked_text, _ = aegis.sanitize(text, session_id)

    # Verify masking
    # [KEY_A]
    assert "[KEY_A]" in masked_text
    assert "sk-12345" not in masked_text

    # Verify Alert
    # "Alert: Logs a warning to coreason-veritas (without the key) regarding 'Credential Exposure Attempt.'"

    found_alert = False
    for message in log_sink:
        if "Credential Exposure Attempt detected. Redacting API Key." in str(message):
            found_alert = True
            # Ensure key is NOT in logs
            assert "sk-12345" not in str(message)

    assert found_alert, "Expected alert not found in logs"
