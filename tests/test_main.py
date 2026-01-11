import pytest
from unittest.mock import MagicMock, patch
from typing import Generator
from presidio_analyzer import RecognizerResult

from coreason_aegis.main import Aegis
from coreason_aegis.models import AegisPolicy, RedactionMode


@pytest.fixture
def mock_scanner_engine() -> Generator[MagicMock, None, None]:
    # Mock the internal AnalyzerEngine to avoid loading models
    with patch("coreason_aegis.scanner.AnalyzerEngine") as mock:
        yield mock


@pytest.fixture
def aegis(mock_scanner_engine: MagicMock) -> Aegis:
    # Reset singleton
    from coreason_aegis.scanner import Scanner

    Scanner._instance = None
    Scanner._analyzer = None

    return Aegis()


def test_sanitize_flow(aegis: Aegis, mock_scanner_engine: MagicMock) -> None:
    # Setup mock scanner results
    mock_instance = mock_scanner_engine.return_value
    mock_results = [RecognizerResult("PERSON", 0, 4, 1.0)]  # "John"
    mock_instance.analyze.return_value = mock_results

    text = "John has a secret."
    session_id = "sess_main_1"

    masked_text, deid_map = aegis.sanitize(text, session_id)

    # Check masking occurred
    assert masked_text == "[PERSON_A] has a secret."
    assert deid_map.mappings["[PERSON_A]"] == "John"

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
    llm_response = "Hello [PERSON_A]."
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
    llm_response = "Hello [PERSON_A]."
    result = aegis.desanitize(llm_response, session_id, authorized=False)

    assert result == "Hello [PERSON_A]."


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

    # Expect: "Patient [PERSON_A] (DOB: [DATE_TIME_A]) has a rash."
    # Note: Our default policy uses REPLACE.
    assert "[PERSON_A]" in sanitized_prompt
    assert "[DATE_TIME_A]" in sanitized_prompt
    assert "John Doe" not in sanitized_prompt

    # 2. LLM Response
    llm_response = "For [PERSON_A], considering the rash..."

    # 3. Desanitize
    final_output = aegis.desanitize(llm_response, session_id, authorized=True)

    assert final_output == "For John Doe, considering the rash..."

def test_desanitize_exception(aegis: Aegis, mock_scanner_engine: MagicMock) -> None:
    # Force exception during re-identification
    with patch.object(aegis.reidentifier, 'reidentify', side_effect=Exception("Re-id error")):
        with pytest.raises(Exception, match="Re-id error"):
            aegis.desanitize("text", "sess_err")
