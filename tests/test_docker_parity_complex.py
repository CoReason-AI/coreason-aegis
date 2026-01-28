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

import pytest
from coreason_identity.models import UserContext

from coreason_aegis.models import AegisPolicy
from coreason_aegis.scanner import Scanner


@pytest.fixture
def scanner() -> Scanner:
    return Scanner()


@pytest.mark.integration
def test_json_payload_scanning(scanner: Scanner, mock_context: UserContext) -> None:
    """
    Verifies that the scanner correctly identifies entities within a JSON string,
    typically found in API payloads.
    It should find values, but hopefully not confuse keys with entities (though Presidio treats everything as text).
    """
    data = {
        "patient": "John Doe",
        "mrn": "123456",
        "notes": "Patient assigned to protocol SKY-999.",
        "api_key_field": "sk-1234567890abcdef1234567890abcdef",
    }
    json_text = json.dumps(data)

    # We expect:
    # PERSON: John Doe
    # MRN: 123456
    # PROTOCOL_ID: SKY-999
    # SECRET_KEY: sk-...

    policy = AegisPolicy(entity_types=["PERSON", "MRN", "PROTOCOL_ID", "SECRET_KEY"], confidence_score=0.4)

    results = scanner.scan(json_text, policy, context=mock_context)
    detected_texts = {json_text[r.start : r.end] for r in results}

    assert "John Doe" in detected_texts
    assert "123456" in detected_texts
    assert "SKY-999" in detected_texts
    assert "sk-1234567890abcdef1234567890abcdef" in detected_texts

    # Verify that keys (e.g. "patient") are NOT detected as entities.
    # "patient" is a common word, unlikely to be a PERSON.
    assert "patient" not in detected_texts


@pytest.mark.integration
def test_adversarial_input(scanner: Scanner, mock_context: UserContext) -> None:
    """
    Tests stability against code-like or adversarial inputs that might trigger regex catastrophies or false positives.
    """
    text = """
    SELECT * FROM patients WHERE name = 'Robert'); DROP TABLE students; --
    var x = "John Doe";
    console.log(x);
    // MRN: 999999
    """

    policy = AegisPolicy(entity_types=["PERSON", "MRN"], confidence_score=0.4)

    results = scanner.scan(text, policy, context=mock_context)
    detected_texts = {text[r.start : r.end] for r in results}

    # It should still find John Doe inside the code string
    assert "John Doe" in detected_texts
    # It should find the MRN in the comment
    assert "999999" in detected_texts

    # Ensure SQL keywords didn't crash it
    assert len(results) > 0


@pytest.mark.integration
def test_mixed_language_and_symbols(scanner: Scanner, mock_context: UserContext) -> None:
    """
    Tests input with mixed languages (though model is EN) and symbols.
    """
    text = "El paciente John Doe (MRN: 123456) tiene fiebre. #healthcare @hospital"

    policy = AegisPolicy(entity_types=["PERSON", "MRN"], confidence_score=0.4)
    results = scanner.scan(text, policy, context=mock_context)
    detected_texts = {text[r.start : r.end] for r in results}

    # "El paciente John Doe" might be detected as the full entity due to language confusion
    # Check if "John Doe" is contained in any detected entity
    assert any("John Doe" in t for t in detected_texts)
    assert "123456" in detected_texts
