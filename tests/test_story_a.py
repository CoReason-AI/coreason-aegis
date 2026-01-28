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

import pytest
from coreason_identity.models import UserContext

from coreason_aegis.main import Aegis


@pytest.fixture
def real_aegis() -> Generator[Aegis, None, None]:
    """
    Fixture that provides an Aegis instance with the REAL Scanner (no mocks).
    """
    # Initializing Aegis triggers Scanner initialization (which loads the heavy model)
    with Aegis() as aegis_instance:
        yield aegis_instance


@pytest.mark.integration
def test_story_a_end_to_end(real_aegis: Aegis, mock_context: UserContext) -> None:
    """
    User Story A: The 'Safe Consultation' (Runtime Protection)

    Verifies the Scan-Mask-Map-Reveal loop using the real Presidio/Spacy engine.
    """
    # 1. Input Data
    # "Patient John Doe (DOB: 12/01/1980) has a rash."
    user_prompt = "Patient John Doe (DOB: 12/01/1980) has a rash."
    session_id = "session_story_a_real"

    # 2. Sanitize
    # This calls the real Presidio model.
    # John Doe -> PERSON -> [PATIENT_A] (assuming it's the first person detected)
    # 12/01/1980 -> DATE_TIME -> [DATE_A]
    sanitized_prompt, deid_map = real_aegis.sanitize(user_prompt, session_id, context=mock_context)

    # Verification 1: PII is removed
    assert "John Doe" not in sanitized_prompt
    assert "12/01/1980" not in sanitized_prompt

    # Verification 2: Tokens are present
    # Note: Presidio might detect 'John Doe' as PERSON.
    # '12/01/1980' as DATE_TIME.
    # The suffixes are assigned based on order of appearance.
    # John Doe (idx ~8) comes before Date (idx ~23).
    # So John Doe -> [PATIENT_A]
    # Date -> [DATE_A]

    assert "[PATIENT_A]" in sanitized_prompt
    assert "[DATE_A]" in sanitized_prompt

    # Expected structure: "Patient [PATIENT_A] (DOB: [DATE_A]) has a rash."
    expected_structure = "Patient [PATIENT_A] (DOB: [DATE_A]) has a rash."
    assert sanitized_prompt == expected_structure

    # 3. Simulate LLM Response
    # The LLM receives the tokens and responds using them.
    llm_response = "Regarding [PATIENT_A] on [DATE_A], the rash symptoms..."

    # 4. Desanitize (The Reveal)
    # Aegis should map the tokens back to the original values.
    final_output = real_aegis.desanitize(llm_response, session_id, context=mock_context, authorized=True)

    # Verification 3: Real data is restored
    assert "John Doe" in final_output
    assert "12/01/1980" in final_output
    assert "[PATIENT_A]" not in final_output
    assert "[DATE_A]" not in final_output

    expected_final = "Regarding John Doe on 12/01/1980, the rash symptoms..."
    assert final_output == expected_final


@pytest.mark.integration
def test_multi_turn_consistency(real_aegis: Aegis, mock_context: UserContext) -> None:
    """
    Test Case 1: Consistency across multiple turns.
    "John Doe" must map to the same token within the session.
    """
    session_id = "session_consistency"

    # Turn 1
    input1 = "John Doe is here."
    sanitized1, _ = real_aegis.sanitize(input1, session_id, context=mock_context)
    assert "[PATIENT_A]" in sanitized1

    # Turn 2
    input2 = "Does John Doe have insurance?"
    sanitized2, _ = real_aegis.sanitize(input2, session_id, context=mock_context)
    # Should reuse [PATIENT_A], not create [PATIENT_B]
    assert "[PATIENT_A]" in sanitized2
    assert "[PATIENT_B]" not in sanitized2


@pytest.mark.integration
def test_multiple_identities(real_aegis: Aegis, mock_context: UserContext) -> None:
    """
    Test Case 2: Multiple distinct entities in the same text.
    John Doe -> [PATIENT_A]
    Jane Smith -> [PATIENT_B]
    """
    session_id = "session_multiple"
    text = "John Doe and Jane Smith are meeting."

    sanitized, deid_map = real_aegis.sanitize(text, session_id, context=mock_context)

    assert "[PATIENT_A]" in sanitized
    assert "[PATIENT_B]" in sanitized

    # Check mapping
    # Note: Order depends on appearance.
    # John Doe (idx 0) -> A
    # Jane Smith (idx 13) -> B

    assert deid_map.mappings["[PATIENT_A]"] == "John Doe"
    assert deid_map.mappings["[PATIENT_B]"] == "Jane Smith"


@pytest.mark.integration
def test_hallucinated_token(real_aegis: Aegis, mock_context: UserContext) -> None:
    """
    Test Case 3: LLM returns a token that doesn't exist.
    """
    session_id = "session_hallucination"

    # Seed the session with one entity
    real_aegis.sanitize("John Doe", session_id, context=mock_context)

    # Simulate LLM returning a non-existent token [PATIENT_X]
    llm_response = "I spoke with [PATIENT_X] and [PATIENT_A]."

    result = real_aegis.desanitize(llm_response, session_id, context=mock_context, authorized=True)

    # [PATIENT_A] should be resolved. [PATIENT_X] should remain.
    assert "John Doe" in result
    assert "[PATIENT_X]" in result
