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
from unittest.mock import MagicMock

import pytest
from coreason_identity.models import UserContext

from coreason_aegis.main import Aegis


@pytest.fixture
def real_aegis() -> Generator[Aegis, None, None]:
    """
    Fixture that provides an Aegis instance with the REAL Scanner (no mocks).
    """
    with Aegis() as aegis_instance:
        yield aegis_instance


@pytest.fixture
def user_context():
    uc = MagicMock(spec=UserContext)
    uc.sub = "user-story-a"
    uc.permissions = []
    return uc


@pytest.mark.integration
def test_story_a_end_to_end(real_aegis: Aegis, user_context) -> None:
    """
    User Story A: The 'Safe Consultation' (Runtime Protection)
    """
    user_prompt = "Patient John Doe (DOB: 12/01/1980) has a rash."
    session_id = "session_story_a_real"

    # 2. Sanitize
    sanitized_prompt, deid_map = real_aegis.sanitize(user_prompt, user_context, session_id=session_id)

    # Verification 1: PII is removed
    assert "John Doe" not in sanitized_prompt
    assert "12/01/1980" not in sanitized_prompt

    # Verification 2: Tokens are present
    assert "[PATIENT_A]" in sanitized_prompt
    assert "[DATE_A]" in sanitized_prompt

    expected_structure = "Patient [PATIENT_A] (DOB: [DATE_A]) has a rash."
    assert sanitized_prompt == expected_structure

    # 3. Simulate LLM Response
    llm_response = "Regarding [PATIENT_A] on [DATE_A], the rash symptoms..."

    # 4. Desanitize (The Reveal)
    final_output = real_aegis.desanitize(llm_response, session_id, user_context)

    # Verification 3: Real data is restored
    assert "John Doe" in final_output
    assert "12/01/1980" in final_output
    assert "[PATIENT_A]" not in final_output
    assert "[DATE_A]" not in final_output

    expected_final = "Regarding John Doe on 12/01/1980, the rash symptoms..."
    assert final_output == expected_final


@pytest.mark.integration
def test_multi_turn_consistency(real_aegis: Aegis, user_context) -> None:
    """
    Test Case 1: Consistency across multiple turns.
    """
    session_id = "session_consistency"

    # Turn 1
    input1 = "John Doe is here."
    sanitized1, _ = real_aegis.sanitize(input1, user_context, session_id=session_id)
    assert "[PATIENT_A]" in sanitized1

    # Turn 2
    input2 = "Does John Doe have insurance?"
    sanitized2, _ = real_aegis.sanitize(input2, user_context, session_id=session_id)
    # Should reuse [PATIENT_A], not create [PATIENT_B]
    assert "[PATIENT_A]" in sanitized2
    assert "[PATIENT_B]" not in sanitized2


@pytest.mark.integration
def test_multiple_identities(real_aegis: Aegis, user_context) -> None:
    """
    Test Case 2: Multiple distinct entities in the same text.
    """
    session_id = "session_multiple"
    text = "John Doe and Jane Smith are meeting."

    sanitized, deid_map = real_aegis.sanitize(text, user_context, session_id=session_id)

    assert "[PATIENT_A]" in sanitized
    assert "[PATIENT_B]" in sanitized

    assert deid_map.mappings["[PATIENT_A]"] == "John Doe"
    assert deid_map.mappings["[PATIENT_B]"] == "Jane Smith"


@pytest.mark.integration
def test_hallucinated_token(real_aegis: Aegis, user_context) -> None:
    """
    Test Case 3: LLM returns a token that doesn't exist.
    """
    session_id = "session_hallucination"

    # Seed the session with one entity
    real_aegis.sanitize("John Doe", user_context, session_id=session_id)

    # Simulate LLM returning a non-existent token [PATIENT_X]
    llm_response = "I spoke with [PATIENT_X] and [PATIENT_A]."

    result = real_aegis.desanitize(llm_response, session_id, user_context)

    # [PATIENT_A] should be resolved. [PATIENT_X] should remain.
    assert "John Doe" in result
    assert "[PATIENT_X]" in result
