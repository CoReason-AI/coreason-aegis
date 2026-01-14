from typing import Generator

import pytest

from coreason_aegis.main import Aegis
from coreason_aegis.scanner import Scanner


@pytest.fixture
def real_aegis() -> Generator[Aegis, None, None]:
    """
    Fixture that provides an Aegis instance with the REAL Scanner (no mocks).
    Resets the Singleton before and after to ensure isolation.
    """
    # Reset singleton to ensure we load the real one, not a mock from a previous test
    Scanner._instance = None
    Scanner._analyzer = None

    # Initializing Aegis triggers Scanner initialization (which loads the heavy model)
    aegis_instance = Aegis()

    yield aegis_instance

    # Cleanup after test
    Scanner._instance = None
    Scanner._analyzer = None


@pytest.mark.integration
def test_story_a_end_to_end(real_aegis: Aegis) -> None:
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
    sanitized_prompt, deid_map = real_aegis.sanitize(user_prompt, session_id)

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
    final_output = real_aegis.desanitize(llm_response, session_id, authorized=True)

    # Verification 3: Real data is restored
    assert "John Doe" in final_output
    assert "12/01/1980" in final_output
    assert "[PATIENT_A]" not in final_output
    assert "[DATE_A]" not in final_output

    expected_final = "Regarding John Doe on 12/01/1980, the rash symptoms..."
    assert final_output == expected_final
