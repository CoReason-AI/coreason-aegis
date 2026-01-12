from coreason_aegis.main import Aegis
from coreason_aegis.models import AegisPolicy, RedactionMode


def test_story_a_safe_consultation() -> None:
    """
    Verifies Story A: The "Safe Consultation" (Runtime Protection)
    User Prompt: "Patient John Doe (DOB: 12/01/1980) has a rash."
    Requirements:
      1. "John Doe" -> Redacted to [PATIENT_X]
      2. "12/01/1980" -> Redacted to [DATE_X]
      3. Lower confidence threshold ensures dates are caught.
    """
    aegis = Aegis()
    # Use default policy (confidence_score=0.40)
    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    session_id = "session_story_a"

    user_prompt = "Patient John Doe (DOB: 12/01/1980) has a rash."

    # 1. Sanitize
    sanitized_text, deid_map = aegis.sanitize(user_prompt, session_id, policy)

    # Check "John Doe" redaction
    assert "John Doe" not in sanitized_text, "Name should be redacted"
    assert "[PATIENT_" in sanitized_text

    # Check "12/01/1980" redaction
    assert "12/01/1980" not in sanitized_text, "Date should be redacted"
    assert "[DATE_" in sanitized_text

    # 2. Desanitize (Simulated LLM response using tokens)
    # LLM might say "For [PATIENT_A], regarding [DATE_A]..."
    # We construct a response using the actual tokens generated

    # Find token for John Doe
    token_name = next(k for k, v in deid_map.mappings.items() if v == "John Doe")
    token_date = next(k for k, v in deid_map.mappings.items() if v == "12/01/1980")

    llm_response = f"For {token_name}, considering the date {token_date}..."

    desanitized = aegis.desanitize(llm_response, session_id, authorized=True)

    assert "John Doe" in desanitized
    assert "12/01/1980" in desanitized
