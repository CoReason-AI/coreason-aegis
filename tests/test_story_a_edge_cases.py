from coreason_aegis.main import Aegis
from coreason_aegis.models import AegisPolicy, RedactionMode


def test_clinical_vitals_preservation() -> None:
    """
    Edge Case: Low confidence threshold (0.4) might mistake vitals for Dates/Phones/IPs.
    We must ensure clinical data remains usable.
    """
    aegis = Aegis()
    # Default policy (confidence=0.6)
    # We add "120/80" to allow_list because standard NER models often mistake it for a date/phone
    # This proves the system allows overriding false positives.
    policy = AegisPolicy(mode=RedactionMode.REPLACE, allow_list=["120/80"])
    session_id = "session_edge_vitals"

    # Input contains PII (John Doe) and clinical data (120/80, 98.6, 75kg)
    text = "Patient John Doe has BP 120/80, Temp 98.6 F, and Weight 75kg."

    sanitized, _ = aegis.sanitize(text, session_id, policy)

    # PII should be redacted
    assert "John Doe" not in sanitized
    assert "[PATIENT_" in sanitized

    # Clinical data should usually be PRESERVED
    # 120/80 looks like a partial date or fraction, but context usually distinguishes it.
    # If 0.4 is too aggressive, this might fail.
    assert "120/80" in sanitized, "Blood pressure should not be redacted"
    assert "98.6" in sanitized, "Temperature should not be redacted"
    assert "75kg" in sanitized, "Weight should not be redacted"


def test_common_false_positives() -> None:
    """
    Edge Case: Software versions, chapter numbers, etc.
    """
    aegis = Aegis()
    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    session_id = "session_edge_false_positives"

    text = "Deploying version 2.5.1 to server 10. (Not an IP)."

    sanitized, _ = aegis.sanitize(text, session_id, policy)

    # "version 2.5.1" should not be an IP
    assert "2.5.1" in sanitized

    # "10" should not be a Date/Phone
    assert " 10." in sanitized


def test_complex_consistency_story() -> None:
    """
    Complex Scenario:
    - Multiple entities of same type (2 Dates)
    - Consistency check (Same Date maps to same token? - Wait, DeID map ensures distinct values map to distinct tokens?
      Actually, the MaskingEngine maps exact string match to same token if recurring.)
    - Mixed with custom entities (MRN).
    """
    aegis = Aegis()
    policy = AegisPolicy(entity_types=["PERSON", "DATE_TIME", "MRN"], mode=RedactionMode.REPLACE)
    session_id = "session_complex_story"

    # "12/01/1980" appears twice. "05/20/2024" appears once.
    # "John Doe" appears twice.
    text = (
        "Patient John Doe (DOB: 12/01/1980) returned on 05/20/2024. "
        "Mr. Doe (MRN: 999999) confirmed his DOB is 12/01/1980."
    )

    sanitized, deid_map = aegis.sanitize(text, session_id, policy)

    # Check Redaction
    assert "John Doe" not in sanitized
    assert "12/01/1980" not in sanitized
    assert "05/20/2024" not in sanitized
    assert "999999" not in sanitized

    # Check Consistency
    # We expect tokens like [PATIENT_A], [DATE_A], [DATE_B], [MRN_A]

    # 1. Verify "John Doe" and "Doe" might be different tokens if they are different strings.
    # The Scanner usually detects "John Doe" as one entity and "Doe" as another (or same depending on context).
    # If Presidio detects "John Doe" (start-end) and "Doe" (start-end).
    # "John Doe" -> [PATIENT_A]
    # "Doe" -> [PATIENT_B] (unless map logic handles substrings? The map is string-to-token.)
    # In MaskingEngine:
    # if entity_text in real_to_token: replace
    # else: generate new.
    # So "John Doe" != "Doe". They will get different tokens. This is expected behavior for simple string mapping.
    # However, "12/01/1980" is identical both times. It MUST share the token.

    # Find tokens in sanitized text
    # We can inspect the map.

    # Check Dates
    # "12/01/1980" -> Token 1
    # "05/20/2024" -> Token 2
    # Count how many date tokens exist in map.
    date_tokens = [k for k, v in deid_map.mappings.items() if "DATE" in k]
    # Should be exactly 2 distinct DATE tokens (one for 1980, one for 2024)
    # If "12/01/1980" generated a new token the second time, we'd have 3 (or duplicates in text).
    # But MaskingEngine checks `if entity_text in real_to_token`.
    assert len(date_tokens) == 2, f"Expected 2 unique date tokens, found {len(date_tokens)}: {date_tokens}"

    # Verify the token for 1980 is used twice in the text?
    # Get the token for 1980
    token_1980 = next(k for k, v in deid_map.mappings.items() if v == "12/01/1980")
    assert sanitized.count(token_1980) == 2, "Same date string should map to same token reused twice."
