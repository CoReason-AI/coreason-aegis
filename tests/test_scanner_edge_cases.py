import pytest

from coreason_aegis.models import AegisPolicy
from coreason_aegis.scanner import Scanner


@pytest.fixture
def scanner() -> Scanner:
    return Scanner()


@pytest.mark.integration
def test_false_positive_avoidance(scanner: Scanner) -> None:
    """
    Verifies that common words or short sequences do not trigger custom recognizers.
    """
    text = (
        "The parking lot was full. "  # Should not trigger LOT_NUMBER
        "I need to ask-about the task-force. "  # Should not trigger SECRET_KEY (sk-)
        "My genes are ATCG. "  # Short sequence, should not trigger GENE_SEQUENCE
        "Call 123-456. "  # Phone format, but not MRN (needs 6-10 digits without dashes usually, or specific boundary)
        "ABC-12 is not a protocol."  # Too short for PROTOCOL_ID (ABC-123)
    )

    policy = AegisPolicy(
        entity_types=["LOT_NUMBER", "SECRET_KEY", "GENE_SEQUENCE", "MRN", "PROTOCOL_ID"], confidence_score=0.4
    )

    results = scanner.scan(text, policy)
    detected_texts = {text[r.start : r.end] for r in results}

    # Assert ABSENCE of false positives
    assert "lot" not in detected_texts
    assert "parking lot" not in detected_texts
    assert "ask-about" not in detected_texts
    assert "ATCG" not in detected_texts
    assert "ABC-12" not in detected_texts

    # Note: "123-456" might be picked up as phone number if PHONE_NUMBER was enabled,
    # but here we only check MRN. MRN regex is \b\d{6,10}\b.
    # "123-456" has a dash, so it shouldn't match MRN regex.
    assert "123-456" not in detected_texts


@pytest.mark.integration
def test_idempotency_or_remasking(scanner: Scanner) -> None:
    """
    Checks behavior when input already contains text that looks like tokens.
    Ideally, we don't want to double-redact if it confuses the system,
    but mainly we want to ensure it doesn't crash.
    """
    text = "Status of [PATIENT_A] is stable."

    # If [PATIENT_A] is detected as a PERSON, it might be masked again.
    # Spacy usually treats brackets as punctuation.

    policy = AegisPolicy(entity_types=["PERSON"], confidence_score=0.4)
    results = scanner.scan(text, policy)
    detected = {text[r.start : r.end] for r in results}

    # If "PATIENT_A" is detected as a person, it's a bit ambiguous.
    # But usually all-caps with underscore is NOT a person name in standard models.
    # So we expect NO detection here.
    assert "PATIENT_A" not in detected
    assert "[PATIENT_A]" not in detected


@pytest.mark.integration
def test_long_continuous_string(scanner: Scanner) -> None:
    """
    Tests stability with a very long string without spaces (potential buffer/regex issues).
    """
    # 50KB string of random chars
    text = "A" * 50000 + "123456" + "B" * 50000

    policy = AegisPolicy(entity_types=["MRN"], confidence_score=0.4)

    results = scanner.scan(text, policy)

    # Should detect the MRN buried in the middle?
    # MRN regex is \b\d{6,10}\b.
    # "A...A123456B...B"
    # The boundaries are "A" and "B". They are Word chars.
    # So \b will NOT match between A and 1.
    # So it should NOT detect it.
    assert len(results) == 0

    # Now try with separators
    text_with_sep = "A" * 50000 + " 123456 " + "B" * 50000
    results_sep = scanner.scan(text_with_sep, policy)

    # Should detect
    assert len(results_sep) == 1
    assert results_sep[0].entity_type == "MRN"
