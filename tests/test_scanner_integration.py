import pytest

from coreason_aegis.models import AegisPolicy
from coreason_aegis.scanner import Scanner


@pytest.fixture
def scanner() -> Scanner:
    # Reset singleton to ensure fresh initialization with real AnalyzerEngine
    Scanner._instance = None
    Scanner._analyzer = None
    return Scanner()


@pytest.mark.integration
def test_standard_entity_detection(scanner: Scanner) -> None:
    """
    Verifies that the Spacy model is loaded and working by detecting standard entities.
    """
    text = "John Doe contact: john.doe@example.com, IP: 192.168.1.1."
    policy = AegisPolicy(
        entity_types=["PERSON", "EMAIL_ADDRESS", "IP_ADDRESS"],
        confidence_score=0.4,  # Slightly lower threshold for standard entities to be safe in tests
    )

    results = scanner.scan(text, policy)

    detected_types = {r.entity_type for r in results}
    detected_text = {text[r.start : r.end] for r in results}

    assert "PERSON" in detected_types
    assert "EMAIL_ADDRESS" in detected_types
    assert "IP_ADDRESS" in detected_types

    assert "John Doe" in detected_text
    assert "john.doe@example.com" in detected_text
    assert "192.168.1.1" in detected_text


@pytest.mark.integration
def test_complex_mixed_scenario(scanner: Scanner) -> None:
    """
    Tests a complex scenario with mixed custom and standard entities,
    verifying they coexist and are detected correctly.
    """
    text = (
        "Patient Sarah Connor (MRN: 123456) was admitted on 2024-05-20. "
        "Protocol T-800 (ID: SKY-999) was initiated. "
        "Contact: sarah@resistance.net. "
        "Administered LOT-XYZ123."
    )

    # Enable all relevant entities
    policy = AegisPolicy(
        entity_types=["PERSON", "MRN", "DATE_TIME", "PROTOCOL_ID", "EMAIL_ADDRESS", "LOT_NUMBER"], confidence_score=0.4
    )

    results = scanner.scan(text, policy)

    # Helper to find result by type
    def get_text_by_type(etype: str) -> list[str]:
        return [text[r.start : r.end] for r in results if r.entity_type == etype]

    # Standard
    assert "Sarah Connor" in get_text_by_type("PERSON")
    # Date detection depends on Presidio/Spacy model.
    # Usually detects "2024-05-20" or parts of it.
    dates = get_text_by_type("DATE_TIME")
    assert any("2024-05-20" in d for d in dates) or dates  # At least some date detected

    assert "sarah@resistance.net" in get_text_by_type("EMAIL_ADDRESS")

    # Custom
    assert "123456" in get_text_by_type("MRN")
    assert "SKY-999" in get_text_by_type("PROTOCOL_ID")
    assert "LOT-XYZ123" in get_text_by_type("LOT_NUMBER")


@pytest.mark.integration
def test_overlap_and_adjacency(scanner: Scanner) -> None:
    """
    Tests scenarios where entities are adjacent or potentially overlapping.
    """
    # "LOT-A1" ends with digit, "123456" (MRN) starts with digit.
    # Adjacent: LOT-A1 123456
    text = "Check LOT-A1 123456 and SKY-123."

    policy = AegisPolicy(entity_types=["LOT_NUMBER", "MRN", "PROTOCOL_ID"], confidence_score=0.5)
    results = scanner.scan(text, policy)

    detected = {text[r.start : r.end] for r in results}

    assert "LOT-A1" in detected
    assert "123456" in detected
    assert "SKY-123" in detected


@pytest.mark.integration
def test_large_input_stability(scanner: Scanner) -> None:
    """
    Tests stability with a larger input buffer.
    """
    # Create a 10KB string with repeated patterns
    base_text = "Patient John Doe (MRN 123456) "
    text = base_text * 500

    policy = AegisPolicy(entity_types=["PERSON", "MRN"], confidence_score=0.5)

    # Should not raise exception
    results = scanner.scan(text, policy)

    assert len(results) >= 500  # Should detect at least one per repetition
    assert len(results) <= 1000  # Person + MRN per repetition
