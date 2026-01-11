import pytest

from coreason_aegis.models import AegisPolicy
from coreason_aegis.scanner import Scanner


@pytest.fixture
def scanner() -> Scanner:
    # Reset singleton for testing
    Scanner._instance = None
    Scanner._analyzer = None
    return Scanner()


def test_mrn_detection(scanner: Scanner) -> None:
    text = "Patient has MRN 12345678."
    policy = AegisPolicy(entity_types=["MRN"], confidence_score=0.5)
    results = scanner.scan(text, policy)

    assert len(results) == 1
    assert results[0].entity_type == "MRN"
    assert text[results[0].start : results[0].end] == "12345678"


def test_protocol_id_detection(scanner: Scanner) -> None:
    text = "Study protocol ABC-123 is active."
    policy = AegisPolicy(entity_types=["PROTOCOL_ID"], confidence_score=0.5)
    results = scanner.scan(text, policy)

    assert len(results) == 1
    assert results[0].entity_type == "PROTOCOL_ID"
    assert text[results[0].start : results[0].end] == "ABC-123"


def test_lot_number_detection(scanner: Scanner) -> None:
    text = "Batch LOT-X99Z1 used."
    policy = AegisPolicy(entity_types=["LOT_NUMBER"], confidence_score=0.5)
    results = scanner.scan(text, policy)

    assert len(results) == 1
    assert results[0].entity_type == "LOT_NUMBER"
    assert text[results[0].start : results[0].end] == "LOT-X99Z1"


def test_mixed_entities(scanner: Scanner) -> None:
    text = "MRN 987654 assigned to ABC-999 for LOT-A1."
    policy = AegisPolicy(entity_types=["MRN", "PROTOCOL_ID", "LOT_NUMBER"], confidence_score=0.5)
    results = scanner.scan(text, policy)

    assert len(results) == 3
    types = {r.entity_type for r in results}
    assert "MRN" in types
    assert "PROTOCOL_ID" in types
    assert "LOT_NUMBER" in types
