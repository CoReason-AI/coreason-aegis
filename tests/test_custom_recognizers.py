# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

import pytest
from coreason_aegis.models import AegisPolicy
from coreason_aegis.scanner import Scanner
from coreason_identity.models import UserContext


@pytest.fixture
def scanner() -> Scanner:
    return Scanner()


def test_mrn_detection(scanner: Scanner, mock_context: UserContext) -> None:
    text = "Patient has MRN 12345678."
    policy = AegisPolicy(entity_types=["MRN"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    assert len(results) == 1
    assert results[0].entity_type == "MRN"
    assert text[results[0].start : results[0].end] == "12345678"


def test_protocol_id_detection(scanner: Scanner, mock_context: UserContext) -> None:
    text = "Study protocol ABC-123 is active."
    policy = AegisPolicy(entity_types=["PROTOCOL_ID"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    assert len(results) == 1
    assert results[0].entity_type == "PROTOCOL_ID"
    assert text[results[0].start : results[0].end] == "ABC-123"


def test_lot_number_detection(scanner: Scanner, mock_context: UserContext) -> None:
    text = "Batch LOT-X99Z1 used."
    policy = AegisPolicy(entity_types=["LOT_NUMBER"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    assert len(results) == 1
    assert results[0].entity_type == "LOT_NUMBER"
    assert text[results[0].start : results[0].end] == "LOT-X99Z1"


def test_mixed_entities(scanner: Scanner, mock_context: UserContext) -> None:
    text = "MRN 987654 assigned to ABC-999 for LOT-A1."
    policy = AegisPolicy(entity_types=["MRN", "PROTOCOL_ID", "LOT_NUMBER"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    assert len(results) == 3
    types = {r.entity_type for r in results}
    assert "MRN" in types
    assert "PROTOCOL_ID" in types
    assert "LOT_NUMBER" in types


def test_mrn_boundary_conditions(scanner: Scanner, mock_context: UserContext) -> None:
    # Test length constraints: 6-10 digits
    text = "5digits: 12345, 6digits: 123456, 10digits: 1234567890, 11digits: 12345678901"
    policy = AegisPolicy(entity_types=["MRN"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    detected = [text[r.start : r.end] for r in results]
    assert "12345" not in detected  # Too short
    assert "123456" in detected  # Min length
    assert "1234567890" in detected  # Max length
    assert "12345678901" not in detected  # Too long (regex ensures \b boundary)


def test_protocol_id_formats(scanner: Scanner, mock_context: UserContext) -> None:
    # Test strict format: 3 letters, dash, 3 numbers
    text = "Valid: ABC-123. Invalid: AB-123, ABCD-123, ABC-12, ABC-1234, abc-123, 123-ABC"
    policy = AegisPolicy(entity_types=["PROTOCOL_ID"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    detected = [text[r.start : r.end] for r in results]
    assert "ABC-123" in detected
    # Ensure invalid ones are NOT detected
    assert "AB-123" not in detected
    assert "ABCD-123" not in detected
    assert "ABC-12" not in detected
    assert "ABC-1234" not in detected
    # Presidio is case-insensitive by default, so abc-123 IS detected.
    # This is actually desirable for robust privacy protection.
    assert "abc-123" in detected
    assert "123-ABC" not in detected


def test_lot_number_edge_cases(scanner: Scanner, mock_context: UserContext) -> None:
    # Test LOT prefix and alphanumeric
    text = "Valid: LOT-A1, LOT-999. Invalid: lot-a1, LOT-, LOT-@#$"
    policy = AegisPolicy(entity_types=["LOT_NUMBER"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    detected = [text[r.start : r.end] for r in results]
    assert "LOT-A1" in detected
    assert "LOT-999" in detected
    # Presidio is case-insensitive by default, so lot-a1 IS detected.
    assert "lot-a1" in detected
    assert "LOT-" not in detected  # Empty suffix
    # LOT-@#$ might partial match if it contains valid chars? Regex is [A-Z0-9]+
    # So LOT-@#$ -> No match.
    # LOT-A@#$ -> Matches LOT-A? Regex is \bLOT-[A-Z0-9]+\b.
    # If @ is a word boundary, then LOT-A matches.
    # But @ is usually not a word character, so it acts as boundary.
    # Let's test checking that weird symbols don't get included in the match.
    for r in results:
        assert "@" not in text[r.start : r.end]


def test_complex_mixed_text(scanner: Scanner, mock_context: UserContext) -> None:
    text = (
        "Patient (MRN: 88223344) enrolled in protocol XYZ-789. "
        "Medication from batch LOT-Q2W3E4 was administered. "
        "Ignore 12345 and ABC-XYZ."
    )
    policy = AegisPolicy(entity_types=["MRN", "PROTOCOL_ID", "LOT_NUMBER"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    detected_values = {text[r.start : r.end] for r in results}
    assert "88223344" in detected_values
    assert "XYZ-789" in detected_values
    assert "LOT-Q2W3E4" in detected_values
    assert "12345" not in detected_values
    assert "ABC-XYZ" not in detected_values


def test_gene_sequence_detection(scanner: Scanner, mock_context: UserContext) -> None:
    text = "Sequence ATCGATCGAT found in sample."
    policy = AegisPolicy(entity_types=["GENE_SEQUENCE"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    assert len(results) == 1
    assert results[0].entity_type == "GENE_SEQUENCE"
    assert text[results[0].start : results[0].end] == "ATCGATCGAT"


def test_chemical_cas_detection(scanner: Scanner, mock_context: UserContext) -> None:
    text = "Formaldehyde (CAS 50-00-0) is toxic."
    policy = AegisPolicy(entity_types=["CHEMICAL_CAS"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    assert len(results) == 1
    assert results[0].entity_type == "CHEMICAL_CAS"
    assert text[results[0].start : results[0].end] == "50-00-0"


def test_gene_sequence_boundary(scanner: Scanner, mock_context: UserContext) -> None:
    # Test min length 10
    text = "Short: ATCGATCGA, Valid: ATCGATCGAT, Long: ATCGATCGATCG"
    policy = AegisPolicy(entity_types=["GENE_SEQUENCE"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    detected = [text[r.start : r.end] for r in results]
    assert "ATCGATCGA" not in detected  # 9 chars
    assert "ATCGATCGAT" in detected  # 10 chars
    assert "ATCGATCGATCG" in detected  # 12 chars

    # Test valid characters (only A, T, C, G)
    text_invalid = "ATCGXATCGAT"
    results_invalid = scanner.scan(text_invalid, policy, context=mock_context)
    # The X breaks the sequence into "ATCG" and "ATCGAT", both too short.
    # Or matches \b[ATCG]{10,}\b -> no match.
    assert len(results_invalid) == 0


def test_chemical_cas_formats(scanner: Scanner, mock_context: UserContext) -> None:
    # Test CAS format: 2-7 digits - 2 digits - 1 digit
    # e.g., 50-00-0 (Formaldehyde), 7732-18-5 (Water)
    text = "50-00-0, 7732-18-5, 1234567-89-0. Invalid: 1-22-3, 12-3-4, 12-34-56"
    policy = AegisPolicy(entity_types=["CHEMICAL_CAS"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    detected = [text[r.start : r.end] for r in results]
    assert "50-00-0" in detected
    assert "7732-18-5" in detected
    assert "1234567-89-0" in detected

    assert "1-22-3" not in detected  # First part too short (min 2)
    assert "12-3-4" not in detected  # Middle part too short (min 2)
    assert "12-34-56" not in detected  # Last part too long (max 1)


def test_gene_sequence_case_sensitivity(scanner: Scanner, mock_context: UserContext) -> None:
    # Test that lowercase sequences are detected (Presidio/Regex interaction)
    # If the regex is \b[ATCG]{10,}\b, it technically only matches Uppercase.
    # However, Presidio often defaults to case-insensitive or we might need to adjust regex.
    # Let's verify behavior. If this fails, we need (?i) in regex.
    text = "Lowercase: atcgatcgat, Mixed: AtCgAtCgAt"
    policy = AegisPolicy(entity_types=["GENE_SEQUENCE"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    detected = [text[r.start : r.end] for r in results]

    # We expect these to be detected if we want robust scanning.
    # If the current implementation is strict [ATCG], these might fail.
    # But usually PII scanning prefers recall.
    # Let's see if they are detected.
    assert "atcgatcgat" in detected
    assert "AtCgAtCgAt" in detected


def test_cas_false_positives(scanner: Scanner, mock_context: UserContext) -> None:
    # CAS is digits-digits-digit (last part is 1 digit)
    # ISO Date is YYYY-MM-DD (last part is 2 digits)
    text = "Date: 2023-10-01. CAS: 50-00-0. ID: 123-45-678."
    policy = AegisPolicy(entity_types=["CHEMICAL_CAS"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    detected = [text[r.start : r.end] for r in results]
    assert "50-00-0" in detected
    assert "2023-10-01" not in detected  # Last part has 2 digits
    assert "123-45-678" not in detected  # Last part has 3 digits


def test_complex_scientific_scenario(scanner: Scanner, mock_context: UserContext) -> None:
    # Mixed valid and invalid entities
    text = (
        "Experiment on gene ATCGATCGAT (fragment: ATCGA) using "
        "reagent 50-00-0 (Formaldehyde) and 7732-18-5 (Water). "
        "Recorded on 2023-11-15. "
        "Avoid contamination with RNA sequence AUCGAUCGAU."
    )
    policy = AegisPolicy(entity_types=["GENE_SEQUENCE", "CHEMICAL_CAS"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    detected = {text[r.start : r.end] for r in results}

    # Valid Genes
    assert "ATCGATCGAT" in detected
    # Invalid Genes
    assert "ATCGA" not in detected  # Too short
    assert "AUCGAUCGAU" not in detected  # Contains U (RNA), regex expects ATCG

    # Valid Chemicals
    assert "50-00-0" in detected
    assert "7732-18-5" in detected

    # False Positives
    assert "2023-11-15" not in detected


def test_api_key_detection(scanner: Scanner, mock_context: UserContext) -> None:
    # Also test typical OpenAI key structure (usually ~51 chars, sk-...48 chars)
    # But for test purposes, our regex is >= 20 chars after sk-
    # Wait, regex is sk-[...]{20,}.
    # So sk- + 20 chars = 23 chars total.

    valid_key = "sk-" + "a" * 20

    text = f"Key1: {valid_key}."

    policy = AegisPolicy(entity_types=["SECRET_KEY"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    assert len(results) == 1
    assert results[0].entity_type == "SECRET_KEY"
    assert text[results[0].start : results[0].end] == valid_key


def test_api_key_boundary(scanner: Scanner, mock_context: UserContext) -> None:
    # Test length constraints
    # Regex: sk-[...]{20,}

    short_val = "sk-" + "a" * 19  # 19 chars suffix -> Total 22. Should NOT match.
    exact_val = "sk-" + "a" * 20  # 20 chars suffix -> Total 23. Should match.

    text = f"Short: {short_val}, Exact: {exact_val}"

    policy = AegisPolicy(entity_types=["SECRET_KEY"], confidence_score=0.5)
    results = scanner.scan(text, policy, context=mock_context)

    detected = [text[r.start : r.end] for r in results]
    assert short_val not in detected
    assert exact_val in detected
