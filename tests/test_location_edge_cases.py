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
from coreason_identity.models import UserContext

from coreason_aegis.main import Aegis
from coreason_aegis.models import AegisPolicy
from coreason_aegis.scanner import Scanner


@pytest.fixture
def scanner() -> Scanner:
    return Scanner()


@pytest.mark.integration
def test_ambiguous_location_vs_name(scanner: Scanner, mock_context: UserContext) -> None:
    """
    Test differentiation between ambiguous names that are also locations.
    e.g., "Washington" (Name) vs "Washington" (Location).
    Note: Standard NER models struggle with this without context, but we check baseline behavior.
    """
    text = "George Washington visited Washington."
    policy = AegisPolicy(entity_types=["PERSON", "LOCATION"], confidence_score=0.4)
    results = scanner.scan(text, policy, context=mock_context)

    detected_texts = [text[r.start : r.end] for r in results]
    entity_types = [r.entity_type for r in results]

    # We expect "George Washington" to be PERSON
    # We expect "Washington" (the city) to be LOCATION

    assert "George Washington" in detected_texts
    assert "PERSON" in entity_types

    # This assertion depends heavily on the model (en_core_web_lg)
    # Ideally it catches the second Washington as Location (GPE)
    if "Washington" in detected_texts:
        # Find index of second "Washington" in text
        # "George Washington visited Washington."
        #  0123456789012345678901234567890123456
        #  George Washington (0-17)
        #  Washington (26-36)

        # Check if we have a result starting > 20
        loc_results = [r for r in results if r.start > 20]
        if loc_results:
            assert loc_results[0].entity_type == "LOCATION"


@pytest.mark.integration
def test_multi_word_locations(scanner: Scanner, mock_context: UserContext) -> None:
    """
    Test detection of multi-word locations.
    """
    text = "I live in New York and work in San Francisco."
    policy = AegisPolicy(entity_types=["LOCATION"], confidence_score=0.4)
    results = scanner.scan(text, policy, context=mock_context)

    detected = {text[r.start : r.end] for r in results}

    assert "New York" in detected
    assert "San Francisco" in detected


@pytest.mark.integration
def test_location_with_punctuation(scanner: Scanner, mock_context: UserContext) -> None:
    """
    Test detection of locations with punctuation.
    """
    text = "He is from St. Louis, MO."
    policy = AegisPolicy(entity_types=["LOCATION"], confidence_score=0.4)
    results = scanner.scan(text, policy, context=mock_context)

    detected = {text[r.start : r.end] for r in results}

    # "St. Louis" should be detected. "MO" might also be detected as GPE.
    assert "St. Louis" in detected


@pytest.mark.integration
def test_repeated_locations_consistency(mock_context: UserContext) -> None:
    """
    Test that repeated locations map to the same token in REPLACE mode.
    """
    aegis = Aegis()
    # Default mode is REPLACE, ensure LOCATION is in default policy
    # The default AegisPolicy now includes LOCATION, so Aegis() uses it.

    text = "I flew from London to Paris, then back to London."
    session_id = "test_loc_consistency"

    sanitized, deid_map = aegis.sanitize(text, session_id, context=mock_context)

    # Expect: "I flew from [LOCATION_A] to [LOCATION_B], then back to [LOCATION_A]."

    assert "[LOCATION_A]" in sanitized
    assert "[LOCATION_B]" in sanitized

    # Check counts
    assert sanitized.count("[LOCATION_A]") == 2
    assert sanitized.count("[LOCATION_B]") == 1

    # Check vault
    assert deid_map.mappings["[LOCATION_A]"] == "London" or deid_map.mappings["[LOCATION_B]"] == "London"
    assert deid_map.mappings["[LOCATION_A]"] == "Paris" or deid_map.mappings["[LOCATION_B]"] == "Paris"


@pytest.mark.integration
def test_complex_mixed_entity_paragraph(mock_context: UserContext) -> None:
    """
    Test a complex paragraph with multiple entity types including locations.
    """
    aegis = Aegis()
    # Default policy includes PERSON, EMAIL, PHONE, IP, DATE, SECRET_KEY, LOCATION

    text = (
        "On 2024-01-01, Dr. Alice Smith traveled from Boston to Seattle. "
        "She contacted bob@example.com regarding Patient John Doe (MRN: 12345678). "
        "The server at 192.168.0.1 showed logs from Tokyo."
    )
    session_id = "test_complex_loc"

    sanitized, deid_map = aegis.sanitize(text, session_id, context=mock_context)

    # Check that original PII is gone
    assert "Alice Smith" not in sanitized
    assert "Boston" not in sanitized
    assert "Seattle" not in sanitized
    assert "bob@example.com" not in sanitized
    assert "John Doe" not in sanitized
    assert "192.168.0.1" not in sanitized
    assert "Tokyo" not in sanitized

    # Check for presence of tokens
    # Note: tokens assigned alphabetically A, B, C based on appearance
    assert "[DATE_" in sanitized
    assert "[PATIENT_" in sanitized  # Dr. Alice might be PATIENT or just PERSON mapped to PATIENT
    assert "[LOCATION_" in sanitized
    assert "[EMAIL_" in sanitized
    assert "[IP_" in sanitized

    # Verify we have at least 3 distinct locations (Boston, Seattle, Tokyo)
    # Use the map to verify
    locations_in_map = [val for val in deid_map.mappings.values() if val in ["Boston", "Seattle", "Tokyo"]]
    assert len(locations_in_map) == 3
