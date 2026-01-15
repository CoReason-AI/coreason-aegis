# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

from presidio_analyzer import RecognizerResult

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, RedactionMode
from coreason_aegis.vault import VaultManager


def test_unknown_entity_type() -> None:
    """
    Edge Case: Entities that are NOT in the normalization map should retain their original type.
    """
    vault = VaultManager()
    engine = MaskingEngine(vault)
    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    session_id = "sess_unknown"

    text = "Google is an organization."
    # ORGANIZATION is not in our normalization list
    results = [RecognizerResult("ORGANIZATION", 0, 6, 1.0)]

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    # Should be [ORGANIZATION_A]
    assert "[ORGANIZATION_A]" in deid_map.mappings
    assert deid_map.mappings["[ORGANIZATION_A]"] == "Google"
    assert masked_text == "[ORGANIZATION_A] is an organization."


def test_mixed_normalization() -> None:
    """
    Complex Scenario: Mix of normalized (PERSON->PATIENT) and unnormalized (LOCATION) entities.
    """
    vault = VaultManager()
    engine = MaskingEngine(vault)
    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    session_id = "sess_mixed"

    text = "John went to Paris."
    # John -> PERSON -> PATIENT
    # Paris -> LOCATION -> LOCATION (Unchanged)
    results = [
        RecognizerResult("PERSON", 0, 4, 1.0),
        RecognizerResult("LOCATION", 13, 18, 1.0),
    ]

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    assert "[PATIENT_A]" in deid_map.mappings
    assert "[LOCATION_A]" in deid_map.mappings

    assert deid_map.mappings["[PATIENT_A]"] == "John"
    assert deid_map.mappings["[LOCATION_A]"] == "Paris"

    # Order verification (John is first)
    assert masked_text == "[PATIENT_A] went to [LOCATION_A]."


def test_namespace_collision() -> None:
    """
    Complex Scenario: Two different raw types resolving to the same normalized type.
    They should share the suffix counter.

    Scenario:
    1. '2023-01-01' detected as DATE_TIME -> Normalizes to DATE
    2. 'January' detected as DATE (hypothetical raw type) -> Normalizes to DATE (identity)

    Result should be [DATE_A] and [DATE_B].
    """
    vault = VaultManager()
    engine = MaskingEngine(vault)
    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    session_id = "sess_collision"

    text = "Date 1: 2023-01-01. Date 2: January."

    # Simulate results
    # 2023-01-01 at index 8 (len 10)
    # January at index 28 (len 7)
    results = [
        RecognizerResult("DATE_TIME", 8, 18, 1.0),
        RecognizerResult("DATE", 28, 35, 1.0),
    ]

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    # Both map to DATE namespace
    assert "[DATE_A]" in deid_map.mappings
    assert "[DATE_B]" in deid_map.mappings

    # Verification of assignment order (sorted by start index)
    # DATE_TIME (start 8) -> A
    # DATE (start 28) -> B

    assert deid_map.mappings["[DATE_A]"] == "2023-01-01"
    assert deid_map.mappings["[DATE_B]"] == "January"

    assert masked_text == "Date 1: [DATE_A]. Date 2: [DATE_B]."


def test_synthetic_mode_with_normalization() -> None:
    """
    Edge Case: Ensure SYNTHETIC mode still works and uses the original entity type
    for generation logic (e.g. EMAIL_ADDRESS triggers email faker), despite normalization.
    """
    vault = VaultManager()
    engine = MaskingEngine(vault)
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)
    session_id = "sess_synth_norm"

    text = "Contact test@example.com"
    # EMAIL_ADDRESS would normalize to EMAIL in REPLACE mode.
    # But in SYNTHETIC mode, we need to ensure it generates an email.
    results = [RecognizerResult("EMAIL_ADDRESS", 8, 24, 1.0)]

    masked_text, _ = engine.mask(text, results, policy, session_id)

    # Check that it looks like an email (contains @)
    # If it fell back to generic word (because it saw "EMAIL" instead of "EMAIL_ADDRESS"),
    # it likely wouldn't have @ (Faker word).
    assert "@" in masked_text
    assert "test@example.com" not in masked_text
