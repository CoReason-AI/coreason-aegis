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
from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, RedactionMode
from coreason_aegis.vault import VaultManager
from coreason_identity.models import UserContext
from faker import Faker


@pytest.fixture
def vault_manager() -> VaultManager:
    return VaultManager()


@pytest.fixture
def masking_engine(vault_manager: VaultManager) -> MaskingEngine:
    return MaskingEngine(vault_manager)


def test_masking_initialization(masking_engine: MaskingEngine) -> None:
    assert masking_engine is not None
    assert isinstance(masking_engine.faker, Faker)


def test_generate_suffix() -> None:
    assert MaskingEngine._generate_suffix(0) == "A"
    assert MaskingEngine._generate_suffix(25) == "Z"
    assert MaskingEngine._generate_suffix(26) == "AA"
    assert MaskingEngine._generate_suffix(27) == "AB"


def test_normalize_entity_type() -> None:
    assert MaskingEngine._normalize_entity_type("PERSON") == "PATIENT"
    assert MaskingEngine._normalize_entity_type("DATE_TIME") == "DATE"
    assert MaskingEngine._normalize_entity_type("EMAIL_ADDRESS") == "EMAIL"
    assert MaskingEngine._normalize_entity_type("UNKNOWN") == "UNKNOWN"


def test_mask_mode_mask(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    from presidio_analyzer import RecognizerResult

    text = "John Doe"
    results = [RecognizerResult("PERSON", 0, 8, 1.0)]
    policy = AegisPolicy(mode=RedactionMode.MASK)
    session_id = "sess1"

    masked, _ = masking_engine.mask(text, results, policy, session_id, context=mock_context)
    assert masked == "[PATIENT]"


def test_mask_mode_replace(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    from presidio_analyzer import RecognizerResult

    text = "John Doe"
    results = [RecognizerResult("PERSON", 0, 8, 1.0)]
    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    session_id = "sess2"

    masked, deid_map = masking_engine.mask(text, results, policy, session_id, context=mock_context)
    assert masked == "[PATIENT_A]"
    assert deid_map.mappings["[PATIENT_A]"] == "John Doe"


def test_mask_mode_replace_reuse(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    # Test reusing existing token
    from presidio_analyzer import RecognizerResult

    text = "John Doe again"
    results = [RecognizerResult("PERSON", 0, 8, 1.0)]
    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    session_id = "sess_reuse"

    # First pass
    masking_engine.mask(
        "John Doe", [RecognizerResult("PERSON", 0, 8, 1.0)], policy, session_id, context=mock_context
    )

    # Second pass
    masked, deid_map = masking_engine.mask(text, results, policy, session_id, context=mock_context)
    assert masked == "[PATIENT_A] again"
    assert deid_map.mappings["[PATIENT_A]"] == "John Doe"


def test_mask_mode_synthetic(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    from presidio_analyzer import RecognizerResult

    text = "John Doe"
    results = [RecognizerResult("PERSON", 0, 8, 1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)
    session_id = "sess3"

    masked, _ = masking_engine.mask(text, results, policy, session_id, context=mock_context)
    assert masked != "John Doe"
    assert isinstance(masked, str)
    # Check consistency
    masked2, _ = masking_engine.mask(text, results, policy, session_id, context=mock_context)
    assert masked == masked2


def test_mask_mode_hash(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    from presidio_analyzer import RecognizerResult

    text = "John Doe"
    results = [RecognizerResult("PERSON", 0, 8, 1.0)]
    policy = AegisPolicy(mode=RedactionMode.HASH)
    session_id = "sess4"

    masked, _ = masking_engine.mask(text, results, policy, session_id, context=mock_context)
    # sha256 of John Doe
    import hashlib

    expected = hashlib.sha256("John Doe".encode()).hexdigest()
    assert masked == expected


def test_allow_list(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    from presidio_analyzer import RecognizerResult

    text = "Tylenol"
    results = [RecognizerResult("MEDICATION", 0, 7, 1.0)]
    policy = AegisPolicy(mode=RedactionMode.MASK, allow_list=["Tylenol"])
    session_id = "sess5"

    masked, _ = masking_engine.mask(text, results, policy, session_id, context=mock_context)
    assert masked == "Tylenol"


def test_overlapping_entities(masking_engine: MaskingEngine) -> None:
    # Test collision handling: Presidio can return overlapping entities.
    pass


def test_multiple_entities_order(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    from presidio_analyzer import RecognizerResult

    text = "John and Jane"
    # John: 0-4, Jane: 9-13
    results = [
        RecognizerResult("PERSON", 0, 4, 1.0),
        RecognizerResult("PERSON", 9, 13, 1.0),
    ]
    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    session_id = "sess_multi"

    masked, _ = masking_engine.mask(text, results, policy, session_id, context=mock_context)
    assert masked == "[PATIENT_A] and [PATIENT_B]"


def test_synthetic_fallback(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    """Test fallback logic for synthetic data generation."""
    from presidio_analyzer import RecognizerResult

    text = "SomeRandomThing"
    # Case 1: ID/NUMBER/MRN fallback
    results_mrn = [RecognizerResult("MRN", 0, 15, 1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)

    masked_mrn, _ = masking_engine.mask(text, results_mrn, policy, "sess_fallback_mrn", context=mock_context)
    # Should be digits
    assert masked_mrn.isdigit()

    # Case 2: Generic fallback
    results_generic = [RecognizerResult("UNKNOWN_TYPE", 0, 15, 1.0)]
    masked_generic, _ = masking_engine.mask(
        text, results_generic, policy, "sess_fallback_gen", context=mock_context
    )
    assert isinstance(masked_generic, str)
    assert masked_generic != text
    assert masked_generic != masked_mrn

    # Coverage for line 96 (seeding logic):
    # This is implicitly covered by test_mask_mode_synthetic, but let's double check determinism for custom types
    masked_generic_2, _ = masking_engine.mask(
        text, results_generic, policy, "sess_fallback_gen", context=mock_context
    )
    assert masked_generic == masked_generic_2


def test_synthetic_types(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    """Test synthetic generation for specific types coverage."""
    from presidio_analyzer import RecognizerResult

    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)

    # EMAIL
    res_email = [RecognizerResult("EMAIL_ADDRESS", 0, 5, 1.0)]
    masked, _ = masking_engine.mask("a@b.c", res_email, policy, "sess_syn_types", context=mock_context)
    assert "@" in masked

    # PHONE
    res_phone = [RecognizerResult("PHONE_NUMBER", 0, 3, 1.0)]
    masked, _ = masking_engine.mask("123", res_phone, policy, "sess_syn_types", context=mock_context)
    assert any(c.isdigit() for c in masked)

    # IP
    res_ip = [RecognizerResult("IP_ADDRESS", 0, 3, 1.0)]
    masked, _ = masking_engine.mask("1.1", res_ip, policy, "sess_syn_types", context=mock_context)
    assert "." in masked

    # DATE
    res_date = [RecognizerResult("DATE_TIME", 0, 3, 1.0)]
    masked, _ = masking_engine.mask("now", res_date, policy, "sess_syn_types", context=mock_context)
    assert isinstance(masked, str)
