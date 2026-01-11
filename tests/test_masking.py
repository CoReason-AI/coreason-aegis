from datetime import datetime, timedelta, timezone

import pytest
from presidio_analyzer import RecognizerResult

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, DeIdentificationMap, RedactionMode
from coreason_aegis.vault import VaultManager


@pytest.fixture
def vault() -> VaultManager:
    return VaultManager()


@pytest.fixture
def engine(vault: VaultManager) -> MaskingEngine:
    return MaskingEngine(vault)


def test_mask_replace_mode_consistency(engine: MaskingEngine) -> None:
    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    text = "John met John."
    results = [
        RecognizerResult("PERSON", 0, 4, 1.0),
        RecognizerResult("PERSON", 9, 13, 1.0),
    ]
    session_id = "sess_1"

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    assert masked_text == "[PERSON_A] met [PERSON_A]."
    assert len(deid_map.mappings) == 1
    assert deid_map.mappings["[PERSON_A]"] == "John"


def test_mask_replace_mode_different_entities(engine: MaskingEngine) -> None:
    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    text = "John met Jane."
    results = [
        RecognizerResult("PERSON", 0, 4, 1.0),
        RecognizerResult("PERSON", 9, 13, 1.0),
    ]
    session_id = "sess_1"

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    assert masked_text == "[PERSON_B] met [PERSON_A]."
    assert len(deid_map.mappings) == 2
    assert deid_map.mappings["[PERSON_A]"] == "Jane"
    assert deid_map.mappings["[PERSON_B]"] == "John"


def test_mask_mask_mode(engine: MaskingEngine) -> None:
    policy = AegisPolicy(mode=RedactionMode.MASK)
    text = "John."
    results = [RecognizerResult("PERSON", 0, 4, 1.0)]
    session_id = "sess_1"

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    assert masked_text == "[PERSON]."
    assert len(deid_map.mappings) == 0


def test_mask_synthetic_mode(engine: MaskingEngine) -> None:
    # SYNTHETIC mode currently falls back to MASK
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)
    text = "John."
    results = [RecognizerResult("PERSON", 0, 4, 1.0)]
    session_id = "sess_1"

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    assert masked_text == "[PERSON]."
    assert len(deid_map.mappings) == 0


def test_mask_unknown_mode(engine: MaskingEngine) -> None:
    # Force an unknown mode
    policy = AegisPolicy()
    policy.mode = "UNKNOWN"  # type: ignore
    text = "John."
    results = [RecognizerResult("PERSON", 0, 4, 1.0)]
    session_id = "sess_1"

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    # Should default to simple replacement (like MASK but maybe without brackets if code fell through?
    # Logic: else replacement = f"[{result.entity_type}]")
    assert masked_text == "[PERSON]."


def test_mask_allow_list(engine: MaskingEngine) -> None:
    policy = AegisPolicy(allow_list=["John"], mode=RedactionMode.REPLACE)
    text = "John met Jane."
    results = [
        RecognizerResult("PERSON", 0, 4, 1.0),
        RecognizerResult("PERSON", 9, 13, 1.0),
    ]
    session_id = "sess_1"

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    # John should be skipped, Jane masked
    assert masked_text == "John met [PERSON_A]."
    assert len(deid_map.mappings) == 1
    assert deid_map.mappings["[PERSON_A]"] == "Jane"


def test_existing_session_consistency(engine: MaskingEngine, vault: VaultManager) -> None:
    session_id = "sess_persistent"
    # Pre-populate vault
    deid_map = DeIdentificationMap(
        session_id=session_id,
        mappings={"[PERSON_A]": "John"},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    vault.save_map(deid_map)

    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    text = "John is back."
    results = [RecognizerResult("PERSON", 0, 4, 1.0)]

    masked_text, updated_map = engine.mask(text, results, policy, session_id)

    assert masked_text == "[PERSON_A] is back."
    assert updated_map.mappings["[PERSON_A]"] == "John"


def test_suffix_generation(engine: MaskingEngine) -> None:
    # Test internal helper
    assert engine._generate_suffix(0) == "A"
    assert engine._generate_suffix(25) == "Z"
    assert engine._generate_suffix(26) == "26"
