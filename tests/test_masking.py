from datetime import datetime, timedelta, timezone

import pytest
from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, DeIdentificationMap, RedactionMode
from coreason_aegis.vault import VaultManager
from presidio_analyzer import RecognizerResult


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

    # PERSON should map to PATIENT
    assert masked_text == "[PATIENT_A] met [PATIENT_A]."
    assert len(deid_map.mappings) == 1
    assert deid_map.mappings["[PATIENT_A]"] == "John"


def test_mask_replace_mode_different_entities(engine: MaskingEngine) -> None:
    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    text = "John met Jane."
    results = [
        RecognizerResult("PERSON", 0, 4, 1.0),
        RecognizerResult("PERSON", 9, 13, 1.0),
    ]
    session_id = "sess_1"

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    # With Pass 1 (Forward Assignment), John appears first -> PATIENT_A
    # Jane appears second -> PATIENT_B
    assert masked_text == "[PATIENT_A] met [PATIENT_B]."
    assert len(deid_map.mappings) == 2
    assert deid_map.mappings["[PATIENT_A]"] == "John"
    assert deid_map.mappings["[PATIENT_B]"] == "Jane"


def test_mask_mask_mode(engine: MaskingEngine) -> None:
    policy = AegisPolicy(mode=RedactionMode.MASK)
    text = "John."
    results = [RecognizerResult("PERSON", 0, 4, 1.0)]
    session_id = "sess_1"

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    assert masked_text == "[PATIENT]."
    assert len(deid_map.mappings) == 0


def test_mask_synthetic_mode(engine: MaskingEngine) -> None:
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)
    text = "John met Jane."
    results = [
        RecognizerResult("PERSON", 0, 4, 1.0),
        RecognizerResult("PERSON", 9, 13, 1.0),
    ]
    session_id = "sess_1"

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    # Should be replaced by names, not tokens
    assert "[PATIENT" not in masked_text
    assert "John" not in masked_text
    assert "Jane" not in masked_text
    # Faker names might have spaces (e.g. "John Smith"), so we can't strict split count
    # assert len(masked_text.split()) == 3

    # Verify no mapping
    assert len(deid_map.mappings) == 0

    # Verify determinism
    masked_text_2, _ = engine.mask(text, results, policy, session_id)
    assert masked_text == masked_text_2


def test_mask_synthetic_mode_types(engine: MaskingEngine) -> None:
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)
    text = "test@example.com at 127.0.0.1 call 555-1234 on 2023-01-01"
    results = [
        RecognizerResult("EMAIL_ADDRESS", 0, 16, 1.0),
        RecognizerResult("IP_ADDRESS", 20, 29, 1.0),
        RecognizerResult("PHONE_NUMBER", 35, 43, 1.0),
        RecognizerResult("DATE_TIME", 47, 57, 1.0),
    ]
    session_id = "sess_types"

    masked_text, _ = engine.mask(text, results, policy, session_id)
    parts = masked_text.split()

    # Check replacements
    assert "@" in parts[0]  # Email
    assert "." in parts[2]  # IP
    # Phone usually has digits, format varies
    assert any(c.isdigit() for c in parts[4])
    # Date format varies, but shouldn't be the original
    assert "2023-01-01" not in masked_text


def test_mask_synthetic_mode_fallback(engine: MaskingEngine) -> None:
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)
    text = "MRN123456 and RANDOM"
    results = [
        RecognizerResult("MRN", 0, 9, 1.0),
        RecognizerResult("UNKNOWN_TYPE", 14, 20, 1.0),
    ]
    session_id = "sess_fallback"

    masked_text, _ = engine.mask(text, results, policy, session_id)
    parts = masked_text.split()

    # MRN triggers ID logic (random number)
    assert parts[0].isdigit()
    # UNKNOWN_TYPE triggers generic word
    assert parts[2].isalpha()


def test_mask_synthetic_consistency_across_instances(vault: VaultManager) -> None:
    # Determinism should hold even with new engine instances
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)
    text = "John"
    results = [RecognizerResult("PERSON", 0, 4, 1.0)]
    session_id = "sess_1"

    engine1 = MaskingEngine(vault)
    masked1, _ = engine1.mask(text, results, policy, session_id)

    engine2 = MaskingEngine(vault)
    masked2, _ = engine2.mask(text, results, policy, session_id)

    assert masked1 == masked2


def test_mask_unknown_mode(engine: MaskingEngine) -> None:
    # Force an unknown mode
    policy = AegisPolicy()
    policy.mode = "UNKNOWN"  # type: ignore
    text = "John."
    results = [RecognizerResult("PERSON", 0, 4, 1.0)]
    session_id = "sess_1"

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    # Should default to simple replacement
    assert masked_text == "[PATIENT]."


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
    assert masked_text == "John met [PATIENT_A]."
    assert len(deid_map.mappings) == 1
    assert deid_map.mappings["[PATIENT_A]"] == "Jane"


def test_existing_session_consistency(engine: MaskingEngine, vault: VaultManager) -> None:
    session_id = "sess_persistent"
    # Pre-populate vault
    deid_map = DeIdentificationMap(
        session_id=session_id,
        mappings={"[PATIENT_A]": "John"},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    vault.save_map(deid_map)

    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    text = "John is back."
    results = [RecognizerResult("PERSON", 0, 4, 1.0)]

    masked_text, updated_map = engine.mask(text, results, policy, session_id)

    assert masked_text == "[PATIENT_A] is back."
    assert updated_map.mappings["[PATIENT_A]"] == "John"


def test_suffix_generation(engine: MaskingEngine) -> None:
    # Test internal helper
    assert engine._generate_suffix(0) == "A"
    assert engine._generate_suffix(25) == "Z"
    assert engine._generate_suffix(26) == "AA"


def test_mask_high_volume_entities(engine: MaskingEngine) -> None:
    # Simulate a document with many unique entities to force suffix transitions
    # We want to cover A-Z, AA-ZZ transitions.
    # 26 (A-Z) + 26*26 (AA-ZZ) = 702 entities.
    # Let's generate 705 distinct names.

    count = 705
    entities = [f"Person_{i}" for i in range(count)]
    text = " ".join(entities)

    # Manually construct results (simulating Scanner)
    results = []
    cursor = 0
    for entity in entities:
        start = text.find(entity, cursor)
        end = start + len(entity)
        results.append(RecognizerResult("PERSON", start, end, 1.0))
        cursor = end + 1  # +1 for space

    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    session_id = "sess_high_vol"

    masked_text, deid_map = engine.mask(text, results, policy, session_id)

    # Check that we have 705 unique mappings
    assert len(deid_map.mappings) == count

    # Check specific tokens
    # First should be A
    assert deid_map.mappings["[PATIENT_A]"] == "Person_0"
    # 26th (index 25) should be Z
    assert deid_map.mappings["[PATIENT_Z]"] == "Person_25"
    # 27th (index 26) should be AA
    assert deid_map.mappings["[PATIENT_AA]"] == "Person_26"
    # 702th (index 701) should be ZZ
    assert deid_map.mappings["[PATIENT_ZZ]"] == "Person_701"
    # 703th (index 702) should be AAA
    assert deid_map.mappings["[PATIENT_AAA]"] == "Person_702"

    # Verify masked text format roughly
    assert "[PATIENT_A]" in masked_text
    assert "[PATIENT_AAA]" in masked_text
