from datetime import datetime, timedelta, timezone

from coreason_aegis.models import AegisPolicy, DeIdentificationMap, RedactionMode


def test_redaction_mode_values() -> None:
    assert RedactionMode.MASK == "MASK"
    assert RedactionMode.REPLACE == "REPLACE"
    assert RedactionMode.SYNTHETIC == "SYNTHETIC"


def test_aegis_policy_defaults() -> None:
    policy = AegisPolicy()
    assert policy.allow_list == []
    assert "PERSON" in policy.entity_types
    assert policy.mode == RedactionMode.REPLACE
    assert policy.confidence_score == 0.85


def test_aegis_policy_custom() -> None:
    policy = AegisPolicy(allow_list=["Tylenol"], entity_types=["US_SSN"], mode=RedactionMode.MASK, confidence_score=0.9)
    assert policy.allow_list == ["Tylenol"]
    assert policy.entity_types == ["US_SSN"]
    assert policy.mode == RedactionMode.MASK
    assert policy.confidence_score == 0.9


def test_deidentification_map_defaults() -> None:
    session_id = "sess_123"
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    deid_map = DeIdentificationMap(session_id=session_id, expires_at=expires_at)

    assert deid_map.session_id == session_id
    assert deid_map.mappings == {}
    assert isinstance(deid_map.created_at, datetime)
    assert deid_map.created_at.tzinfo == timezone.utc
    assert deid_map.expires_at == expires_at


def test_deidentification_map_custom() -> None:
    session_id = "sess_123"
    mappings = {"[TOKEN]": "REAL"}
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(hours=1)

    deid_map = DeIdentificationMap(
        session_id=session_id, mappings=mappings, created_at=created_at, expires_at=expires_at
    )

    assert deid_map.session_id == session_id
    assert deid_map.mappings == mappings
    assert deid_map.created_at == created_at
    assert deid_map.expires_at == expires_at
