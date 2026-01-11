import hashlib
from typing import Generator

import pytest
from presidio_analyzer import RecognizerResult

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, RedactionMode
from coreason_aegis.vault import VaultManager


@pytest.fixture
def masking_engine() -> Generator[MaskingEngine, None, None]:
    vault = VaultManager()
    yield MaskingEngine(vault)


def test_masking_hash_mode_simple(masking_engine: MaskingEngine) -> None:
    """
    Test that HASH mode replaces entities with their SHA-256 hex digest.
    """
    text = "My name is John Doe."
    # Simulate scanner result for "John Doe" (indices 11 to 19)
    results = [RecognizerResult(entity_type="PERSON", start=11, end=19, score=1.0)]

    policy = AegisPolicy(mode=RedactionMode.HASH, entity_types=["PERSON"])
    session_id = "test_session_hash"

    masked_text, deid_map = masking_engine.mask(text, results, policy, session_id)

    # Calculate expected hash
    expected_hash = hashlib.sha256("John Doe".encode("utf-8")).hexdigest()

    # Expect: "My name is <hash>."
    assert masked_text == f"My name is {expected_hash}."


def test_masking_hash_consistency(masking_engine: MaskingEngine) -> None:
    """
    Test that hashing is deterministic.
    """
    text = "John Doe"
    results = [RecognizerResult(entity_type="PERSON", start=0, end=8, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.HASH)
    session_id = "session_1"

    masked_text_1, _ = masking_engine.mask(text, results, policy, session_id)
    masked_text_2, _ = masking_engine.mask(text, results, policy, "session_2")

    assert masked_text_1 == masked_text_2
