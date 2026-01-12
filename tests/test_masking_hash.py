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


def test_masking_hash_unicode(masking_engine: MaskingEngine) -> None:
    """
    Test that hashing handles Unicode characters correctly.
    """
    # "Renée" contains a non-ASCII character
    text = "Contact Renée for details."
    # Indices: "Renée" starts at 8, ends at 13
    results = [RecognizerResult(entity_type="PERSON", start=8, end=13, score=1.0)]

    policy = AegisPolicy(mode=RedactionMode.HASH, entity_types=["PERSON"])
    session_id = "test_session_unicode"

    masked_text, _ = masking_engine.mask(text, results, policy, session_id)

    expected_hash = hashlib.sha256("Renée".encode("utf-8")).hexdigest()
    assert masked_text == f"Contact {expected_hash} for details."


def test_masking_hash_repeated_and_multiple(masking_engine: MaskingEngine) -> None:
    """
    Test that repeated entities get the same hash and distinct entities get different hashes.
    """
    text = "John and Jane went to see John."
    # "John" at 0-4
    # "Jane" at 9-13
    # "John" at 26-30
    results = [
        RecognizerResult(entity_type="PERSON", start=0, end=4, score=1.0),
        RecognizerResult(entity_type="PERSON", start=9, end=13, score=1.0),
        RecognizerResult(entity_type="PERSON", start=26, end=30, score=1.0),
    ]

    policy = AegisPolicy(mode=RedactionMode.HASH, entity_types=["PERSON"])
    session_id = "test_session_multiple"

    masked_text, _ = masking_engine.mask(text, results, policy, session_id)

    hash_john = hashlib.sha256("John".encode("utf-8")).hexdigest()
    hash_jane = hashlib.sha256("Jane".encode("utf-8")).hexdigest()

    # The resulting string should replace occurrences in place
    expected_text = f"{hash_john} and {hash_jane} went to see {hash_john}."

    assert masked_text == expected_text
    assert hash_john != hash_jane
