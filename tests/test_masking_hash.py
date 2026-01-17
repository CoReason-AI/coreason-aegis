# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

import hashlib

import pytest
from presidio_analyzer import RecognizerResult

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, RedactionMode
from coreason_aegis.vault import VaultManager


@pytest.fixture
def masking_engine() -> MaskingEngine:
    return MaskingEngine(VaultManager())


def test_hash_consistency(masking_engine: MaskingEngine) -> None:
    text = "SecretData"
    results = [RecognizerResult("DATA", 0, 10, 1.0)]
    policy = AegisPolicy(mode=RedactionMode.HASH)

    masked1, _ = masking_engine.mask(text, results, policy, "sess1")
    masked2, _ = masking_engine.mask(text, results, policy, "sess2")

    assert masked1 == masked2
    assert masked1 == hashlib.sha256("SecretData".encode()).hexdigest()


def test_hash_no_vault_storage(masking_engine: MaskingEngine) -> None:
    # HASH mode is one-way, shouldn't store in vault mapping ideally?
    # Logic in masking.py:
    # elif policy.mode == RedactionMode.HASH:
    #    replacement = ...
    # It does NOT add to deid_map.mappings.
    # Verify this.

    text = "John"
    results = [RecognizerResult("PERSON", 0, 4, 1.0)]
    policy = AegisPolicy(mode=RedactionMode.HASH)

    _, deid_map = masking_engine.mask(text, results, policy, "sess_hash")
    assert len(deid_map.mappings) == 0


def test_synthetic_consistency(masking_engine: MaskingEngine) -> None:
    # Synthetic should be deterministic based on hash of text
    text = "John Doe"
    results = [RecognizerResult("PERSON", 0, 8, 1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)

    masked1, _ = masking_engine.mask(text, results, policy, "sess1")
    masked2, _ = masking_engine.mask(text, results, policy, "sess2")

    assert masked1 == masked2
    assert masked1 != "John Doe"


def test_synthetic_different_inputs(masking_engine: MaskingEngine) -> None:
    text1 = "John Doe"
    text2 = "Jane Doe"
    # Assuming standard setup
    results1 = [RecognizerResult("PERSON", 0, 8, 1.0)]
    results2 = [RecognizerResult("PERSON", 0, 8, 1.0)]  # same indices in their respective texts

    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC)

    masked1, _ = masking_engine.mask(text1, results1, policy, "sess")
    masked2, _ = masking_engine.mask(text2, results2, policy, "sess")

    # High probability they are different
    assert masked1 != masked2
