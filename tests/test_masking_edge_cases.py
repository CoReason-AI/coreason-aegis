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
from presidio_analyzer import RecognizerResult

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, RedactionMode
from coreason_aegis.vault import VaultManager


@pytest.fixture
def masking_engine() -> MaskingEngine:
    return MaskingEngine(VaultManager())


def test_empty_results(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    text = "Nothing here."
    results: list[RecognizerResult] = []
    policy = AegisPolicy()
    masked, _ = masking_engine.mask(text, results, policy, "sess_empty", context=mock_context)
    assert masked == text


def test_empty_text(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    text = ""
    results: list[RecognizerResult] = []
    policy = AegisPolicy()
    masked, _ = masking_engine.mask(text, results, policy, "sess_empty_text", context=mock_context)
    assert masked == ""


def test_result_out_of_bounds(masking_engine: MaskingEngine) -> None:
    # Should throw error or handle gracefully?
    # Logic: text[start:end] will slice.
    # But replacement construction uses start/end.
    # masked_text[:start] + repl + masked_text[end:]
    # If start > len, slice works (empty).
    # If end > len, slice works.
    # But if indices are wrong relative to text content, we might get weird string duplications or cuts.
    # Presidio usually guarantees valid indices for the input text.
    pass


def test_policy_allow_list_case_sensitivity(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    # Check if allow list matches exact string.
    text = "John vs john"
    # John 0-4
    # john 8-12
    results = [
        RecognizerResult("PERSON", 0, 4, 1.0),
        RecognizerResult("PERSON", 8, 12, 1.0),
    ]
    policy = AegisPolicy(mode=RedactionMode.MASK, allow_list=["John"])

    masked, _ = masking_engine.mask(text, results, policy, "sess_case", context=mock_context)

    # "John" allowed -> kept.
    # "john" not in allow list -> masked.
    assert "John" in masked
    assert "[PATIENT]" in masked
    # masked should be "John vs [PATIENT]"
    assert masked == "John vs [PATIENT]"
