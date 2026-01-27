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
from presidio_analyzer import RecognizerResult

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, RedactionMode
from coreason_aegis.vault import VaultManager


@pytest.fixture
def masking_engine() -> MaskingEngine:
    return MaskingEngine(VaultManager())


def test_complex_replacement_sequence(masking_engine: MaskingEngine) -> None:
    # A B A C B A
    # A -> [TOKEN_A]
    # B -> [TOKEN_B]
    # C -> [TOKEN_C]
    # Verify reusing tokens and creating new ones in mixed order
    text = "John met Jane. John liked Jane. Then Bob came. John left."
    # John: 0-4, 15-19, 47-51
    # Jane: 9-13, 26-30
    # Bob: 37-40

    results = [
        RecognizerResult("PERSON", 0, 4, 1.0),
        RecognizerResult("PERSON", 9, 13, 1.0),
        RecognizerResult("PERSON", 15, 19, 1.0),
        RecognizerResult("PERSON", 26, 30, 1.0),
        RecognizerResult("PERSON", 37, 40, 1.0),
        RecognizerResult("PERSON", 47, 51, 1.0),
    ]

    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    masked, deid_map = masking_engine.mask(text, results, policy, "sess_complex", "test_owner")

    expected = "[PATIENT_A] met [PATIENT_B]. [PATIENT_A] liked [PATIENT_B]. Then [PATIENT_C] came. [PATIENT_A] left."
    assert masked == expected
    assert deid_map.mappings["[PATIENT_A]"] == "John"
    assert deid_map.mappings["[PATIENT_B]"] == "Jane"
    assert deid_map.mappings["[PATIENT_C]"] == "Bob"


def test_mixed_types_sequence(masking_engine: MaskingEngine) -> None:
    # John (PERSON), 123 (MRN), Jane (PERSON)
    # A, A, B
    text = "John has MRN 123. Jane also used 123."
    # John: 0-4
    # 123: 13-16
    # Jane: 18-22
    # 123: 33-36

    results = [
        RecognizerResult("PERSON", 0, 4, 1.0),
        RecognizerResult("MRN", 13, 16, 1.0),
        RecognizerResult("PERSON", 18, 22, 1.0),
        RecognizerResult("MRN", 33, 36, 1.0),
    ]

    policy = AegisPolicy(mode=RedactionMode.REPLACE, entity_types=["PERSON", "MRN"])
    masked, deid_map = masking_engine.mask(text, results, policy, "sess_mixed", "test_owner")

    # [PATIENT_A] has MRN [MRN_A]. [PATIENT_B] also used [MRN_A].
    # Wait, MRN suffix counter is separate from PERSON?
    # Logic: existing_count = sum(1 for t in ... if t.startswith(f"[{token_prefix}_"))
    # So yes, separate counters.

    expected = "[PATIENT_A] has MRN [MRN_A]. [PATIENT_B] also used [MRN_A]."
    assert masked == expected
    assert deid_map.mappings["[PATIENT_A]"] == "John"
    assert deid_map.mappings["[PATIENT_B]"] == "Jane"
    assert deid_map.mappings["[MRN_A]"] == "123"


def test_many_tokens(masking_engine: MaskingEngine) -> None:
    # Test AA, AB...
    # Generate 30 names
    names = [f"Name{i}" for i in range(30)]
    text = " ".join(names)
    results = []
    offset = 0
    for name in names:
        results.append(RecognizerResult("PERSON", offset, offset + len(name), 1.0))
        offset += len(name) + 1  # +1 for space

    policy = AegisPolicy(mode=RedactionMode.REPLACE)
    masked, deid_map = masking_engine.mask(text, results, policy, "sess_many", "test_owner")

    # Verify last one is [PATIENT_AD] (29th -> index 29 -> AD?)
    # 0->A ... 25->Z, 26->AA, 27->AB, 28->AC, 29->AD. Correct.
    assert "[PATIENT_AD]" in masked
    assert len(deid_map.mappings) == 30
