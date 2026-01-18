# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

import re

import pytest
from presidio_analyzer import RecognizerResult

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, RedactionMode
from coreason_aegis.vault import VaultManager


@pytest.fixture
def masking_engine() -> MaskingEngine:
    vault = VaultManager()
    return MaskingEngine(vault)


def test_synthetic_mrn(masking_engine: MaskingEngine) -> None:
    text = "Patient has MRN 123456"
    # Mock result from Scanner
    results = [RecognizerResult(entity_type="MRN", start=16, end=22, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["MRN"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_1")

    # Extract the replacement
    # "Patient has MRN " is 16 chars long.
    # The replacement starts at index 16.
    prefix = "Patient has MRN "
    assert masked_text.startswith(prefix)
    replacement = masked_text[len(prefix) :]

    # Verify it looks like an MRN (6-10 digits)
    assert re.fullmatch(r"\d{6,10}", replacement), f"Generated MRN '{replacement}' does not match format."
    # Ensure it's not the original
    assert replacement != "123456"


def test_synthetic_protocol_id(masking_engine: MaskingEngine) -> None:
    text = "Protocol ABC-123 started."
    # Mock result from Scanner
    # "Protocol " is 9 chars. "ABC-123" is 7 chars.
    results = [RecognizerResult(entity_type="PROTOCOL_ID", start=9, end=16, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["PROTOCOL_ID"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_1")

    prefix = "Protocol "
    suffix = " started."
    assert masked_text.startswith(prefix)
    assert masked_text.endswith(suffix)

    replacement = masked_text[len(prefix) : -len(suffix)]

    # Verify format [A-Z]{3}-\d{3}
    assert re.fullmatch(r"[A-Z]{3}-\d{3}", replacement), f"Generated Protocol ID '{replacement}' does not match format."
    assert replacement != "ABC-123"


def test_synthetic_lot_number(masking_engine: MaskingEngine) -> None:
    text = "Batch LOT-A1B2 is ready."
    # "Batch " is 6 chars. "LOT-A1B2" is 8 chars.
    results = [RecognizerResult(entity_type="LOT_NUMBER", start=6, end=14, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["LOT_NUMBER"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_1")

    prefix = "Batch "
    suffix = " is ready."
    assert masked_text.startswith(prefix)
    assert masked_text.endswith(suffix)

    replacement = masked_text[len(prefix) : -len(suffix)]

    # Verify format LOT-[A-Z0-9]+
    assert re.fullmatch(r"LOT-[A-Z0-9]+", replacement), f"Generated LOT '{replacement}' does not match format."
    assert replacement != "LOT-A1B2"


def test_synthetic_gene_sequence(masking_engine: MaskingEngine) -> None:
    text = "Sequence ATCGATCGAT detected."
    # "Sequence " is 9 chars. "ATCGATCGAT" is 10 chars.
    results = [RecognizerResult(entity_type="GENE_SEQUENCE", start=9, end=19, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["GENE_SEQUENCE"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_1")

    prefix = "Sequence "
    suffix = " detected."
    assert masked_text.startswith(prefix)
    assert masked_text.endswith(suffix)

    replacement = masked_text[len(prefix) : -len(suffix)]

    # Verify format [ATCG]+
    assert re.fullmatch(r"[ATCG]+", replacement), f"Generated Gene '{replacement}' does not match format."
    assert replacement != "ATCGATCGAT"


def test_synthetic_chemical_cas(masking_engine: MaskingEngine) -> None:
    text = "Chemical 50-00-0 used."
    # "Chemical " is 9 chars. "50-00-0" is 7 chars.
    results = [RecognizerResult(entity_type="CHEMICAL_CAS", start=9, end=16, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["CHEMICAL_CAS"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_1")

    prefix = "Chemical "
    suffix = " used."
    assert masked_text.startswith(prefix)
    assert masked_text.endswith(suffix)

    replacement = masked_text[len(prefix) : -len(suffix)]

    # Verify format \d{2,7}-\d{2}-\d
    assert re.fullmatch(r"\d{2,7}-\d{2}-\d", replacement), f"Generated CAS '{replacement}' does not match format."
    assert replacement != "50-00-0"


def test_synthetic_secret_key(masking_engine: MaskingEngine) -> None:
    original_key = "sk-1234567890abcdef1234"
    text = f"Key {original_key} leaked."
    # "Key " is 4 chars.
    start = 4
    end = 4 + len(original_key)
    results = [RecognizerResult(entity_type="SECRET_KEY", start=start, end=end, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["SECRET_KEY"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_1")

    prefix = "Key "
    suffix = " leaked."
    assert masked_text.startswith(prefix)
    assert masked_text.endswith(suffix)

    replacement = masked_text[len(prefix) : -len(suffix)]

    # Verify format sk-[A-Za-z0-9]{20,}
    assert re.fullmatch(r"sk-[A-Za-z0-9]{20,}", replacement), f"Generated Key '{replacement}' does not match format."
    assert replacement != original_key


def test_synthetic_determinism(masking_engine: MaskingEngine) -> None:
    """Ensure that the same input produces the same synthetic output."""
    text = "Protocol ABC-123"
    results = [RecognizerResult(entity_type="PROTOCOL_ID", start=9, end=16, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["PROTOCOL_ID"])

    repl1, _ = masking_engine.mask(text, results, policy, "s1")
    repl2, _ = masking_engine.mask(text, results, policy, "s2")

    assert repl1 == repl2
