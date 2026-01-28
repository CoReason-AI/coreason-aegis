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
from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, RedactionMode
from coreason_aegis.vault import VaultManager
from coreason_identity.models import UserContext
from presidio_analyzer import RecognizerResult


@pytest.fixture
def masking_engine() -> MaskingEngine:
    vault = VaultManager()
    return MaskingEngine(vault)


def test_synthetic_mrn(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    text = "Patient has MRN 123456"
    # Mock result from Scanner
    results = [RecognizerResult(entity_type="MRN", start=16, end=22, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["MRN"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_1", context=mock_context)

    # Extract the replacement
    prefix = "Patient has MRN "
    assert masked_text.startswith(prefix)
    replacement = masked_text[len(prefix) :]

    # Verify it looks like an MRN (6-10 digits)
    assert re.fullmatch(r"\d{6,10}", replacement), f"Generated MRN '{replacement}' does not match format."
    assert replacement != "123456"


def test_synthetic_protocol_id(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    text = "Protocol ABC-123 started."
    results = [RecognizerResult(entity_type="PROTOCOL_ID", start=9, end=16, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["PROTOCOL_ID"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_1", context=mock_context)

    prefix = "Protocol "
    suffix = " started."
    assert masked_text.startswith(prefix)
    assert masked_text.endswith(suffix)

    replacement = masked_text[len(prefix) : -len(suffix)]

    # Verify format [A-Z]{3}-\d{3}
    assert re.fullmatch(r"[A-Z]{3}-\d{3}", replacement), f"Generated Protocol ID '{replacement}' does not match format."
    assert replacement != "ABC-123"


def test_synthetic_lot_number(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    text = "Batch LOT-A1B2 is ready."
    results = [RecognizerResult(entity_type="LOT_NUMBER", start=6, end=14, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["LOT_NUMBER"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_1", context=mock_context)

    prefix = "Batch "
    suffix = " is ready."
    assert masked_text.startswith(prefix)
    assert masked_text.endswith(suffix)

    replacement = masked_text[len(prefix) : -len(suffix)]

    # Verify format LOT-[A-Z0-9]+
    assert re.fullmatch(r"LOT-[A-Z0-9]+", replacement), f"Generated LOT '{replacement}' does not match format."
    assert replacement != "LOT-A1B2"


def test_synthetic_gene_sequence(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    text = "Sequence ATCGATCGAT detected."
    results = [RecognizerResult(entity_type="GENE_SEQUENCE", start=9, end=19, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["GENE_SEQUENCE"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_1", context=mock_context)

    prefix = "Sequence "
    suffix = " detected."
    assert masked_text.startswith(prefix)
    assert masked_text.endswith(suffix)

    replacement = masked_text[len(prefix) : -len(suffix)]

    # Verify format [ATCG]+
    assert re.fullmatch(r"[ATCG]+", replacement), f"Generated Gene '{replacement}' does not match format."
    assert replacement != "ATCGATCGAT"


def test_synthetic_chemical_cas(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    text = "Chemical 50-00-0 used."
    results = [RecognizerResult(entity_type="CHEMICAL_CAS", start=9, end=16, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["CHEMICAL_CAS"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_1", context=mock_context)

    prefix = "Chemical "
    suffix = " used."
    assert masked_text.startswith(prefix)
    assert masked_text.endswith(suffix)

    replacement = masked_text[len(prefix) : -len(suffix)]

    # Verify format \d{2,7}-\d{2}-\d
    assert re.fullmatch(r"\d{2,7}-\d{2}-\d", replacement), f"Generated CAS '{replacement}' does not match format."
    assert replacement != "50-00-0"


def test_synthetic_secret_key(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    original_key = "sk-1234567890abcdef1234"
    text = f"Key {original_key} leaked."
    start = 4
    end = 4 + len(original_key)
    results = [RecognizerResult(entity_type="SECRET_KEY", start=start, end=end, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["SECRET_KEY"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_1", context=mock_context)

    prefix = "Key "
    suffix = " leaked."
    assert masked_text.startswith(prefix)
    assert masked_text.endswith(suffix)

    replacement = masked_text[len(prefix) : -len(suffix)]

    # Verify format sk-[A-Za-z0-9]{20,}
    assert re.fullmatch(r"sk-[A-Za-z0-9]{20,}", replacement), f"Generated Key '{replacement}' does not match format."
    assert replacement != original_key


def test_synthetic_determinism(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    """Ensure that the same input produces the same synthetic output."""
    text = "Protocol ABC-123"
    results = [RecognizerResult(entity_type="PROTOCOL_ID", start=9, end=16, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["PROTOCOL_ID"])

    repl1, _ = masking_engine.mask(text, results, policy, "s1", context=mock_context)
    repl2, _ = masking_engine.mask(text, results, policy, "s2", context=mock_context)

    assert repl1 == repl2


def test_synthetic_gene_sequence_long(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    """Test performance and length matching for very long gene sequences."""
    # Create a 1000 char gene sequence
    long_seq = "ATCG" * 250
    text = f"Seq: {long_seq}"
    results = [RecognizerResult(entity_type="GENE_SEQUENCE", start=5, end=5 + len(long_seq), score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["GENE_SEQUENCE"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_long", context=mock_context)

    # Verify result length matches input length
    # Input total length = 5 + 1000 = 1005
    # Expect output length to be same since we replace 1000 chars with 1000 chars
    assert len(masked_text) == len(text)

    replacement = masked_text[5:]
    assert len(replacement) == 1000
    assert re.fullmatch(r"[ATCG]+", replacement)
    assert replacement != long_seq  # Unlikely to match exactly 1000 random chars


def test_synthetic_mixed_scenario(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    """Test a complex scenario with all custom entity types mixed together."""
    text = (
        "Protocol XYZ-999 uses LOT-Q1W2. "
        "Patient MRN 98765432 has gene ATCGATCG. "
        "Key sk-abcdef12345678901234 leaked. "
        "CAS 12-34-5."
    )

    # Manually define results based on the text above
    # "Protocol XYZ-999" -> 9 to 16
    # "LOT-Q1W2" -> 22 to 30
    # "MRN 98765432" -> MRN part is "98765432" (start 44, end 52) - wait "Patient MRN " is 12 chars.
    # Let's count accurately or just use search.

    # Protocol XYZ-999 -> indices 9-16 (len 7)
    # LOT-Q1W2 -> indices 22-30 (len 8)
    # 98765432 -> indices 44-52 (len 8)
    # ATCGATCG -> indices 62-70 (len 8)
    # sk-abcdef12345678901234 -> indices 76-99 (len 23)
    # 12-34-5 -> indices 112-119 (len 7)

    results = [
        RecognizerResult(entity_type="PROTOCOL_ID", start=9, end=16, score=1.0),
        RecognizerResult(entity_type="LOT_NUMBER", start=22, end=30, score=1.0),
        RecognizerResult(entity_type="MRN", start=44, end=52, score=1.0),
        RecognizerResult(entity_type="GENE_SEQUENCE", start=62, end=70, score=1.0),
        RecognizerResult(entity_type="SECRET_KEY", start=76, end=99, score=1.0),
        RecognizerResult(entity_type="CHEMICAL_CAS", start=112, end=119, score=1.0),
    ]

    policy = AegisPolicy(
        mode=RedactionMode.SYNTHETIC,
        entity_types=["PROTOCOL_ID", "LOT_NUMBER", "MRN", "GENE_SEQUENCE", "SECRET_KEY", "CHEMICAL_CAS"],
    )

    masked_text, _ = masking_engine.mask(text, results, policy, "session_mixed", context=mock_context)

    # Verify structural integrity (surrounding text should remain)
    assert "Protocol " in masked_text
    assert " uses " in masked_text
    assert "Patient MRN " in masked_text
    assert " has gene " in masked_text
    assert "Key " in masked_text
    assert " leaked." in masked_text
    assert "CAS " in masked_text

    # Verify no original PII remains
    assert "XYZ-999" not in masked_text
    assert "LOT-Q1W2" not in masked_text
    assert "98765432" not in masked_text
    assert "ATCGATCG" not in masked_text
    assert "sk-abcdef12345678901234" not in masked_text
    assert "12-34-5" not in masked_text


def test_synthetic_unicode_input(masking_engine: MaskingEngine, mock_context: UserContext) -> None:
    """Test robust seeding with Unicode characters."""
    # A protocol ID embedded in unicode text
    text = "Prótocol 🚀 ABC-123"
    # "Prótocol 🚀 " is 11 chars (if rocket is 1 char? Python handles unicode len usually by code point)
    # 🚀 is U+1F680. len("🚀") is 1 in Python 3.
    # P r ó t o c o l _ 🚀 _ = 8 + 1 + 1 + 1 = 11.
    # ABC-123 starts at 11, ends at 18.

    results = [RecognizerResult(entity_type="PROTOCOL_ID", start=11, end=18, score=1.0)]
    policy = AegisPolicy(mode=RedactionMode.SYNTHETIC, entity_types=["PROTOCOL_ID"])

    masked_text, _ = masking_engine.mask(text, results, policy, "session_unicode", context=mock_context)

    assert masked_text.startswith("Prótocol 🚀 ")
    repl = masked_text[11:]
    assert re.fullmatch(r"[A-Z]{3}-\d{3}", repl)
    assert repl != "ABC-123"

    # Verify determinism for unicode too
    masked_text_2, _ = masking_engine.mask(text, results, policy, "session_unicode_2", context=mock_context)
    assert masked_text == masked_text_2
