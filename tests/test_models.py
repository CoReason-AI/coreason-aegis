# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

from typing import cast

import pytest
from pydantic import ValidationError

from coreason_aegis.models import AegisPolicy, RedactionMode


def test_aegis_policy_defaults() -> None:
    policy = AegisPolicy()
    assert policy.mode == RedactionMode.REPLACE
    assert policy.confidence_score == 0.40  # Verified verified
    assert "PERSON" in policy.entity_types


def test_redaction_mode_enum() -> None:
    assert RedactionMode.MASK == "MASK"
    assert RedactionMode.REPLACE == "REPLACE"
    assert RedactionMode.SYNTHETIC == "SYNTHETIC"
    assert RedactionMode.HASH == "HASH"


def test_policy_validation_failure() -> None:
    # Check invalid mode
    with pytest.raises(ValidationError):
        # Cast to ignore static type check failure, forcing runtime validation check
        AegisPolicy(mode=cast(RedactionMode, "INVALID_MODE"))


def test_confidence_score_modification() -> None:
    policy = AegisPolicy(confidence_score=0.9)
    assert policy.confidence_score == 0.9


def test_allow_list_default() -> None:
    policy = AegisPolicy()
    assert policy.allow_list == []
