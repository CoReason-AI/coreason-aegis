# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

from datetime import datetime, timedelta, timezone

import pytest

from coreason_aegis.models import DeIdentificationMap
from coreason_aegis.reidentifier import ReIdentifier
from coreason_aegis.vault import VaultManager


@pytest.fixture
def vault() -> VaultManager:
    return VaultManager()


@pytest.fixture
def reidentifier(vault: VaultManager) -> ReIdentifier:
    return ReIdentifier(vault)


def test_reidentify_authorized(reidentifier: ReIdentifier, vault: VaultManager) -> None:
    session_id = "sess_1"
    mappings = {"[PATIENT_A]": "John Doe", "[DATE_A]": "2023-01-01"}
    deid_map = DeIdentificationMap(
        session_id=session_id,
        mappings=mappings,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    vault.save_map(deid_map)

    text = "User [PATIENT_A] visited on [DATE_A]."
    result = reidentifier.reidentify(text, session_id, authorized=True)

    assert result == "User John Doe visited on 2023-01-01."


def test_reidentify_unauthorized(reidentifier: ReIdentifier, vault: VaultManager) -> None:
    session_id = "sess_1"
    mappings = {"[PATIENT_A]": "John Doe"}
    deid_map = DeIdentificationMap(
        session_id=session_id,
        mappings=mappings,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    vault.save_map(deid_map)

    text = "User [PATIENT_A]."
    result = reidentifier.reidentify(text, session_id, authorized=False)

    assert result == "User [PATIENT_A]."


def test_reidentify_no_session(reidentifier: ReIdentifier) -> None:
    text = "User [PATIENT_A]."
    result = reidentifier.reidentify(text, "non_existent_session", authorized=True)

    # Should return original text as no map found
    assert result == text


def test_reidentify_empty_text(reidentifier: ReIdentifier) -> None:
    assert reidentifier.reidentify("", "sess_1") == ""


def test_reidentify_substring_tokens(reidentifier: ReIdentifier, vault: VaultManager) -> None:
    # Edge case: One token is substring of another?
    # Our tokens usually have brackets, so [A] inside [A_B] isn't typical,
    # but [PATIENT_A] vs [PATIENT_AA] is possible.
    session_id = "sess_overlap"
    mappings = {"[PATIENT_A]": "John", "[PATIENT_AA]": "Johnny"}
    deid_map = DeIdentificationMap(
        session_id=session_id,
        mappings=mappings,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    vault.save_map(deid_map)

    text = "Is it [PATIENT_A] or [PATIENT_AA]?"
    result = reidentifier.reidentify(text, session_id, authorized=True)

    # Should correctly identify distinct tokens
    assert result == "Is it John or Johnny?"


def test_reidentify_empty_mappings(reidentifier: ReIdentifier, vault: VaultManager) -> None:
    session_id = "sess_empty_map"
    deid_map = DeIdentificationMap(
        session_id=session_id,
        mappings={},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    vault.save_map(deid_map)

    text = "Nothing to do."
    result = reidentifier.reidentify(text, session_id, authorized=True)

    assert result == "Nothing to do."
