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

from coreason_aegis.models import DeIdentificationMap
from coreason_aegis.reidentifier import ReIdentifier
from coreason_aegis.vault import VaultManager


@pytest.fixture
def vault() -> VaultManager:
    return VaultManager()


@pytest.fixture
def reidentifier(vault: VaultManager) -> ReIdentifier:
    return ReIdentifier(vault)


def test_reidentify_success(reidentifier: ReIdentifier, vault: VaultManager, mock_context: UserContext) -> None:
    # Setup
    from datetime import datetime, timezone

    session_id = "sess1"
    deid_map = DeIdentificationMap(
        session_id=session_id,
        mappings={"[PATIENT_A]": "John Doe"},
        expires_at=datetime.now(timezone.utc),
    )
    vault.save_map(deid_map, context=mock_context)

    text = "Hello [PATIENT_A]."
    result = reidentifier.reidentify(text, session_id, context=mock_context, authorized=True)
    assert result == "Hello John Doe."


def test_reidentify_unauthorized(reidentifier: ReIdentifier, vault: VaultManager, mock_context: UserContext) -> None:
    # Setup
    from datetime import datetime, timezone

    session_id = "sess2"
    deid_map = DeIdentificationMap(
        session_id=session_id,
        mappings={"[PATIENT_A]": "John Doe"},
        expires_at=datetime.now(timezone.utc),
    )
    vault.save_map(deid_map, context=mock_context)

    text = "Hello [PATIENT_A]."
    result = reidentifier.reidentify(text, session_id, context=mock_context, authorized=False)
    assert result == "Hello [PATIENT_A]."


def test_reidentify_no_map(reidentifier: ReIdentifier, mock_context: UserContext) -> None:
    # No map in vault
    text = "Hello [PATIENT_A]."
    result = reidentifier.reidentify(text, "sess_missing", context=mock_context, authorized=True)
    assert result == "Hello [PATIENT_A]."


def test_reidentify_empty_text(reidentifier: ReIdentifier, mock_context: UserContext) -> None:
    result = reidentifier.reidentify("", "sess1", context=mock_context, authorized=True)
    assert result == ""


def test_reidentify_empty_mappings(reidentifier: ReIdentifier, vault: VaultManager, mock_context: UserContext) -> None:
    # Map exists but is empty
    from datetime import datetime, timezone

    session_id = "sess_empty"
    deid_map = DeIdentificationMap(
        session_id=session_id,
        mappings={},
        expires_at=datetime.now(timezone.utc),
    )
    vault.save_map(deid_map, context=mock_context)

    text = "Hello [PATIENT_A]."
    result = reidentifier.reidentify(text, session_id, context=mock_context, authorized=True)
    assert result == text


def test_reidentify_partial_overlap(reidentifier: ReIdentifier, vault: VaultManager, mock_context: UserContext) -> None:
    # Case: [TOKEN] vs [TOKEN_A] ?
    # Our tokens are distinct ([PATIENT_A], [PATIENT_B]) so low risk.
    # But checking multiple tokens.
    from datetime import datetime, timezone

    session_id = "sess_multi"
    deid_map = DeIdentificationMap(
        session_id=session_id,
        mappings={
            "[A]": "Alpha",
            "[B]": "Beta",
        },
        expires_at=datetime.now(timezone.utc),
    )
    vault.save_map(deid_map, context=mock_context)

    text = "[A] and [B]"
    result = reidentifier.reidentify(text, session_id, context=mock_context, authorized=True)
    assert result == "Alpha and Beta"


def test_reidentify_nested_substrings(
    reidentifier: ReIdentifier, vault: VaultManager, mock_context: UserContext
) -> None:
    # Case: [A] and [AA]
    # If we replace [A] first, [AA] becomes [AlphaA] (incorrect) or similar.
    # Logic should handle sorting keys by length descending.
    from datetime import datetime, timezone

    session_id = "sess_nest"
    deid_map = DeIdentificationMap(
        session_id=session_id,
        mappings={
            "[A]": "Short",
            "[AA]": "Long",
        },
        expires_at=datetime.now(timezone.utc),
    )
    vault.save_map(deid_map, context=mock_context)

    text = "This is [A] and this is [AA]."
    # Should replace [AA] first -> "This is [A] and this is Long."
    # Then [A] -> "This is Short and this is Long."

    result = reidentifier.reidentify(text, session_id, context=mock_context, authorized=True)
    assert result == "This is Short and this is Long."
