# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

import time

import pytest
from cachetools import TTLCache
from coreason_identity.models import UserContext

from coreason_aegis.models import DeIdentificationMap
from coreason_aegis.vault import VaultManager


@pytest.fixture
def vault_manager() -> VaultManager:
    return VaultManager(ttl_seconds=1, timer=time.monotonic)


def test_initialization_defaults() -> None:
    vault = VaultManager()
    # verify private storage is initialized
    assert vault._storage is not None
    assert isinstance(vault._storage, TTLCache)
    assert vault._storage.maxsize == 10000
    assert vault._storage.ttl == 3600


def test_save_and_get_map(vault_manager: VaultManager, mock_context: UserContext) -> None:
    from datetime import datetime, timezone

    session_id = "test_session"
    mapping = DeIdentificationMap(
        session_id=session_id,
        mappings={"TOKEN": "VALUE"},
        expires_at=datetime.now(timezone.utc),
    )

    vault_manager.save_map(mapping, context=mock_context)
    retrieved = vault_manager.get_map(session_id, context=mock_context)
    assert retrieved == mapping


def test_get_nonexistent_map(vault_manager: VaultManager, mock_context: UserContext) -> None:
    assert vault_manager.get_map("nonexistent", context=mock_context) is None


def test_ttl_expiry(vault_manager: VaultManager, mock_context: UserContext) -> None:
    from datetime import datetime, timezone

    session_id = "test_session_ttl"
    mapping = DeIdentificationMap(
        session_id=session_id,
        mappings={"TOKEN": "VALUE"},
        expires_at=datetime.now(timezone.utc),
    )

    vault_manager.save_map(mapping, context=mock_context)
    assert vault_manager.get_map(session_id, context=mock_context) is not None

    # Wait for TTL expiry
    time.sleep(1.1)

    assert vault_manager.get_map(session_id, context=mock_context) is None


def test_delete_map(vault_manager: VaultManager, mock_context: UserContext) -> None:
    from datetime import datetime, timezone

    session_id = "test_session_del"
    mapping = DeIdentificationMap(
        session_id=session_id,
        mappings={"TOKEN": "VALUE"},
        expires_at=datetime.now(timezone.utc),
    )

    vault_manager.save_map(mapping, context=mock_context)
    vault_manager.delete_map(session_id, context=mock_context)
    assert vault_manager.get_map(session_id, context=mock_context) is None


def test_delete_nonexistent_map(vault_manager: VaultManager, mock_context: UserContext) -> None:
    # Should not raise error
    vault_manager.delete_map("nonexistent", context=mock_context)


def test_max_size_eviction(mock_context: UserContext) -> None:
    # Test that LRU eviction works (cachetools logic)
    # Use small cache
    vault = VaultManager(max_size=2)
    from datetime import datetime, timezone

    def create_map(sid: str) -> DeIdentificationMap:
        return DeIdentificationMap(
            session_id=sid,
            mappings={},
            expires_at=datetime.now(timezone.utc),
        )

    vault.save_map(create_map("1"), context=mock_context)
    vault.save_map(create_map("2"), context=mock_context)
    assert vault.get_map("1", context=mock_context) is not None
    assert vault.get_map("2", context=mock_context) is not None

    vault.save_map(create_map("3"), context=mock_context)
    # Expect 1 to be evicted (LRU)
    assert vault.get_map("3", context=mock_context) is not None
    assert vault.get_map("2", context=mock_context) is not None
    assert vault.get_map("1", context=mock_context) is None
