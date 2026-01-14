from datetime import datetime, timedelta, timezone

import pytest

from coreason_aegis.models import DeIdentificationMap
from coreason_aegis.vault import VaultManager


@pytest.fixture
def vault() -> VaultManager:
    return VaultManager()


def test_save_and_get_map(vault: VaultManager) -> None:
    session_id = "sess_1"
    # expires_at is required by the model, but VaultManager now manages TTL independently.
    # We still provide it to satisfy the model.
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    mapping = DeIdentificationMap(session_id=session_id, expires_at=expires_at)

    vault.save_map(mapping)
    retrieved = vault.get_map(session_id)

    assert retrieved is not None
    assert retrieved.session_id == session_id
    assert retrieved == mapping


def test_get_non_existent_map(vault: VaultManager) -> None:
    assert vault.get_map("non_existent") is None


def test_delete_map(vault: VaultManager) -> None:
    session_id = "sess_1"
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    mapping = DeIdentificationMap(session_id=session_id, expires_at=expires_at)

    vault.save_map(mapping)
    vault.delete_map(session_id)

    assert vault.get_map(session_id) is None


def test_delete_non_existent_map(vault: VaultManager) -> None:
    # Should not raise error
    vault.delete_map("non_existent")


def test_ttl_expiration() -> None:
    """
    Verifies that items are evicted after TTL expires.
    Uses a manual timer injection for deterministic testing.
    """
    current_time = 0.0

    def mock_timer() -> float:
        return current_time

    # Initialize vault with 10 seconds TTL and mock timer
    vault = VaultManager(ttl_seconds=10, timer=mock_timer)

    session_id = "sess_ttl"
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    mapping = DeIdentificationMap(session_id=session_id, expires_at=expires_at)

    # 1. Save at time 0
    vault.save_map(mapping)

    # 2. Retrieve at time 5 (Should exist)
    current_time = 5.0
    assert vault.get_map(session_id) is not None

    # 3. Retrieve at time 11 (Should be gone)
    current_time = 11.0
    assert vault.get_map(session_id) is None

    # 4. Verify physical eviction from storage
    # cachetools lazy expires on access or size limit, but .get() should handle it.
    # Let's check __contains__ (in operator)
    assert session_id not in vault._storage


def test_max_size_eviction() -> None:
    """
    Verifies that the cache respects max_size.
    """
    vault = VaultManager(max_size=2)

    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    map1 = DeIdentificationMap(session_id="1", expires_at=expires_at)
    map2 = DeIdentificationMap(session_id="2", expires_at=expires_at)
    map3 = DeIdentificationMap(session_id="3", expires_at=expires_at)

    vault.save_map(map1)
    vault.save_map(map2)
    vault.save_map(map3)  # Should evict oldest (map1)

    assert vault.get_map("1") is None
    assert vault.get_map("2") is not None
    assert vault.get_map("3") is not None
