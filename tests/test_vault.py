from datetime import datetime, timedelta, timezone

import pytest

from coreason_aegis.models import DeIdentificationMap
from coreason_aegis.vault import VaultManager


@pytest.fixture
def vault() -> VaultManager:
    return VaultManager()


def test_save_and_get_map(vault: VaultManager) -> None:
    session_id = "sess_1"
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


def test_expiration(vault: VaultManager) -> None:
    session_id = "sess_expired"
    # Create an already expired mapping
    expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    mapping = DeIdentificationMap(session_id=session_id, expires_at=expires_at)

    vault.save_map(mapping)

    # Should return None and delete internally
    assert vault.get_map(session_id) is None

    # Verify it was deleted from storage (accessing private _storage for test verification)
    assert session_id not in vault._storage
