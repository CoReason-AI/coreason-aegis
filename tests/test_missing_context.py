from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, DeIdentificationMap
from coreason_aegis.reidentifier import ReIdentifier
from coreason_aegis.scanner import Scanner
from coreason_aegis.vault import VaultManager


def test_vault_save_missing_context() -> None:
    vault = VaultManager()
    mapping = DeIdentificationMap(session_id="s1", expires_at=datetime.now(timezone.utc))
    with pytest.raises(ValueError, match="UserContext is required"):
        vault.save_map(mapping, context=None)


def test_vault_get_missing_context() -> None:
    vault = VaultManager()
    with pytest.raises(ValueError, match="UserContext is required"):
        vault.get_map("s1", context=None)


def test_vault_delete_missing_context() -> None:
    vault = VaultManager()
    with pytest.raises(ValueError, match="UserContext is required"):
        vault.delete_map("s1", context=None)


def test_scanner_missing_context(mock_scanner_engine: MagicMock) -> None:
    scanner = Scanner()
    policy = AegisPolicy()
    with pytest.raises(ValueError, match="UserContext is required"):
        scanner.scan("text", policy, context=None)


def test_masking_missing_context(mock_scanner_engine: MagicMock) -> None:
    vault = VaultManager()
    masker = MaskingEngine(vault)
    policy = AegisPolicy()
    # Need results? Masker checks context first.
    with pytest.raises(ValueError, match="UserContext is required"):
        masker.mask("text", [], policy, "s1", context=None)


def test_reidentifier_missing_context() -> None:
    vault = VaultManager()
    reid = ReIdentifier(vault)
    with pytest.raises(ValueError, match="UserContext is required"):
        reid.reidentify("text", "s1", context=None)
