# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

"""Secure storage for de-identification mappings.

This module provides the VaultManager, which handles the ephemeral storage of
mappings between redacted tokens and real values, ensuring data expires
appropriately.
"""

import time
from typing import Callable, MutableMapping, Optional

from cachetools import TTLCache

from coreason_aegis.models import DeIdentificationMap


class VaultManager:
    """Manages the storage and retrieval of DeIdentificationMaps using a TTL cache.

    Ensures secure eviction of sensitive data after a set period. This acts as
    the "Memory" component of the Aegis system.
    """

    def __init__(
        self,
        ttl_seconds: float = 3600,
        max_size: int = 10000,
        timer: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initializes the VaultManager.

        Args:
            ttl_seconds: Time to live in seconds. Default 1 hour.
            max_size: Maximum number of items in the cache. Default 10000.
            timer: Timer function for TTL. Defaults to time.monotonic.
        """
        # TTLCache implements MutableMapping, which is compatible with Dict interface for basic ops
        self._storage: MutableMapping[str, DeIdentificationMap] = TTLCache(
            maxsize=max_size, ttl=ttl_seconds, timer=timer
        )

    def save_map(self, mapping: DeIdentificationMap) -> None:
        """Saves or updates a mapping in the vault.

        Args:
            mapping: The DeIdentificationMap to store.
        """
        self._storage[mapping.session_id] = mapping

    def get_map(self, session_id: str) -> Optional[DeIdentificationMap]:
        """Retrieves a mapping by session_id.

        Args:
            session_id: The unique session identifier.

        Returns:
            The DeIdentificationMap if found and valid, else None.
            (Expiration is handled automatically by the underlying TTLCache).
        """
        # TTLCache automatically handles expiration on access (or rather, hides expired items)
        return self._storage.get(session_id)

    def delete_map(self, session_id: str) -> None:
        """Deletes a mapping from the vault.

        Args:
            session_id: The session ID to remove.
        """
        if session_id in self._storage:
            del self._storage[session_id]
