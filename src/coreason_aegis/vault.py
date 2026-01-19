# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

"""
VaultManager module for secure storage of de-identification maps.

This module manages the ephemeral storage of mappings between sensitive data and tokens.
It uses a Time-To-Live (TTL) cache to ensure data is automatically evicted after
a configured duration, enforcing the "Right to be Forgotten" and session expiry.
"""

import time
from typing import Callable, MutableMapping, Optional

from cachetools import TTLCache

from coreason_aegis.models import DeIdentificationMap


class VaultManager:
    """
    Manages the storage and retrieval of DeIdentificationMaps using a TTL cache.
    Ensures secure eviction of sensitive data after a set period.
    """

    def __init__(
        self,
        ttl_seconds: float = 3600,
        max_size: int = 10000,
        timer: Callable[[], float] = time.monotonic,
    ) -> None:
        """
        Initializes the VaultManager.

        Args:
            ttl_seconds: Time to live in seconds for each mapping. Default 1 hour.
            max_size: Maximum number of items in the cache. Default 10000.
            timer: Timer function for TTL. Defaults to time.monotonic.
        """
        # TTLCache implements MutableMapping, which is compatible with Dict interface for basic ops
        self._storage: MutableMapping[str, DeIdentificationMap] = TTLCache(
            maxsize=max_size, ttl=ttl_seconds, timer=timer
        )

    def save_map(self, mapping: DeIdentificationMap) -> None:
        """
        Saves or updates a mapping in the vault.

        Args:
            mapping: The DeIdentificationMap object to store.
        """
        self._storage[mapping.session_id] = mapping

    def get_map(self, session_id: str) -> Optional[DeIdentificationMap]:
        """
        Retrieves a mapping by session_id.

        Args:
            session_id: The session identifier.

        Returns:
            The DeIdentificationMap if found and not expired, else None.
        """
        # TTLCache automatically handles expiration on access (or rather, hides expired items)
        return self._storage.get(session_id)

    def delete_map(self, session_id: str) -> None:
        """
        Deletes a mapping from the vault.

        Args:
            session_id: The session identifier to delete.
        """
        if session_id in self._storage:
            del self._storage[session_id]
