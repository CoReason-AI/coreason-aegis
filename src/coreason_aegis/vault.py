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
        """Saves or updates a mapping in the vault."""
        self._storage[mapping.session_id] = mapping

    def get_map(self, session_id: str) -> Optional[DeIdentificationMap]:
        """
        Retrieves a mapping by session_id.
        Returns None if not found or expired (handled by TTLCache).
        """
        # TTLCache automatically handles expiration on access (or rather, hides expired items)
        return self._storage.get(session_id)

    def delete_map(self, session_id: str) -> None:
        """Deletes a mapping from the vault."""
        if session_id in self._storage:
            del self._storage[session_id]
