from datetime import datetime, timezone
from typing import Dict, Optional

from coreason_aegis.models import DeIdentificationMap


class VaultManager:
    """
    Manages the storage and retrieval of DeIdentificationMaps.
    Currently implements an in-memory storage.
    """

    def __init__(self) -> None:
        self._storage: Dict[str, DeIdentificationMap] = {}

    def save_map(self, mapping: DeIdentificationMap) -> None:
        """Saves or updates a mapping in the vault."""
        self._storage[mapping.session_id] = mapping

    def get_map(self, session_id: str) -> Optional[DeIdentificationMap]:
        """
        Retrieves a mapping by session_id.
        Returns None if not found or expired.
        """
        mapping = self._storage.get(session_id)
        if not mapping:
            return None

        # Check for expiration
        if datetime.now(timezone.utc) > mapping.expires_at:
            self.delete_map(session_id)  # Clean up expired
            return None

        return mapping

    def delete_map(self, session_id: str) -> None:
        """Deletes a mapping from the vault."""
        if session_id in self._storage:
            del self._storage[session_id]
