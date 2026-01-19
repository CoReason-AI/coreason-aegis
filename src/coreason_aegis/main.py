# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

"""Main entry point for the Aegis privacy filter.

This module provides the primary `Aegis` class, which orchestrates the scanning,
masking, and re-identification processes to enforce data privacy policies.
"""

from typing import Any, Optional, Tuple, cast

import anyio
import httpx

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, DeIdentificationMap
from coreason_aegis.reidentifier import ReIdentifier
from coreason_aegis.scanner import Scanner
from coreason_aegis.utils.logger import logger
from coreason_aegis.vault import VaultManager


class AegisAsync:
    """The main async interface for the privacy filter.

    Coordinates the Scanner, MaskingEngine, and ReIdentifier components to provide
    a unified API for sanitizing and de-sanitizing text in an async-native way.
    """

    def __init__(self, client: Optional[httpx.AsyncClient] = None) -> None:
        """Initializes the Aegis system and its components.

        Args:
            client: Optional httpx.AsyncClient for external connections.
        """
        self._internal_client = client is None
        self._client = client or httpx.AsyncClient()

        self.vault = VaultManager()
        self.scanner = Scanner()
        self.masking_engine = MaskingEngine(self.vault)
        self.reidentifier = ReIdentifier(self.vault)
        self._default_policy = AegisPolicy()

    async def __aenter__(self) -> "AegisAsync":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self._internal_client:
            await self._client.aclose()
        # In a future revision where VaultManager has resources, we would close them here.

    async def sanitize(
        self,
        text: str,
        session_id: str,
        policy: Optional[AegisPolicy] = None,
    ) -> Tuple[str, DeIdentificationMap]:
        """Scans and masks the input text based on the provided policy.

        Args:
            text: The text to sanitize.
            session_id: The unique session identifier.
            policy: Optional AegisPolicy override. Uses default if None.

        Returns:
            A tuple containing:
            - The sanitized text string.
            - The updated DeIdentificationMap.

        Raises:
            Exception: If sanitization fails (Fail Closed).
        """
        active_policy = policy or self._default_policy

        try:
            # 1. Scan (CPU bound)
            # Wrap synchronous scanner call in thread
            results = await anyio.to_thread.run_sync(self.scanner.scan, text, active_policy)

            # Check for API Keys and alert
            for result in results:
                if result.entity_type == "SECRET_KEY":
                    logger.warning("Credential Exposure Attempt detected. Redacting API Key.")

            # 2. Mask (CPU bound)
            # Wrap synchronous masking call in thread
            # Note: MaskingEngine uses VaultManager which is thread-safe for reads/writes if properly implemented,
            # but currently it's just a dict wrapper.
            masked_text, deid_map = await anyio.to_thread.run_sync(
                self.masking_engine.mask, text, results, active_policy, session_id
            )

            # Log success (omitting PII)
            logger.info(f"Sanitized text for session {session_id}. Detected {len(results)} entities.")

            return masked_text, deid_map

        except Exception as e:
            logger.error(f"Sanitization failed for session {session_id}: {e}")
            # Fail Closed: Propagate exception
            raise

    async def desanitize(
        self,
        text: str,
        session_id: str,
        authorized: bool = False,
    ) -> str:
        """Re-identifies the input text (e.g., response from LLM).

        Args:
            text: The text to de-sanitize.
            session_id: The unique session identifier.
            authorized: Whether the requestor is authorized to view real PII.

        Returns:
            The de-sanitized text (if authorized), or the original text with tokens.

        Raises:
            Exception: If de-sanitization fails.
        """
        try:
            # CPU bound
            # Explicitly cast to str because run_sync returns Any
            result = await anyio.to_thread.run_sync(self.reidentifier.reidentify, text, session_id, authorized)
            logger.info(f"Desanitized text for session {session_id}. Authorized: {authorized}")
            return cast(str, result)
        except Exception as e:
            logger.error(f"Desanitization failed for session {session_id}: {e}")
            # Fail Closed: Propagate exception
            raise


class Aegis:
    """The synchronous facade for the Aegis privacy filter.

    Wraps AegisAsync to provide a blocking interface.
    """

    def __init__(self, client: Optional[httpx.AsyncClient] = None) -> None:
        """Initializes the Aegis facade.

        Args:
            client: Optional httpx.AsyncClient (passed to AegisAsync).
        """
        self._async = AegisAsync(client=client)

    def __enter__(self) -> "Aegis":
        """Context manager entry."""
        anyio.run(self._async.__aenter__)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        anyio.run(self._async.__aexit__, exc_type, exc_val, exc_tb)

    def sanitize(
        self,
        text: str,
        session_id: str,
        policy: Optional[AegisPolicy] = None,
    ) -> Tuple[str, DeIdentificationMap]:
        """Scans and masks the input text (blocking)."""
        return cast(
            Tuple[str, DeIdentificationMap],
            anyio.run(self._async.sanitize, text, session_id, policy),
        )

    def desanitize(
        self,
        text: str,
        session_id: str,
        authorized: bool = False,
    ) -> str:
        """Re-identifies the input text (blocking)."""
        return cast(
            str,
            anyio.run(self._async.desanitize, text, session_id, authorized),
        )
