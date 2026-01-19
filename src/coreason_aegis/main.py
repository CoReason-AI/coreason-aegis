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
Main entry point for the CoReason Aegis privacy filter.

This module exposes the `Aegis` class, which orchestrates the scanning, masking,
and re-identification of sensitive data (PII/PHI) in text streams.
It acts as the "Air Gap" between the CoReason platform and external systems like LLMs.
"""

from typing import Optional, Tuple

from coreason_aegis.masking import MaskingEngine
from coreason_aegis.models import AegisPolicy, DeIdentificationMap
from coreason_aegis.reidentifier import ReIdentifier
from coreason_aegis.scanner import Scanner
from coreason_aegis.utils.logger import logger
from coreason_aegis.vault import VaultManager


class Aegis:
    """
    The main interface for the privacy filter.
    Coordinates Scanner, MaskingEngine, and ReIdentifier.
    """

    def __init__(self) -> None:
        """
        Initializes the Aegis engine.
        Sets up the VaultManager, Scanner, MaskingEngine, and ReIdentifier.
        """
        self.vault = VaultManager()
        self.scanner = Scanner()
        self.masking_engine = MaskingEngine(self.vault)
        self.reidentifier = ReIdentifier(self.vault)
        self._default_policy = AegisPolicy()

    def sanitize(
        self,
        text: str,
        session_id: str,
        policy: Optional[AegisPolicy] = None,
    ) -> Tuple[str, DeIdentificationMap]:
        """
        Scans and masks the input text.

        This is the inbound filter. It detects sensitive entities in the `text`
        and replaces them with tokens (masking) according to the `policy`.
        It ensures that no sensitive data leaves the secure perimeter.

        Args:
            text: The raw input text containing potential PII/PHI.
            session_id: The unique identifier for the user session.
            policy: The redaction policy to apply. If None, uses default policy.

        Returns:
            A tuple containing:
                - The sanitized text with tokens.
                - The updated DeIdentificationMap containing the mappings.

        Raises:
            RuntimeError: If the sanitization process fails (Fail Closed).
        """
        active_policy = policy or self._default_policy

        try:
            # 1. Scan
            results = self.scanner.scan(text, active_policy)

            # Check for API Keys and alert
            for result in results:
                if result.entity_type == "SECRET_KEY":
                    logger.warning("Credential Exposure Attempt detected. Redacting API Key.")

            # 2. Mask
            masked_text, deid_map = self.masking_engine.mask(text, results, active_policy, session_id)

            # Log success (omitting PII)
            logger.info(f"Sanitized text for session {session_id}. Detected {len(results)} entities.")

            return masked_text, deid_map

        except Exception as e:
            logger.error(f"Sanitization failed for session {session_id}: {e}")
            # Fail Closed: Propagate exception
            raise

    def desanitize(
        self,
        text: str,
        session_id: str,
        authorized: bool = False,
    ) -> str:
        """
        Re-identifies the input text (response from LLM).

        This is the outbound filter. It intercepts the response from the LLM,
        looks up tokens in the `VaultManager`, and replaces them with the
        original values if the user is authorized.

        Args:
            text: The sanitized text (from LLM) containing tokens.
            session_id: The unique identifier for the user session.
            authorized: Whether the user is authorized to view the PII.

        Returns:
            The re-identified text with real values (if authorized),
            or the original tokenized text (if unauthorized or not found).

        Raises:
            Exception: If the desanitization process encounters a critical error.
        """
        try:
            result = self.reidentifier.reidentify(text, session_id, authorized)
            logger.info(f"Desanitized text for session {session_id}. Authorized: {authorized}")
            return result
        except Exception as e:
            logger.error(f"Desanitization failed for session {session_id}: {e}")
            # Fail Closed: Propagate exception?
            # Or return safe text (tokens)?
            # If re-id fails, it's safer to return the tokens than nothing or crashing the UI?
            # But the protocol says "Fail Closed". If we crash, user sees nothing -> Closed.
            # If we return tokens -> Safe but bad UX.
            # Let's propagate for now as strict safety.
            raise
