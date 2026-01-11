# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

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
        Returns the sanitized text and the updated DeIdentificationMap.
        """
        active_policy = policy or self._default_policy

        try:
            # 1. Scan
            results = self.scanner.scan(text, active_policy)

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
