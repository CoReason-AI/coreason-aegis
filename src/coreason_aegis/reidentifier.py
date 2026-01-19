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
Re-identification module for reversing tokenization.

This module handles the sensitive process of replacing tokens with their original
values in the LLM response, contingent on user authorization.
"""

from coreason_aegis.vault import VaultManager


class ReIdentifier:
    """
    Handles the reversal of tokenization (re-identification) based on permissions.
    """

    def __init__(self, vault: VaultManager) -> None:
        """
        Initializes the ReIdentifier.

        Args:
            vault: The VaultManager instance to retrieve mappings from.
        """
        self.vault = vault

    def reidentify(
        self,
        text: str,
        session_id: str,
        authorized: bool = False,
    ) -> str:
        """
        Replaces tokens with real values if authorized.

        Args:
            text: The text containing tokens.
            session_id: The session identifier to look up mappings.
            authorized: Boolean flag indicating if the user has permission to view PII.

        Returns:
            The text with real values restored (if authorized and found),
            otherwise the original text.
        """
        if not text:
            return ""

        # Retrieve the map
        deid_map = self.vault.get_map(session_id)
        if not deid_map:
            # If no map exists (expired or never created), we cannot re-identify.
            # Return text as is (with tokens).
            return text

        if not authorized:
            # If not authorized, return tokens as is.
            return text

        # Replace tokens with real values.
        # We need to scan for tokens.
        # Since tokens are in the map, we can iterate the map.
        # However, simple string replacement might be dangerous if tokens are substrings of others
        # (though our tokens have brackets like [PATIENT_A], which helps).
        # Better approach: Regex replacement for all keys in map.

        # Optimization: Build a single regex pattern from all keys?
        # keys are like [PATIENT_A], [EMAIL_A]...
        # Escape keys for regex.

        if not deid_map.mappings:
            return text

        # Sort keys by length descending to avoid prefix matching issues
        sorted_keys = sorted(deid_map.mappings.keys(), key=len, reverse=True)

        # We can iterate and replace.
        result_text = text
        for token in sorted_keys:
            real_value = deid_map.mappings[token]
            # Simple replace is O(N*M), but fine for typical text sizes.
            result_text = result_text.replace(token, real_value)

        return result_text
