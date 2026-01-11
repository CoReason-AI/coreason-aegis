from typing import Dict, List, Tuple

from presidio_analyzer import RecognizerResult

from coreason_aegis.models import AegisPolicy, DeIdentificationMap, RedactionMode
from coreason_aegis.vault import VaultManager


class MaskingEngine:
    """
    Replaces detected entities with tokens and manages the de-identification map.
    """

    def __init__(self, vault: VaultManager) -> None:
        self.vault = vault

    def mask(
        self,
        text: str,
        results: List[RecognizerResult],
        policy: AegisPolicy,
        session_id: str,
    ) -> Tuple[str, DeIdentificationMap]:
        """
        Masks the text based on the scanner results and policy.
        Returns the masked text and the updated DeIdentificationMap.
        """
        # Retrieve existing map or create new one
        deid_map = self.vault.get_map(session_id)
        if not deid_map:
            # We need to decide on expiration. For now, let's assume caller or vault default handles it,
            # but DeIdentificationMap requires expires_at.
            # Ideally, the main Aegis class orchestrates session creation.
            # Here, we might just need to accept an existing map object or raise if not found?
            # Or simplified: if not found, we cannot maintain consistency easily without creation logic.
            # Let's assume the map SHOULD exist or we create a fresh one here.
            # But wait, creating here requires knowing expiration policy.
            # Let's assume we pass the map IN or get it from Vault.
            # If it's None, we might fail or create new.
            # Let's simplify: Return the map updates, caller saves.
            # Actually, the requirement says "Vault of Identity... stored ephemerally".
            # Let's try to get it, if not, create new with default 1 hour?
            from datetime import datetime, timedelta, timezone

            deid_map = DeIdentificationMap(
                session_id=session_id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )

        # Sort results by start index ascending for deterministic token assignment
        # (Person appearing first gets A, second gets B...)
        sorted_results_asc = sorted(results, key=lambda x: x.start)

        # Reverse lookup: Real Value -> Token
        real_to_token: Dict[str, str] = {v: k for k, v in deid_map.mappings.items()}

        # Pass 1: Assign tokens
        # We store the determined replacement for each result to apply later
        replacements: List[Tuple[int, int, str]] = []

        for result in sorted_results_asc:
            entity_text = text[result.start : result.end]

            # Check policy Allow List
            if entity_text in policy.allow_list:
                continue

            # Determine token prefix
            token_prefix = result.entity_type
            if token_prefix == "PERSON":
                token_prefix = "PATIENT"

            replacement = ""
            if policy.mode == RedactionMode.MASK:
                replacement = f"[{token_prefix}]"
            elif policy.mode == RedactionMode.REPLACE:
                if entity_text in real_to_token:
                    replacement = real_to_token[entity_text]
                else:
                    # Generate new token
                    existing_count = sum(1 for t in deid_map.mappings.keys() if t.startswith(f"[{token_prefix}_"))
                    suffix = self._generate_suffix(existing_count)
                    replacement = f"[{token_prefix}_{suffix}]"

                    # Update maps
                    deid_map.mappings[replacement] = entity_text
                    real_to_token[entity_text] = replacement
            elif policy.mode == RedactionMode.SYNTHETIC:
                # Fallback to MASK for now
                replacement = f"[{token_prefix}]"
            else:
                replacement = f"[{token_prefix}]"

            replacements.append((result.start, result.end, replacement))

        # Pass 2: Apply replacements
        # We must apply from end to start to avoid index shifting
        # Sort replacements by start index descending
        replacements.sort(key=lambda x: x[0], reverse=True)

        masked_text = text
        for start, end, repl in replacements:
            masked_text = masked_text[:start] + repl + masked_text[end:]

        # Save updated map
        self.vault.save_map(deid_map)

        return masked_text, deid_map

    @staticmethod
    def _generate_suffix(count: int) -> str:
        """
        Generates a suffix A, B, ... Z, AA, AB... based on count (0-based index).
        Bijective Base-26 system.
        0 -> A
        25 -> Z
        26 -> AA
        """
        if count < 0:
            raise ValueError("Count must be non-negative")

        n = count
        result = ""
        while True:
            n, r = divmod(n, 26)
            result = chr(65 + r) + result
            if n == 0:
                break
            n -= 1
        return result
