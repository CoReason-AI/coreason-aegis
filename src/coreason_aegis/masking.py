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

        # Sort results by start index in descending order to replace from end
        # This prevents index shifting issues.
        sorted_results = sorted(results, key=lambda x: x.start, reverse=True)

        masked_text = text
        # Local cache for this masking operation to ensure consistency within the text if needed,
        # but we rely on the deid_map for session consistency.

        # We also need to track what we added to save it back.
        # But we modify the deid_map object directly.

        # To support consistency (e.g. John -> PATIENT_A every time), we need to check if the real value
        # already has a token in the map.
        # The map is Token -> Real Value.
        # We need Reverse Lookup: Real Value -> Token.
        real_to_token: Dict[str, str] = {v: k for k, v in deid_map.mappings.items()}

        # We also need counters for types to generate PATIENT_A, PATIENT_B, etc.
        # Or we can hash.
        # PRD says: "If 'John Doe' is mentioned 5 times, it must always map to [PATIENT_A]"

        # We need to process results.
        for result in sorted_results:
            entity_text = text[result.start : result.end]

            # Check policy Allow List (already handled by Scanner usually, but double check?)
            if entity_text in policy.allow_list:
                continue

            # Determine replacement
            # Map PERSON to PATIENT token prefix
            token_prefix = result.entity_type
            if token_prefix == "PERSON":
                token_prefix = "PATIENT"

            if policy.mode == RedactionMode.MASK:
                replacement = f"[{token_prefix}]"
            elif policy.mode == RedactionMode.REPLACE:
                # Consistency check
                if entity_text in real_to_token:
                    replacement = real_to_token[entity_text]
                else:
                    # Generate new token
                    # We need a strategy. [ENTITY_TYPE_COUNTER] or [ENTITY_TYPE_HASH]
                    # PRD example: [PATIENT_A].
                    # Let's use a simple counter per entity type for the session?
                    # But recovering the counter state from just the map is hard (parsing A, B...).
                    # Easier: SHA256 suffix? [PATIENT_a1b2...]
                    # Or simpler: Increment based on existing count of that type in map?
                    # Let's count existing tokens of this type.

                    # Optimized approach: Use a deterministic hash of the value for the suffix?
                    # But PRD says [PATIENT_A] is for reasoning.
                    # Let's try to generate A, B, C...

                    # Count existing tokens of this type
                    existing_count = sum(1 for t in deid_map.mappings.keys() if t.startswith(f"[{token_prefix}_"))
                    suffix = self._generate_suffix(existing_count)
                    replacement = f"[{token_prefix}_{suffix}]"

                    # Update maps
                    deid_map.mappings[replacement] = entity_text
                    real_to_token[entity_text] = replacement

            elif policy.mode == RedactionMode.SYNTHETIC:
                # Not fully implemented yet, fallback to MASK
                replacement = f"[{token_prefix}]"
            else:
                replacement = f"[{token_prefix}]"

            # Apply replacement
            masked_text = masked_text[: result.start] + replacement + masked_text[result.end :]

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
