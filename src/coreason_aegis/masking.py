import hashlib
from typing import Any, Dict, List, Tuple, cast

from faker import Faker
from presidio_analyzer import RecognizerResult

from coreason_aegis.models import AegisPolicy, DeIdentificationMap, RedactionMode
from coreason_aegis.vault import VaultManager


class MaskingEngine:
    """
    Replaces detected entities with tokens and manages the de-identification map.
    """

    def __init__(self, vault: VaultManager) -> None:
        self.vault = vault
        # Initialize Faker once. We will seed it per usage.
        self.faker = Faker()

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
                # Deterministic synthetic replacement
                replacement = self._get_synthetic_replacement(entity_text, result.entity_type)
            elif policy.mode == RedactionMode.HASH:
                # Deterministic HASH replacement
                # Use SHA-256 and return hex digest
                replacement = hashlib.sha256(entity_text.encode("utf-8")).hexdigest()
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

        # Save updated map (Only relevant for REPLACE mode,
        # but saving is harmless/idempotent for others if mapping didn't change)
        self.vault.save_map(deid_map)

        return masked_text, deid_map

    def _get_synthetic_replacement(self, text: str, entity_type: str) -> str:
        """
        Generates a deterministic synthetic value using Faker.
        """
        # Hash the input text to seed Faker
        # Use hashlib.sha256 for consistency
        hash_object = hashlib.sha256(text.encode("utf-8"))
        # Convert hash to integer for seeding
        seed_val = int(hash_object.hexdigest(), 16)

        # Faker.seed() is global, which is thread-unsafe and bad practice if used globally.
        # However, Faker instances can be seeded individually if we use the generator correctly.
        # The standard Faker class proxies to a generator.
        # self.faker.seed_instance(seed_val) is the correct way for the instance.
        self.faker.seed_instance(seed_val)

        if entity_type == "PERSON":
            return cast(str, cast(Any, self.faker.name()))
        elif entity_type == "EMAIL_ADDRESS":
            return cast(str, cast(Any, self.faker.email()))
        elif entity_type == "PHONE_NUMBER":
            return cast(str, cast(Any, self.faker.phone_number()))
        elif entity_type == "IP_ADDRESS":
            return cast(str, cast(Any, self.faker.ipv4()))
        elif entity_type == "DATE_TIME":
            return cast(str, cast(Any, self.faker.date()))
        else:
            # Fallback for custom entities or unknown standard ones
            # For things like MRN, maybe random digits?
            # Or just return a placeholder + random string?
            # Let's try to be smart or generic.
            if "ID" in entity_type or "NUMBER" in entity_type or "MRN" in entity_type:
                return str(self.faker.random_number(digits=8))

            # Use a generic word
            return cast(str, cast(Any, self.faker.word()))

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
