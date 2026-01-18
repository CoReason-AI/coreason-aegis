# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

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
        # Also handle overlap: If two entities overlap, we must pick one.
        # We sort by start ASC, then by length DESC to prefer longer matches if they start at same position.
        # However, if one starts later but overlaps, we skip it.
        sorted_results_asc = sorted(results, key=lambda x: (x.start, -(x.end - x.start)))

        # Filter overlaps
        filtered_results: List[RecognizerResult] = []
        last_end = -1
        for res in sorted_results_asc:
            if res.start >= last_end:
                filtered_results.append(res)
                last_end = res.end
            else:
                # This result overlaps with the previous one. Skip it.
                # Example: "on 01/01/2025" (start 43, end 57) vs "01/01/2025" (start 47, end 57)
                # If "on..." comes first (start 43), we keep it. "01..." (start 47) is < 57, so skip.
                # This prevents replacing text that has already been accounted for.
                pass

        # Reverse lookup: Real Value -> Token
        real_to_token: Dict[str, str] = {v: k for k, v in deid_map.mappings.items()}

        # Pass 1: Assign tokens
        # We store the determined replacement for each result to apply later
        replacements: List[Tuple[int, int, str]] = []

        for result in filtered_results:
            entity_text = text[result.start : result.end]

            # Check policy Allow List
            if entity_text in policy.allow_list:
                continue

            # Determine token prefix
            token_prefix = self._normalize_entity_type(result.entity_type)

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
                replacement = f"[{token_prefix}]"  # pragma: no cover

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
        elif entity_type == "MRN":
            # 6-10 digits
            # We'll pick 8 digits as a safe default
            return str(self.faker.random_number(digits=8, fix_len=True))
        elif entity_type == "PROTOCOL_ID":
            # [A-Z]{3}-\d{3}
            # Faker doesn't have a direct provider for this, so we build it.
            # Use random_uppercase_letter and random_number
            letters = "".join(self.faker.random_letters(length=3)).upper()
            digits = str(self.faker.random_number(digits=3, fix_len=True))
            return f"{letters}-{digits}"
        elif entity_type == "LOT_NUMBER":
            # LOT-[A-Z0-9]+
            # Let's generate LOT-[A-Z]{2}\d{2} for simplicity and realism
            suffix_part = "".join(self.faker.random_letters(length=2)).upper()
            digits_part = str(self.faker.random_number(digits=2, fix_len=True))
            return f"LOT-{suffix_part}{digits_part}"
        elif entity_type == "GENE_SEQUENCE":
            # Sequence of ATCG.
            # Match length of input if possible? Or just fixed?
            # Input text is passed to this method.
            # Let's try to match the length of the original text, or default to 10 if too short.
            length = max(len(text), 10)
            # Efficiently generate sequence
            # random.choices is not seeded by faker.seed_instance?
            # Faker has random_choices or similar.
            # Actually, self.faker.random.choices works and uses the seeded random instance.
            bases = ["A", "T", "C", "G"]
            return "".join(self.faker.random_elements(elements=bases, length=length, unique=False))
        elif entity_type == "CHEMICAL_CAS":
            # \d{2,7}-\d{2}-\d
            # Let's generate roughly: 5 digits - 2 digits - 1 digit
            part1 = str(self.faker.random_number(digits=5, fix_len=True))
            part2 = str(self.faker.random_number(digits=2, fix_len=True))
            part3 = str(self.faker.random_digit())
            return f"{part1}-{part2}-{part3}"
        elif entity_type == "SECRET_KEY":
            # sk-[A-Za-z0-9]{20,}
            # Generate 24 chars suffix
            suffix = "".join(self.faker.random_letters(length=24))
            # random_letters might return only letters. We want alphanumeric.
            # random_elements with string.ascii_letters + digits is better.
            import string

            chars = string.ascii_letters + string.digits
            suffix = "".join(self.faker.random_elements(elements=list(chars), length=24, unique=False))
            return f"sk-{suffix}"

        else:
            # Fallback for unknown standard ones
            # Use a generic word
            return cast(str, cast(Any, self.faker.word()))

    @staticmethod
    def _normalize_entity_type(entity_type: str) -> str:
        """
        Normalizes Presidio entity types to simplified tokens per PRD.
        DATE_TIME -> DATE
        EMAIL_ADDRESS -> EMAIL
        PHONE_NUMBER -> PHONE
        IP_ADDRESS -> IP
        SECRET_KEY -> KEY
        PERSON -> PATIENT
        """
        if entity_type == "PERSON":
            return "PATIENT"
        elif entity_type == "DATE_TIME":
            return "DATE"
        elif entity_type == "EMAIL_ADDRESS":
            return "EMAIL"
        elif entity_type == "PHONE_NUMBER":
            return "PHONE"
        elif entity_type == "IP_ADDRESS":
            return "IP"
        elif entity_type == "SECRET_KEY":
            return "SECRET_KEY"
        elif entity_type == "LOCATION":
            return "LOCATION"
        return entity_type

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
