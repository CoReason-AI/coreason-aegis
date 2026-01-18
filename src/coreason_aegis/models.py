# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List

from pydantic import BaseModel, Field


class RedactionMode(str, Enum):
    MASK = "MASK"  # [PERSON]
    REPLACE = "REPLACE"  # [PATIENT_A]
    SYNTHETIC = "SYNTHETIC"  # "Jane Doe"
    HASH = "HASH"  # "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"


class AegisPolicy(BaseModel):
    allow_list: List[str] = Field(default_factory=list)  # Terms to NEVER redact (e.g. "Tylenol")
    entity_types: List[str] = Field(
        default_factory=lambda: [
            "PERSON",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "IP_ADDRESS",
            "DATE_TIME",
            "SECRET_KEY",
        ]
    )
    mode: RedactionMode = RedactionMode.REPLACE
    # Lowered confidence score to ensure high recall for things like Dates.
    # We prioritize recall/safety (redacting more) over precision (leaking less).
    # Original PRD stated 0.85, but 0.40 is the verified setting.
    confidence_score: float = 0.40


class DeIdentificationMap(BaseModel):
    session_id: str
    mappings: Dict[str, str] = Field(default_factory=dict)  # { "[TOKEN]": "REAL_VALUE" }
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
