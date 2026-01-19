# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

"""Data models for coreason-aegis configuration and state management.

This module defines the core data structures used throughout the Aegis system,
including policy configuration and de-identification mapping state.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List

from pydantic import BaseModel, Field


class RedactionMode(str, Enum):
    """Enumeration of supported redaction modes.

    Attributes:
        MASK: Replace entity with generic type token (e.g., [PERSON]).
        REPLACE: Replace entity with a consistent, tracked token (e.g., [PATIENT_A]).
        SYNTHETIC: Replace entity with realistic fake data (e.g., "Jane Doe").
        HASH: Replace entity with a SHA-256 hash.
    """

    MASK = "MASK"
    REPLACE = "REPLACE"
    SYNTHETIC = "SYNTHETIC"
    HASH = "HASH"


class AegisPolicy(BaseModel):
    """Configuration policy for the Aegis scanner and masker.

    Attributes:
        allow_list: List of terms to explicitly exclude from redaction (e.g., "Tylenol").
        entity_types: List of Presidio entity types to detect and redact.
        mode: The redaction strategy to apply (RedactionMode).
        confidence_score: Minimum confidence score (0.0-1.0) for entity detection.
    """

    allow_list: List[str] = Field(default_factory=list)
    entity_types: List[str] = Field(
        default_factory=lambda: [
            "PERSON",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "IP_ADDRESS",
            "DATE_TIME",
            "LOCATION",
            "SECRET_KEY",
        ]
    )
    mode: RedactionMode = RedactionMode.REPLACE
    # Lowered confidence score to ensure high recall for things like Dates.
    # We prioritize recall/safety (redacting more) over precision (leaking less).
    # Original PRD stated 0.85, but 0.40 is the verified setting.
    confidence_score: float = 0.40


class DeIdentificationMap(BaseModel):
    """State container for mapping redacted tokens back to original values.

    Attributes:
        session_id: Unique identifier for the current session.
        mappings: Dictionary mapping tokens (e.g., "[PATIENT_A]") to real values.
        created_at: Timestamp when this map was created.
        expires_at: Timestamp when this map should be evicted.
    """

    session_id: str
    mappings: Dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
