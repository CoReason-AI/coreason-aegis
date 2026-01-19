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
Data models for the CoReason Aegis privacy filter.

This module defines the Pydantic models used for policy configuration (AegisPolicy)
and the internal mapping storage (DeIdentificationMap).
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List

from pydantic import BaseModel, Field


class RedactionMode(str, Enum):
    """
    Enumeration of supported redaction modes.

    Attributes:
        MASK: Replace with generic token (e.g., [PERSON]).
        REPLACE: Replace with unique token (e.g., [PATIENT_A]).
        SYNTHETIC: Replace with fake data (e.g., "Jane Doe").
        HASH: Replace with SHA256 hash.
    """

    MASK = "MASK"
    REPLACE = "REPLACE"
    SYNTHETIC = "SYNTHETIC"
    HASH = "HASH"


class AegisPolicy(BaseModel):
    """
    Configuration policy for the Aegis privacy filter.

    Attributes:
        allow_list: List of terms to exclude from redaction.
        entity_types: List of entity types to detect and redact.
        mode: The redaction mode to apply (REPLACE, MASK, etc.).
        confidence_score: Threshold for NER confidence (0.0 to 1.0).
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
    """
    Internal model representing the mapping between tokens and real values.

    Attributes:
        session_id: Unique identifier for the user session.
        mappings: Dictionary mapping tokens (keys) to real values (values).
        created_at: Timestamp of creation.
        expires_at: Timestamp when this mapping expires.
    """

    session_id: str
    mappings: Dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
