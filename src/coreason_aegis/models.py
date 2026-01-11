from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List

from pydantic import BaseModel, Field


class RedactionMode(str, Enum):
    MASK = "MASK"  # [PERSON]
    REPLACE = "REPLACE"  # [PATIENT_A]
    SYNTHETIC = "SYNTHETIC"  # "Jane Doe"


class AegisPolicy(BaseModel):
    allow_list: List[str] = Field(default_factory=list)  # Terms to NEVER redact (e.g. "Tylenol")
    entity_types: List[str] = Field(
        default_factory=lambda: ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS", "DATE_TIME"]
    )
    mode: RedactionMode = RedactionMode.REPLACE
    confidence_score: float = 0.85


class DeIdentificationMap(BaseModel):
    session_id: str
    mappings: Dict[str, str] = Field(default_factory=dict)  # { "[TOKEN]": "REAL_VALUE" }
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
