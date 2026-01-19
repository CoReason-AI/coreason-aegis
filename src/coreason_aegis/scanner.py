# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

"""Named Entity Recognition (NER) scanner implementation.

This module provides the Scanner class which wraps Microsoft Presidio's
AnalyzerEngine to detect sensitive entities in text. It includes custom
recognizers for specific domains like Pharma and Security.
"""

from typing import Any, List, Optional, cast

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerResult

from coreason_aegis.models import AegisPolicy
from coreason_aegis.utils.logger import logger

_ANALYZER_ENGINE_CACHE: Optional[AnalyzerEngine] = None


def _load_custom_recognizers(analyzer: AnalyzerEngine) -> None:
    """Loads and registers custom entity recognizers into the Presidio analyzer.

    Registers recognizers for:
    - MRN: Medical Record Number (6-10 digits)
    - PROTOCOL_ID: 3 letters, dash, 3 numbers
    - LOT_NUMBER: 'LOT-' followed by alphanumeric
    - GENE_SEQUENCE: DNA sequences
    - CHEMICAL_CAS: CAS Registry Numbers
    - SECRET_KEY: API keys (e.g., sk-...)

    Args:
        analyzer: The Presidio AnalyzerEngine instance to update.
    """
    # MRN: Medical Record Number (6-10 digits)
    mrn_pattern = Pattern(name="mrn_pattern", regex=r"\b\d{6,10}\b", score=0.85)
    mrn_recognizer = PatternRecognizer(supported_entity="MRN", patterns=[mrn_pattern])
    analyzer.registry.add_recognizer(mrn_recognizer)

    # PROTOCOL_ID: 3 letters dash 3 numbers
    protocol_pattern = Pattern(name="protocol_pattern", regex=r"\b[A-Z]{3}-\d{3}\b", score=0.85)
    protocol_recognizer = PatternRecognizer(supported_entity="PROTOCOL_ID", patterns=[protocol_pattern])
    analyzer.registry.add_recognizer(protocol_recognizer)

    # LOT_NUMBER: LOT-[alphanumeric]
    lot_pattern = Pattern(name="lot_pattern", regex=r"\bLOT-[A-Z0-9]+\b", score=0.85)
    lot_recognizer = PatternRecognizer(supported_entity="LOT_NUMBER", patterns=[lot_pattern])
    analyzer.registry.add_recognizer(lot_recognizer)

    # GENE_SEQUENCE: DNA sequences (e.g., ATCGATCGAT)
    # Regex: \b[ATCG]{10,}\b (Matches sequences of length 10 or more)
    gene_pattern = Pattern(name="gene_pattern", regex=r"\b[ATCG]{10,}\b", score=0.85)
    gene_recognizer = PatternRecognizer(supported_entity="GENE_SEQUENCE", patterns=[gene_pattern])
    analyzer.registry.add_recognizer(gene_recognizer)

    # CHEMICAL_CAS: CAS Registry Numbers (e.g., 50-00-0)
    # Regex: \b\d{2,7}-\d{2}-\d\b
    cas_pattern = Pattern(name="cas_pattern", regex=r"\b\d{2,7}-\d{2}-\d\b", score=0.85)
    cas_recognizer = PatternRecognizer(supported_entity="CHEMICAL_CAS", patterns=[cas_pattern])
    analyzer.registry.add_recognizer(cas_recognizer)

    # API_KEY: OpenAI or similar API keys starting with sk-
    # Regex: \bsk-[a-zA-Z0-9-]{20,}\b (Matches sk- followed by at least 20 alphanumeric/hyphen chars)
    api_key_pattern = Pattern(name="api_key_pattern", regex=r"\bsk-[a-zA-Z0-9-]{20,}\b", score=0.95)
    api_key_recognizer = PatternRecognizer(supported_entity="SECRET_KEY", patterns=[api_key_pattern])
    analyzer.registry.add_recognizer(api_key_recognizer)


def _get_analyzer_engine() -> AnalyzerEngine:
    """Retrieves or initializes the global Presidio AnalyzerEngine instance.

    Returns:
        The singleton AnalyzerEngine instance.

    Raises:
        RuntimeError: If initialization fails.
    """
    global _ANALYZER_ENGINE_CACHE
    if _ANALYZER_ENGINE_CACHE is None:
        try:
            logger.info("Initializing Presidio AnalyzerEngine...")
            analyzer = AnalyzerEngine()
            _load_custom_recognizers(analyzer)
            _ANALYZER_ENGINE_CACHE = analyzer
            logger.info("Presidio AnalyzerEngine initialized successfully.")
        except Exception as e:
            logger.critical(f"Failed to initialize Presidio AnalyzerEngine: {e}")
            raise RuntimeError(f"Scanner initialization failed: {e}") from e
    return _ANALYZER_ENGINE_CACHE


class Scanner:
    """A high-speed Named Entity Recognition (NER) scanner.

    This class provides an interface to the Presidio AnalyzerEngine for detecting
    sensitive information in text based on a configurable policy.
    """

    def __init__(self) -> None:
        """Initializes the Scanner."""
        self._analyzer = _get_analyzer_engine()

    @property
    def analyzer(self) -> AnalyzerEngine:
        """Returns the underlying Presidio AnalyzerEngine."""
        return self._analyzer

    def scan(self, text: str, policy: AegisPolicy) -> List[RecognizerResult]:
        """Scans the provided text for entities defined in the policy.

        Args:
            text: The text string to scan.
            policy: The AegisPolicy defining entity types and confidence thresholds.

        Returns:
            A list of RecognizerResult objects containing detected entities.

        Raises:
            RuntimeError: If the scan operation fails (Fail Closed principle).
        """
        if not text:
            return []

        try:
            # Explicitly cast because presidio-analyzer type hints might be loose or Any
            results = self.analyzer.analyze(
                text=text,
                entities=policy.entity_types,
                language="en",
                score_threshold=policy.confidence_score,
                allow_list=policy.allow_list,
            )
            return cast(List[RecognizerResult], cast(Any, results))
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            # Fail Closed: If scanning fails, we must alert or block.
            # Raising exception effectively blocks the process relying on it.
            raise RuntimeError(f"Scan operation failed: {e}") from e
