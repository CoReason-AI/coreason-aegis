from typing import List, Optional, cast

from presidio_analyzer import AnalyzerEngine, RecognizerResult

from coreason_aegis.models import AegisPolicy
from coreason_aegis.utils.logger import logger


class Scanner:
    """
    A high-speed Named Entity Recognition (NER) engine.
    Wraps Microsoft Presidio AnalyzerEngine.
    """

    _instance: Optional["Scanner"] = None
    _analyzer: Optional[AnalyzerEngine] = None

    def __new__(cls) -> "Scanner":
        if cls._instance is None:
            cls._instance = super(Scanner, cls).__new__(cls)
            try:
                # Load the analyzer engine once (Singleton)
                logger.info("Initializing Presidio AnalyzerEngine...")
                cls._analyzer = AnalyzerEngine()
                logger.info("Presidio AnalyzerEngine initialized successfully.")
            except Exception as e:
                logger.critical(f"Failed to initialize Presidio AnalyzerEngine: {e}")
                raise RuntimeError(f"Scanner initialization failed: {e}") from e
        return cls._instance

    @property
    def analyzer(self) -> AnalyzerEngine:
        if self._analyzer is None:
            raise RuntimeError("Scanner not initialized properly.")
        return self._analyzer

    def scan(self, text: str, policy: AegisPolicy) -> List[RecognizerResult]:
        """
        Scans the text for entities defined in the policy.
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
            return cast(List[RecognizerResult], results)
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            # Fail Closed: If scanning fails, we must alert or block.
            # Raising exception effectively blocks the process relying on it.
            raise RuntimeError(f"Scan operation failed: {e}") from e
