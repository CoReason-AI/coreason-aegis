from typing import List, Optional, cast

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerResult

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
                cls._load_custom_recognizers(cls._analyzer)
                logger.info("Presidio AnalyzerEngine initialized successfully.")
            except Exception as e:
                logger.critical(f"Failed to initialize Presidio AnalyzerEngine: {e}")
                raise RuntimeError(f"Scanner initialization failed: {e}") from e
        return cls._instance

    @staticmethod
    def _load_custom_recognizers(analyzer: AnalyzerEngine) -> None:
        """
        Loads custom recognizers for Pharma entities and registers them.
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
