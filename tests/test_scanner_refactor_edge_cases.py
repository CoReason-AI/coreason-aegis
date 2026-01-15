# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

from coreason_aegis.scanner import Scanner


@pytest.fixture
def clean_scanner_state() -> Generator[None, None, None]:
    """Ensure _ANALYZER_ENGINE_CACHE is None before and after test."""
    with patch("coreason_aegis.scanner._ANALYZER_ENGINE_CACHE", None):
        yield


def test_initialization_recovery(clean_scanner_state: None) -> None:
    """
    Test Case: Initialization Recovery.
    Verifies that if AnalyzerEngine fails to load on the first attempt,
    the cache remains None and a subsequent attempt can succeed (retry mechanism).
    """
    # 1. First attempt fails
    with patch("coreason_aegis.scanner.AnalyzerEngine", side_effect=RuntimeError("Transient Model Error")) as mock_fail:
        with pytest.raises(RuntimeError, match="Scanner initialization failed"):
            Scanner()

        mock_fail.assert_called_once()

    # Verify cache is still None (via the module level - need to check via Scanner internals or re-attempt)
    # We can check by trying again.

    # 2. Second attempt succeeds
    with patch("coreason_aegis.scanner.AnalyzerEngine") as mock_success:
        scanner = Scanner()
        assert scanner is not None
        assert scanner.analyzer is not None

        mock_success.assert_called_once()


def test_instance_identity_verification(clean_scanner_state: None) -> None:
    """
    Test Case: Instance Identity Verification.
    Verifies that creating multiple Scanner instances returns distinct objects
    but shares the exact same _analyzer instance ID (module-level singleton).
    """
    # Use real (or mocked) engine
    with patch("coreason_aegis.scanner.AnalyzerEngine"):
        s1 = Scanner()
        s2 = Scanner()
        s3 = Scanner()

        # Scanners are different objects (cheap wrappers)
        assert s1 is not s2
        assert s2 is not s3

        # Analyzer is identical (shared heavyweight object)
        assert s1.analyzer is s2.analyzer
        assert s2.analyzer is s3.analyzer
        assert id(s1.analyzer) == id(s3.analyzer)


def test_custom_recognizer_idempotency(clean_scanner_state: None) -> None:
    """
    Test Case: Custom Recognizer Idempotency.
    Ensures that custom recognizers are added only once, during the initial load,
    and not re-added or duplicated if _get_analyzer_engine is called internally multiple times
    (though caching prevents this, we verify logic).
    """
    with patch("coreason_aegis.scanner.AnalyzerEngine") as mock_engine_cls:
        mock_registry = MagicMock()
        mock_engine_cls.return_value.registry = mock_registry

        # First Init
        _ = Scanner()

        # Verify recognizers added
        # _load_custom_recognizers adds: MRN, PROTOCOL_ID, LOT_NUMBER, GENE, CAS, SECRET_KEY (6)
        assert mock_registry.add_recognizer.call_count == 6

        # Second Init (should use cache)
        _ = Scanner()

        # Should not add anymore
        assert mock_registry.add_recognizer.call_count == 6


def test_stress_instantiation(clean_scanner_state: None) -> None:
    """
    Test Case: Complex Scenario / Stress Test.
    Create a large number of Scanner instances to ensure memory usage stability
    (verifying we aren't leaking AnalyzerEngines).
    """
    with patch("coreason_aegis.scanner.AnalyzerEngine") as mock_engine_cls:
        scanners = []
        for _ in range(1000):
            scanners.append(Scanner())

        # Ensure only 1 engine created
        mock_engine_cls.assert_called_once()

        # Verify all share the same analyzer
        first_analyzer = scanners[0].analyzer
        assert all(s.analyzer is first_analyzer for s in scanners)
