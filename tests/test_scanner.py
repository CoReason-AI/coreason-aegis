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
from presidio_analyzer import RecognizerResult

from coreason_aegis.models import AegisPolicy
from coreason_aegis.scanner import Scanner


@pytest.fixture
def mock_analyzer_engine() -> Generator[MagicMock, None, None]:
    # We patch the AnalyzerEngine class used inside scanner.py
    # NOTE: Since scanner.py now uses a module-level cache, we must ensure
    # the cache is cleared or mocked properly.
    # However, patching 'coreason_aegis.scanner.AnalyzerEngine' effectively mocks
    # the class instantiation. But if _ANALYZER_ENGINE_CACHE is already set,
    # the mock won't be used. So we must clear the cache.
    with patch("coreason_aegis.scanner.AnalyzerEngine") as mock:
        # Clear the cache before and after test
        with patch("coreason_aegis.scanner._ANALYZER_ENGINE_CACHE", None):
            yield mock


@pytest.fixture
def scanner(mock_analyzer_engine: MagicMock) -> Scanner:
    return Scanner()


def test_scanner_initialization(mock_analyzer_engine: MagicMock) -> None:
    scanner = Scanner()
    assert scanner is not None
    mock_analyzer_engine.assert_called_once()


def test_scanner_shared_engine(mock_analyzer_engine: MagicMock) -> None:
    """
    Verifies that multiple Scanner instances share the same AnalyzerEngine
    (via module-level caching), but are distinct Scanner objects.
    """
    s1 = Scanner()
    s2 = Scanner()

    # Instances are different
    assert s1 is not s2

    # Engine is shared
    assert s1.analyzer is s2.analyzer

    # Analyzer initialized only once
    mock_analyzer_engine.assert_called_once()


def test_scan_empty_text(scanner: Scanner) -> None:
    policy = AegisPolicy()
    results = scanner.scan("", policy)
    assert results == []


def test_scan_success(scanner: Scanner, mock_analyzer_engine: MagicMock) -> None:
    mock_instance = mock_analyzer_engine.return_value
    mock_result = RecognizerResult(entity_type="PERSON", start=0, end=4, score=0.9)
    mock_instance.analyze.return_value = [mock_result]

    policy = AegisPolicy(entity_types=["PERSON"], confidence_score=0.8)
    results = scanner.scan("John", policy)

    assert len(results) == 1
    assert results[0] == mock_result
    mock_instance.analyze.assert_called_with(
        text="John",
        entities=["PERSON"],
        language="en",
        score_threshold=0.8,
        allow_list=[],
    )


def test_scan_failure_raises_exception(scanner: Scanner, mock_analyzer_engine: MagicMock) -> None:
    mock_instance = mock_analyzer_engine.return_value
    mock_instance.analyze.side_effect = Exception("Analyzer error")

    policy = AegisPolicy()
    with pytest.raises(RuntimeError, match="Scan operation failed"):
        scanner.scan("Test", policy)


def test_initialization_failure() -> None:
    # Ensure cache is clear for this test is handled by the fixture logic usually,
    # but here we need to manually simulate the failure environment without the fixture
    # interfering or use a specific patch context.

    # We need to ensure _ANALYZER_ENGINE_CACHE is None
    with patch("coreason_aegis.scanner._ANALYZER_ENGINE_CACHE", None):
        with patch("coreason_aegis.scanner.AnalyzerEngine", side_effect=Exception("Init failed")):
            with pytest.raises(RuntimeError, match="Scanner initialization failed"):
                Scanner()
