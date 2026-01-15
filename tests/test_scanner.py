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
    with patch("coreason_aegis.scanner.AnalyzerEngine") as mock:
        yield mock


@pytest.fixture
def scanner(mock_analyzer_engine: MagicMock) -> Scanner:
    # Reset singleton instance for each test
    Scanner._instance = None
    Scanner._analyzer = None
    return Scanner()


def test_scanner_initialization(mock_analyzer_engine: MagicMock) -> None:
    Scanner._instance = None
    Scanner._analyzer = None
    scanner = Scanner()
    assert scanner is not None
    mock_analyzer_engine.assert_called_once()


def test_scanner_singleton(mock_analyzer_engine: MagicMock) -> None:
    # Reset singleton first to ensure clean state
    Scanner._instance = None
    Scanner._analyzer = None

    s1 = Scanner()
    s2 = Scanner()
    assert s1 is s2
    mock_analyzer_engine.assert_called_once()  # Should only be called once


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
    # Reset singleton
    Scanner._instance = None
    Scanner._analyzer = None

    with patch("coreason_aegis.scanner.AnalyzerEngine", side_effect=Exception("Init failed")):
        with pytest.raises(RuntimeError, match="Scanner initialization failed"):
            Scanner()


def test_analyzer_property_access_error() -> None:
    # Simulate a state where _analyzer is None but _instance exists
    # (should ideally not happen if __new__ handles it, but good for coverage)
    Scanner._instance = None
    Scanner._analyzer = None

    with patch("coreason_aegis.scanner.AnalyzerEngine"):
        s = Scanner()
        s._analyzer = None  # Manually break it

        with pytest.raises(RuntimeError, match="Scanner not initialized properly"):
            _ = s.analyzer
