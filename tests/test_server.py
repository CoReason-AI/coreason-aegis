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
from fastapi.testclient import TestClient

from coreason_aegis.server import app


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as c:
        yield c


@pytest.fixture
def mock_aegis_async() -> Generator[MagicMock, None, None]:
    # Patch AegisAsync to avoid real loading in unit tests
    with patch("coreason_aegis.server.AegisAsync") as mock:
        yield mock


def test_health_check_unhealthy() -> None:
    # Patch AegisAsync to avoid real loading and simulate failure
    with patch("coreason_aegis.server.AegisAsync") as mock_cls:
        instance = mock_cls.return_value
        # Use a fixed mock for scanner to ensure consistent attribute access
        scanner_mock = MagicMock()
        scanner_mock.analyzer = None
        instance.scanner = scanner_mock

        with TestClient(app) as client:
            response = client.get("/health")
            assert response.status_code == 503
            assert response.json()["detail"] == "Unhealthy: Scanner not initialized"


def test_health_check_healthy(client: TestClient) -> None:
    # Use real lifespan (will load real AegisAsync which loads real models)
    # This might be slow, but verifies integration.
    # To speed up, we could mock just the heavy parts if needed.
    # For now, let's assume it runs reasonably fast or we mock Scanner.

    # If we want to mock Scanner loading in integration test:
    with patch("coreason_aegis.scanner.AnalyzerEngine"):
        with patch("coreason_aegis.scanner._ANALYZER_ENGINE_CACHE", None):
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json()["status"] == "protected"


def test_sanitize_endpoint(client: TestClient) -> None:
    """Test the sanitize endpoint with valid data."""
    with patch("coreason_aegis.scanner.AnalyzerEngine"):
        with patch("coreason_aegis.scanner._ANALYZER_ENGINE_CACHE", None):
            payload = {
                "text": "My name is John Doe and I live in New York.",
                "session_id": "test_session_1",
                "user_id": "user1",
            }
            response = client.post("/sanitize", json=payload)
            assert response.status_code == 200
            data = response.json()
            assert "map" in data
            assert "text" in data
            # Verify owner_id in map
            assert data["map"]["owner_id"] == "user1"


def test_sanitize_endpoint_failure() -> None:
    """Test the sanitize endpoint failure handling."""
    with patch("coreason_aegis.server.AegisAsync") as mock_cls:
        instance = mock_cls.return_value
        # Mock async context manager return
        instance.__aenter__.return_value = instance
        # Mock sanitize to raise exception
        instance.sanitize.side_effect = Exception("Boom")

        with TestClient(app) as client:
            payload = {"text": "test", "session_id": "s", "user_id": "u"}
            response = client.post("/sanitize", json=payload)
            assert response.status_code == 500
            assert "Sanitization failed: Boom" in response.json()["detail"]


def test_desanitize_endpoint(client: TestClient) -> None:
    """Test the desanitize endpoint (requires state from sanitize)."""
    with patch("coreason_aegis.scanner.AnalyzerEngine"):
        with patch("coreason_aegis.scanner._ANALYZER_ENGINE_CACHE", None):
            session_id = "test_session_2"
            original_text = "Contact support at 555-0199."

            # 1. Sanitize
            san_response = client.post(
                "/sanitize", json={"text": original_text, "session_id": session_id, "user_id": "user1"}
            )
            assert san_response.status_code == 200
            san_text = san_response.json()["text"]

            # 2. Desanitize with same user
            desan_response = client.post(
                "/desanitize", json={"text": san_text, "session_id": session_id, "user_id": "user1"}
            )
            assert desan_response.status_code == 200
            assert desan_response.json()["text"] == original_text


def test_desanitize_unauthorized(client: TestClient) -> None:
    """Test desanitize without authorization."""
    with patch("coreason_aegis.scanner.AnalyzerEngine"):
        with patch("coreason_aegis.scanner._ANALYZER_ENGINE_CACHE", None):
            session_id = "test_session_3"
            original_text = "My email is test@example.com"

            # 1. Sanitize
            san_response = client.post(
                "/sanitize", json={"text": original_text, "session_id": session_id, "user_id": "user1"}
            )
            san_text = san_response.json()["text"]

            # 2. Desanitize with different user
            desan_response = client.post(
                "/desanitize", json={"text": san_text, "session_id": session_id, "user_id": "attacker"}
            )

            # Should fail
            assert desan_response.status_code == 500
            assert "Unauthorized access" in desan_response.json()["detail"]
