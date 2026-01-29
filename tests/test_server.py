# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

from datetime import datetime, timezone
from typing import Generator
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from fastapi.testclient import TestClient

from coreason_aegis.models import DeIdentificationMap
from coreason_aegis.server import app


@pytest.fixture
def mock_aegis_async() -> Generator[AsyncMock, None, None]:
    with patch("coreason_aegis.server.AegisAsync") as MockClass:
        mock_instance = AsyncMock()
        MockClass.return_value = mock_instance
        # Mock __aenter__ and __aexit__ for context manager usage
        mock_instance.__aenter__.return_value = mock_instance
        mock_instance.__aexit__.return_value = None

        # Mock scanner analyzer for health check
        mock_instance.scanner = MagicMock()
        mock_instance.scanner.analyzer = "MockAnalyzer"

        yield mock_instance


@pytest.fixture
def client(mock_aegis_async: AsyncMock) -> Generator[TestClient, None, None]:
    # Pass mock_aegis_async to ensure the patch is active when TestClient runs lifespan
    with TestClient(app) as c:
        yield c


def test_health(client: TestClient, mock_aegis_async: AsyncMock) -> None:
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "protected",
        "engine": "presidio",
        "model": "en_core_web_lg",
    }


def test_health_not_initialized(mock_aegis_async: AsyncMock) -> None:
    """Test health check when Aegis is not initialized."""
    # We use TestClient without entering the context manager manually implies lifespan runs.
    # To test "not initialized", we can manually check the app state logic
    # OR create a client where lifespan fails or is skipped?
    # Actually, TestClient(app) runs lifespan.
    # If we want to test the 503 case, we can manually manipulate state.

    with TestClient(app) as c:
        # Simulate Aegis removed from state
        del c.app.state.aegis
        response = c.get("/health")
        assert response.status_code == 503
        assert response.json()["detail"] == "Aegis not initialized"


def test_sanitize_success(client: TestClient, mock_aegis_async: AsyncMock) -> None:
    """Test sanitize endpoint success."""
    # Setup mock return
    deid_map = DeIdentificationMap(session_id="test-session", expires_at=datetime.now(timezone.utc))
    mock_aegis_async.sanitize.return_value = ("masked text", deid_map)

    response = client.post("/sanitize", json={"text": "My name is John", "session_id": "test-session"})

    assert response.status_code == 200
    data = response.json()
    assert data["text"] == "masked text"
    assert data["deid_map"]["session_id"] == "test-session"

    # Verify sanitize was called
    mock_aegis_async.sanitize.assert_called_once()
    call_args = mock_aegis_async.sanitize.call_args
    assert call_args[0][0] == "My name is John"  # text
    assert call_args[0][1] == "test-session"  # session_id
    # context is 3rd arg, policy is 4th
    assert call_args[0][2].user_id.get_secret_value() == "api-user-test-session"


def test_sanitize_fail_closed(client: TestClient, mock_aegis_async: AsyncMock) -> None:
    """Test that sanitize endpoint fails closed (500) on exception."""
    mock_aegis_async.sanitize.side_effect = Exception("Scanning failed")

    response = client.post("/sanitize", json={"text": "Input", "session_id": "fail-session"})

    assert response.status_code == 500
    assert response.json()["detail"] == "Internal Server Error"


def test_health_exception(client: TestClient, mock_aegis_async: AsyncMock) -> None:
    """Test health check exception handling."""
    # Configure scanner access to raise exception
    # accessing app.state.aegis.scanner raises RuntimeError
    type(mock_aegis_async).scanner = PropertyMock(side_effect=RuntimeError("Broken"))

    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["detail"] == "Unhealthy"


def test_health_analyzer_none(client: TestClient, mock_aegis_async: AsyncMock) -> None:
    """Test health check when analyzer is None."""
    mock_aegis_async.scanner.analyzer = None
    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["detail"] == "Unhealthy"


def test_desanitize_success(client: TestClient, mock_aegis_async: AsyncMock) -> None:
    """Test desanitize endpoint success."""
    mock_aegis_async.desanitize.return_value = "My name is John"

    response = client.post(
        "/desanitize", json={"text": "masked text", "session_id": "test-session", "authorized": True}
    )

    assert response.status_code == 200
    assert response.json()["text"] == "My name is John"

    mock_aegis_async.desanitize.assert_called_once()


def test_desanitize_fail_closed(client: TestClient, mock_aegis_async: AsyncMock) -> None:
    """Test that desanitize endpoint fails closed (500) on exception."""
    mock_aegis_async.desanitize.side_effect = Exception("ReID failed")

    response = client.post("/desanitize", json={"text": "masked", "session_id": "fail-session", "authorized": True})

    assert response.status_code == 500
    assert response.json()["detail"] == "Internal Server Error"
