# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from coreason_aegis.server import app

@pytest.fixture
def client():
    """Fixture to provide a TestClient instance with lifespan management."""
    with TestClient(app) as c:
        yield c

def test_health_check(client):
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "protected",
        "engine": "presidio",
        "model": "en_core_web_lg"
    }

def test_health_check_unhealthy(client):
    """Test health check when scanner is not initialized."""
    # Temporarily replace scanner with a mock that has no analyzer
    original_scanner = app.state.aegis.scanner
    mock_scanner = MagicMock()
    # Configure mock to fail the check: hasattr(scanner, "analyzer") and scanner.analyzer
    # We can just make scanner.analyzer None
    mock_scanner.analyzer = None

    app.state.aegis.scanner = mock_scanner
    try:
        response = client.get("/health")
        assert response.status_code == 503
        assert "Unhealthy" in response.json()["detail"]
    finally:
        app.state.aegis.scanner = original_scanner

def test_sanitize_endpoint(client):
    """Test the sanitize endpoint with valid data."""
    payload = {
        "text": "My name is John Doe and I live in New York.",
        "session_id": "test_session_1"
    }
    response = client.post("/sanitize", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert "text" in data
    assert "map" in data
    assert data["map"]["session_id"] == "test_session_1"

    # Check redaction
    sanitized_text = data["text"]
    assert "John Doe" not in sanitized_text
    assert "New York" not in sanitized_text
    # Expect tokens (depending on policy, likely REPLACE)
    # Just checking if they are redacted is enough, but let's check for brackets
    assert "[" in sanitized_text and "]" in sanitized_text

def test_desanitize_endpoint(client):
    """Test the desanitize endpoint (requires state from sanitize)."""
    session_id = "test_session_2"
    original_text = "Contact support at 555-0199."

    # 1. Sanitize
    san_response = client.post("/sanitize", json={
        "text": original_text,
        "session_id": session_id
    })
    assert san_response.status_code == 200
    san_text = san_response.json()["text"]

    # 2. Desanitize (Authorized)
    desan_response = client.post("/desanitize", json={
        "text": san_text,
        "session_id": session_id,
        "authorized": True
    })
    assert desan_response.status_code == 200
    desan_text = desan_response.json()["text"]

    assert desan_text == original_text

def test_desanitize_unauthorized(client):
    """Test desanitize without authorization."""
    session_id = "test_session_3"
    original_text = "My email is test@example.com"

    # 1. Sanitize
    san_response = client.post("/sanitize", json={
        "text": original_text,
        "session_id": session_id
    })
    san_text = san_response.json()["text"]

    # 2. Desanitize (Unauthorized)
    desan_response = client.post("/desanitize", json={
        "text": san_text,
        "session_id": session_id,
        "authorized": False
    })
    assert desan_response.status_code == 200
    # Should return the masked text
    assert desan_response.json()["text"] == san_text

def test_sanitize_fail_closed():
    """Test that the system fails closed (500) if scanning/masking fails."""
    # Patching AegisAsync.sanitize to raise an exception
    with patch("coreason_aegis.main.AegisAsync.sanitize", side_effect=Exception("Simulated Failure")):
        # We need a new client here or rely on the patch affecting the instance.
        # Since AegisAsync is instantiated inside lifespan, we must patch the CLASS method
        # so that the instance method is affected, OR patch where it's used.
        # Patching the class method works for instances.

        with TestClient(app) as fail_client:
            payload = {
                "text": "Safe text",
                "session_id": "fail_test"
            }
            response = fail_client.post("/sanitize", json=payload)
            assert response.status_code == 500
            assert "Sanitization failed" in response.json()["detail"]

def test_desanitize_fail_closed():
    """Test that the system fails closed (500) if re-identification fails."""
    with patch("coreason_aegis.main.AegisAsync.desanitize", side_effect=Exception("Simulated Failure")):
        with TestClient(app) as fail_client:
            payload = {
                "text": "Some text",
                "session_id": "fail_test_desan",
                "authorized": True
            }
            response = fail_client.post("/desanitize", json=payload)
            assert response.status_code == 500
            assert "Desanitization failed" in response.json()["detail"]
