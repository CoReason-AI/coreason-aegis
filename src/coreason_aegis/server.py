# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

"""FastAPI server implementation for the Aegis Privacy Microservice.

This module provides the HTTP interface for the Aegis system, exposing
endpoints for sanitization, de-sanitization, and health checks.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator, List, Optional

from coreason_identity.models import UserContext
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from coreason_aegis.main import AegisAsync
from coreason_aegis.models import AegisPolicy, DeIdentificationMap


class SanitizeRequest(BaseModel):
    """Request model for sanitizing text."""

    text: str
    session_id: Optional[str] = None
    policy: AegisPolicy | None = None
    # Simulated identity fields for now
    user_id: str = "default_user"
    permissions: List[str] = []


class SanitizeResponse(BaseModel):
    """Response model containing sanitized text and mapping data."""

    text: str
    map: DeIdentificationMap


class DesanitizeRequest(BaseModel):
    """Request model for de-sanitizing text."""

    text: str
    session_id: str
    # authorized is no longer used, we rely on identity
    user_id: str = "default_user"
    permissions: List[str] = []


class DesanitizeResponse(BaseModel):
    """Response model containing re-identified text."""

    text: str


class HealthResponse(BaseModel):
    """Response model for service health check."""

    status: str
    engine: str
    model: str


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manages the lifecycle of the Aegis application.

    Initializes the heavy AegisAsync instance (loading NLP models) on startup
    and ensures proper cleanup on shutdown.
    """
    aegis = AegisAsync()
    # Enter async context to initialize resources (e.g. httpx client)
    async with aegis:
        app.state.aegis = aegis
        yield
    # Exit async context handles cleanup


app = FastAPI(lifespan=lifespan)


@app.post("/sanitize", response_model=SanitizeResponse)
async def sanitize(request: SanitizeRequest) -> SanitizeResponse:
    """Sanitizes the input text by redacting sensitive entities.

    Args:
        request: The sanitization request containing text and policy.

    Returns:
        The sanitized text and the de-identification map.

    Raises:
        HTTPException: 500 if sanitization fails (Fail Closed).
    """
    try:
        # Construct UserContext
        # Note: In a real deployment, this would come from a dependency extracting from JWT/headers.
        # WARNING: This insecure population from request body is for demonstration/harness purposes only.
        user_context = UserContext(
            sub=request.user_id,
            permissions=request.permissions,
            email="api@example.com",  # Dummy
            project_context="default",  # Dummy
        )

        text, deid_map = await app.state.aegis.sanitize(request.text, user_context, request.session_id, request.policy)
        return SanitizeResponse(text=text, map=deid_map)
    except Exception as e:
        # Fail Closed: Block traffic on error
        raise HTTPException(status_code=500, detail=f"Sanitization failed: {e}") from e


@app.post("/desanitize", response_model=DesanitizeResponse)
async def desanitize(request: DesanitizeRequest) -> DesanitizeResponse:
    """Re-identifies the input text if authorized.

    Args:
        request: The de-sanitization request.

    Returns:
        The re-identified text (or original tokenized text if unauthorized).

    Raises:
        HTTPException: 500 if de-sanitization fails.
    """
    try:
        user_context = UserContext(
            sub=request.user_id, permissions=request.permissions, email="api@example.com", project_context="default"
        )

        text = await app.state.aegis.desanitize(request.text, request.session_id, user_context)
        return DesanitizeResponse(text=text)
    except Exception as e:
        # Fail Closed
        raise HTTPException(status_code=500, detail=f"Desanitization failed: {e}") from e


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Checks the health of the Aegis service.

    Returns:
        The status of the service and loaded engines.

    Raises:
        HTTPException: 503 if the scanner is not initialized.
    """
    if hasattr(app.state.aegis.scanner, "analyzer") and app.state.aegis.scanner.analyzer:
        return HealthResponse(
            status="protected",
            engine="presidio",
            model="en_core_web_lg",
        )
    raise HTTPException(status_code=503, detail="Unhealthy: Scanner not initialized")
