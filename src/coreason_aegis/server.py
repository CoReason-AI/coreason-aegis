# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_aegis

"""FastAPI server for Aegis Privacy Firewall.

This module exposes the privacy filter capabilities as a microservice,
intended to run as a sidecar or gateway service.
"""

from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from coreason_identity.models import UserContext
from coreason_identity.types import SecretStr

from coreason_aegis.main import AegisAsync
from coreason_aegis.models import AegisPolicy, DeIdentificationMap
from coreason_aegis.utils.logger import logger


class Settings(BaseSettings):
    """Server configuration."""

    model_config = SettingsConfigDict(env_prefix="AEGIS_")

    VAULT_TTL: int = 3600
    HOST: str = "0.0.0.0"
    PORT: int = 8000


settings = Settings()


class SanitizeRequest(BaseModel):
    """Request model for sanitization."""

    text: str
    session_id: str
    policy: Optional[AegisPolicy] = None


class SanitizeResponse(BaseModel):
    """Response model for sanitization."""

    text: str
    deid_map: DeIdentificationMap


class DesanitizeRequest(BaseModel):
    """Request model for desanitization."""

    text: str
    session_id: str
    authorized: bool


class DesanitizeResponse(BaseModel):
    """Response model for desanitization."""

    text: str


def get_context(session_id: str) -> UserContext:
    """Creates a UserContext for the request based on session_id.

    Since the API does not currently accept explicit user identity,
    we derive it from the session or use a generic API user role.
    """
    # Using session_id as part of user_id to allow tracking in VaultManager logs,
    # but strictly this should be the authenticated user's ID.
    return UserContext(
        user_id=SecretStr(f"api-user-{session_id}"),
        roles=["api-user"],
        metadata={"source": "aegis-server"},
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    """Lifespan context manager to initialize AegisAsync."""
    logger.info(f"Initializing AegisAsync with Vault TTL {settings.VAULT_TTL}s")
    async with AegisAsync(vault_ttl=settings.VAULT_TTL) as aegis:
        app.state.aegis = aegis
        yield
    logger.info("AegisAsync shutdown complete")


app = FastAPI(lifespan=lifespan, title="Aegis Privacy Firewall")


@app.post("/sanitize", response_model=SanitizeResponse)
async def sanitize(request: SanitizeRequest) -> SanitizeResponse:
    """Sanitizes text, returning masked text and de-identification map."""
    try:
        context = get_context(request.session_id)
        # app.state.aegis is typed as Any by FastAPI
        masked_text, deid_map = await app.state.aegis.sanitize(
            request.text, request.session_id, context, request.policy
        )
        return SanitizeResponse(text=masked_text, deid_map=deid_map)
    except Exception as e:
        logger.error(f"Sanitize request failed: {e}")
        # Fail Closed
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error",
        ) from e


@app.post("/desanitize", response_model=DesanitizeResponse)
async def desanitize(request: DesanitizeRequest) -> DesanitizeResponse:
    """Desanitizes text using the stored map for the session."""
    try:
        context = get_context(request.session_id)
        text = await app.state.aegis.desanitize(
            request.text, request.session_id, context, request.authorized
        )
        return DesanitizeResponse(text=text)
    except Exception as e:
        logger.error(f"Desanitize request failed: {e}")
        # Fail Closed
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error",
        ) from e


@app.get("/health")
async def health() -> Dict[str, str]:
    """Health check endpoint."""
    if not hasattr(app.state, "aegis"):
        raise HTTPException(status_code=503, detail="Aegis not initialized")

    try:
        # Check if internal components are ready
        if app.state.aegis.scanner.analyzer is None:
            raise RuntimeError("Analyzer not initialized")
    except Exception:
        raise HTTPException(status_code=503, detail="Unhealthy")

    return {"status": "protected", "engine": "presidio", "model": "en_core_web_lg"}
