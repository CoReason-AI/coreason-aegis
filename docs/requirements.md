# Requirements

This document lists the dependencies required to run `coreason-aegis`.

## Runtime Dependencies

These packages are required for the library to function:

*   **python**: `>=3.12, <3.14`
*   **loguru** (`^0.7.2`): Logging utility.
*   **presidio-analyzer** (`^2.2.360`): PII detection engine.
*   **presidio-anonymizer** (`^2.2.360`): PII anonymization engine.
*   **pydantic** (`^2.12.5`): Data validation and settings management.
*   **faker** (`^40.1.2`): Synthetic data generation.
*   **cachetools** (`^6.2.6`): Caching utilities for the Vault.
*   **coreason-identity** (`^0.4.2`): Identity and Context management models.
*   **anyio** (`^4.12.1`): Asynchronous compatibility layer.
*   **httpx** (`^0.28.1`): Async HTTP client.
*   **aiofiles** (`^25.1.0`): File support for asyncio.
*   **types-aiofiles** (`^25.1.0.20251011`): Type stubs for aiofiles.
*   **jaraco-context** (`^6.1.0`): Context management utilities.

## Development Dependencies

These packages are required for development and testing:

*   **pytest**: Testing framework.
*   **ruff**: Linter and formatter.
*   **pre-commit**: Git hook manager.
*   **pytest-cov**: Coverage reporting.
*   **mkdocs**: Documentation generator.
*   **mkdocs-material**: Material theme for MkDocs.
*   **pydantic-settings**: Settings management for Pydantic (used in Dev/Test).
*   **mypy**: Static type checker.
*   **types-cachetools**: Type stubs for cachetools.
*   **pytest-asyncio**: Async support for pytest.

## Installation

You can install dependencies using Poetry:

```bash
poetry install
```

Or via pip (using the generated requirements):

```bash
pip install -r requirements.txt
```
