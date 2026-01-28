import sys
import types
from typing import Any, Dict, Generator, List
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

# --- Mock coreason_identity ---

class SecretStr:
    def __init__(self, value: str):
        self._value = value

    def get_secret_value(self) -> str:
        return self._value

    def __repr__(self):
        return "SecretStr('**********')"

class UserContext(BaseModel):
    user_id: Any  # annotated as SecretStr in usage
    roles: List[str]
    metadata: Dict[str, Any]

    class Config:
        arbitrary_types_allowed = True

# Mock the modules before any test imports them

# Create mock modules
mock_types = types.ModuleType("coreason_identity.types")
mock_types.SecretStr = SecretStr # type: ignore

mock_models = types.ModuleType("coreason_identity.models")
mock_models.UserContext = UserContext # type: ignore

# Patch sys.modules
# We must do this before importing coreason_aegis modules in tests
sys.modules["coreason_identity.types"] = mock_types
sys.modules["coreason_identity.models"] = mock_models

# Also patch the root package if needed, but usually specific submodules are enough
# if imports are from submodules.

@pytest.fixture
def mock_context() -> UserContext:
    return UserContext(
        user_id=SecretStr("test-user"),
        roles=["tester"],
        metadata={"source": "test"}
    )

@pytest.fixture
def mock_scanner_engine() -> Generator[MagicMock, None, None]:
    # Mock the internal AnalyzerEngine to avoid loading models
    # Patch the class so that if instantiated, it returns a mock.
    with patch("coreason_aegis.scanner.AnalyzerEngine") as mock:
        # Crucial: Ensure the module-level cache is None so that Scanner
        # calls AnalyzerEngine() (hitting our mock) instead of using a cached real instance.
        with patch("coreason_aegis.scanner._ANALYZER_ENGINE_CACHE", None):
            yield mock
