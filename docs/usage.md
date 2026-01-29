# Usage

This guide provides examples on how to use `coreason-aegis` in your applications.

## Initialization

You can use `coreason-aegis` in both synchronous and asynchronous contexts. The library provides two main classes: `Aegis` (sync) and `AegisAsync` (async).

### Synchronous Usage

```python
from coreason_aegis.main import Aegis

# Initialize the synchronous facade
# This automatically manages the async event loop in the background.
aegis = Aegis()
```

### Asynchronous Usage

```python
from coreason_aegis.main import AegisAsync

# Initialize the async client
# Best used within an async context manager
async def main():
    async with AegisAsync() as aegis:
        # Use aegis methods here
        pass
```

## Creating User Context

All operations in `coreason-aegis` require a `UserContext` to ensure identity-aware protection and auditing.

```python
from coreason_identity.models import UserContext
from coreason_identity.types import SecretStr

# Create a context for the current user/session
context = UserContext(
    user_id=SecretStr("user_12345"),
    roles=["analyst"],
    metadata={"department": "security"}
)
```

## Sanitization (Scanning & Masking)

The `sanitize` method scans text for sensitive entities and replaces them with tokens.

```python
from coreason_aegis.models import AegisPolicy, RedactionMode

# Define an optional policy (or use default)
policy = AegisPolicy(
    entity_types=["PERSON", "EMAIL", "DATE_TIME"],
    mode=RedactionMode.REPLACE
)

user_prompt = "Patient John Doe (DOB: 12/01/1980) has a rash."
session_id = "session_abc_123"

# Synchronous call
sanitized_text, deid_map = aegis.sanitize(
    text=user_prompt,
    session_id=session_id,
    context=context,
    policy=policy
)

print(sanitized_text)
# Output: "Patient [PATIENT_A] (DOB: [DATE_B]) has a rash."
```

## Desanitization (Re-identification)

The `desanitize` method restores the original values from tokens, provided the user is authorized.

```python
llm_response = "For [PATIENT_A], considering the rash..."

# Synchronous call
final_text = aegis.desanitize(
    text=llm_response,
    session_id=session_id,
    context=context,
    authorized=True
)

print(final_text)
# Output: "For John Doe, considering the rash..."
```

## CLI Usage

The library also exposes CLI commands for quick testing:

```bash
# Scan text
python -c "from coreason_aegis.main import scan; scan('John Doe')"

# Mask text
python -c "from coreason_aegis.main import mask; mask('John Doe', 'sess_1')"

# Reidentify text (requires valid session/vault state, usually for testing within same process)
```
