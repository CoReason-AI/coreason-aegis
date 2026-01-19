# coreason-aegis

A bidirectional privacy filter that sits between the CoReason platform and the external world.

[![License](https://img.shields.io/badge/license-Prosperity%203.0-blue)](https://github.com/CoReason-AI/coreason_aegis)
[![CI](https://github.com/CoReason-AI/coreason_aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/CoReason-AI/coreason_aegis/actions/workflows/ci.yml)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Docs](https://img.shields.io/badge/docs-requirements-green)](docs/product_requirements.md)

**coreason-aegis** implements a **"Tokenize & Detokenize"** strategy. Before any text leaves the secure perimeter (e.g., to OpenAI), Aegis scans it for sensitive entities (Names, MRNs, SSNs, Emails) and replaces them with consistent, context-aware tokens. When the LLM responds using these tokens, Aegis intercepts the message and re-injects the real data *only* for the authorized user's eyes.

## Features

*   **Scan-Mask-Map-Reveal Loop:** Deterministic tokenization ensures LLM reasoning consistency.
*   **The "Vault" of Identity:** Ephemeral, encrypted mapping tables.
*   **Context Preservation:** Uses tokens like `[PATIENT_A]` instead of `[REDACTED]`.
*   **Custom Recognizers:** Supports custom entities like MRNs, Protocol IDs, and Lot Numbers.

For detailed requirements, see [Product Requirements](docs/product_requirements.md).

## Installation

```bash
pip install coreason-aegis
```

Or using Poetry:

```bash
poetry add coreason-aegis
```

*Note: You may need to download the Spacy model manually if not handled by the package installer:*

```bash
python -m spacy download en_core_web_lg
```

## Usage

```python
from coreason_aegis.main import Aegis
from coreason_aegis.models import AegisPolicy, RedactionMode

# Initialize Aegis
aegis = Aegis()

# Define a policy
policy = AegisPolicy(
    allow_list=["Tylenol"],
    entity_types=["PERSON", "EMAIL", "PHONE_NUMBER"],
    mode=RedactionMode.REPLACE,
    confidence_score=0.7
)

# Sanitize user prompt
user_prompt = "Patient John Doe (DOB: 12/01/1980) has a rash."
session_id = "session_123"
sanitized_prompt, mapping_id = aegis.sanitize(user_prompt, policy, session_id)

print(f"Sanitized: {sanitized_prompt}")
# Output: "Patient [PATIENT_A] (DOB: [DATE_B]) has a rash."

# ... Send to LLM ...
llm_response = "For [PATIENT_A], considering the rash..."

# Desanitize LLM response
final_response = aegis.desanitize(llm_response, session_id, mapping_id)

print(f"Final: {final_response}")
# Output: "For John Doe, considering the rash..."
```
