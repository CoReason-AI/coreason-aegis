# coreason-aegis

[![License: Prosperity 3.0](https://img.shields.io/badge/License-Prosperity%203.0-blue)](https://github.com/CoReason-AI/coreason_aegis)
[![CI Status](https://github.com/CoReason-AI/coreason_aegis/actions/workflows/main.yml/badge.svg)](https://github.com/CoReason-AI/coreason_aegis/actions)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**The "Air Gap" / Privacy Shield for CoReason-AI.**

coreason-aegis is the bidirectional privacy filter that sits between the CoReason platform and the external world (LLMs, Logging, Search). It ensures that sensitive data (PII/PHI) is never leaked to external providers while preserving the logical structure needed for effective LLM reasoning.

## Core Philosophy

"The Model needs Logic, not Identity. What is not sent cannot be leaked."

1.  **Scan-Mask-Map-Reveal Loop:** Deterministic tokenization ensures consistency within a session.
2.  **Vault of Identity:** Mappings are stored ephemerally and encrypted at rest.
3.  **Fail Closed:** If the scanner fails, traffic is blocked.

## Features

*   **High-Speed Scanner:** Built on Microsoft Presidio, running locally (no external API calls for scanning).
    *   Detects standard entities: PERSON, EMAIL, PHONE, IP_ADDRESS, DATE.
    *   Detects custom Pharma entities: MRN, PROTOCOL_ID, LOT_NUMBER, GENE_SEQUENCE, CHEMICAL_CAS.
*   **Intelligent Masking:**
    *   **REPLACE:** `[PATIENT_A]` (Preserves context for reasoning).
    *   **MASK:** `[PERSON]` (Standard redaction).
    *   **SYNTHETIC:** `Jane Doe` (Realistic fake data for training).
    *   **HASH:** SHA256 (For analytics).
*   **Vault Manager:** secure, ephemeral storage of identity mappings with automatic expiration (TTL).
*   **Re-Identification:** Context-aware reversal of tokens to real values for authorized users only.
*   **Leak Prevention:** Aggressive detection and redaction of API Keys (e.g., `sk-...`).

## Installation

```bash
pip install coreason-aegis
```

*Note: Requires Python 3.12+*

## Usage

```python
from coreason_aegis.main import Aegis
from coreason_aegis.models import AegisPolicy

# Initialize the Aegis engine
aegis = Aegis()

# Session ID is crucial for consistent tokenization within a conversation
session_id = "session_123"

# Input text containing sensitive data
user_prompt = "Patient John Doe (MRN: 12345678) has a rash."

# 1. Sanitize (Scan & Mask)
# This prevents PII from leaving your secure perimeter.
sanitized_text, _ = aegis.sanitize(user_prompt, session_id)

print(f"Sanitized: {sanitized_text}")
# Output: "Patient [PATIENT_A] (MRN: [MRN_A]) has a rash."

# ... Send sanitized_text to LLM ...
llm_response = "For [PATIENT_A], considering the rash..."

# 2. Desanitize (Re-Identify)
# This restores the real data for the authorized user.
final_text = aegis.desanitize(llm_response, session_id, authorized=True)

print(f"Final: {final_text}")
# Output: "For John Doe, considering the rash..."
```

## Contributing

This project is part of the CoReason-AI ecosystem. Please see `AGENTS.md` for development guidelines.

## License

This software is proprietary and dual-licensed under the **Prosperity Public License 3.0**.
See [LICENSE](LICENSE) for details.
