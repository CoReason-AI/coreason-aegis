# The Architecture and Utility of coreason-aegis

### 1. The Philosophy (The Why)

In the era of Generative AI, the "firewall" concept has evolved. It is no longer enough to block ports; we must block concepts. `coreason-aegis` operates on the premise that large language models (LLMs) require **logic**, not **identity**, to reason effectively.

Traditional redaction methods (e.g., replacing "John Doe" with `[REDACTED]`) destroy the semantic relationships necessary for an LLM to follow a narrative. If "John Doe" appears five times in a clinical note, replacing him with a generic placeholder renders the note disjointed. The model loses the thread of continuity.

`coreason-aegis` solves this by implementing an "Air Gap" for identity. It treats PII (Personally Identifiable Information) not as data to be deleted, but as state to be managed. By transforming "John Doe" into `[PATIENT_A]` consistently within a session, we preserve the logical structure of the data while ensuring that the identity never leaves the secure perimeter. The "Vault" of identity remains local, ephemeral, and encrypted, ensuring that what is not sent cannot be leaked.

### 2. Under the Hood (The Dependencies & Logic)

The package is built on a lean, high-performance stack designed for the Scan-Mask-Map-Reveal loop:

*   **Microsoft Presidio (`presidio-analyzer`, `presidio-anonymizer`)**: This forms the bedrock of the scanning engine. Rather than reinventing Named Entity Recognition (NER), `coreason-aegis` leverages Presidio's battle-tested models to detect standard PII (names, emails, phones) and extends it with custom recognizers for domain-specific entities like Medical Record Numbers (MRN) and Pharma Lot Numbers.
*   **Faker (`faker`)**: Used for the "Synthetic" redaction mode. When a simple mask like `[PATIENT_A]` is too abstract for training contexts, `faker` allows the engine to generate realistic, deterministic surrogates (e.g., swapping "John Doe" with "Michael Smith") that preserve the statistical properties of the text without revealing real data.
*   **Cachetools (`cachetools`)**: The "Vault" manager relies on `TTLCache` to handle the ephemeral mapping storage. This ensures that the lookup tables (mapping `[PATIENT_A]` back to "John Doe") have a strictly enforced Time-To-Live, automatically evicting sensitive keys when a session expires.
*   **Pydantic (`pydantic`)**: Enforces strict schema validation for the `AegisPolicy` and `DeIdentificationMap`, ensuring that the privacy rules are type-safe and validated at runtime.

The core logic is a bidirectional pipeline. In the **outbound** direction (Sanitize), the `Scanner` identifies entities, and the `MaskingEngine` replaces them with deterministic tokens, storing the mapping in the local Vault. In the **inbound** direction (Desanitize), the `ReIdentifier` intercepts the LLM's response and—if the user is authorized—rehydrates the tokens back into their original values using the stored map.

### 3. In Practice (The How)

Using `coreason-aegis` is designed to be seamless for the developer, encapsulating the complexity of NER and token management within a simple interface.

**The Happy Path: Safe Consultation**

Here, we sanitize a prompt before sending it to an LLM, and then re-identify the response for the authorized user.

```python
from coreason_aegis.main import Aegis

# Initialize the privacy filter (loads NER models)
aegis = Aegis()

session_id = "consultation_123"
sensitive_prompt = "Patient John Doe (DOB: 12/01/1980) is showing severe symptoms."

# 1. Sanitize the input
# 'masked_text' becomes: "Patient [PATIENT_A] (DOB: [DATE_A]) is showing severe symptoms."
# The mapping {"[PATIENT_A]": "John Doe", ...} is stored in the vault.
masked_text, deid_map = aegis.sanitize(sensitive_prompt, session_id=session_id)

# ... (Send masked_text to LLM, get response) ...
llm_response = "I recommend checking [PATIENT_A] for allergies given the history on [DATE_A]."

# 2. Desanitize the response
# The tokens are swapped back to real values only for this authorized session.
final_output = aegis.desanitize(llm_response, session_id=session_id, authorized=True)

print(final_output)
# Output: "I recommend checking John Doe for allergies given the history on 12/01/1980."
```

**Custom Policies**

You can also define custom policies for different use cases, such as using synthetic data generation for creating safe training datasets.

```python
from coreason_aegis.models import AegisPolicy, RedactionMode

# Define a policy that replaces real names with fake ones (Synthetic mode)
training_policy = AegisPolicy(
    mode=RedactionMode.SYNTHETIC,
    confidence_score=0.7,
    entity_types=["PERSON", "EMAIL_ADDRESS"]
)

raw_data = "Contact John Smith at john.smith@example.com"

# The engine will deterministically generate fake data based on the input hash
safe_data, _ = aegis.sanitize(raw_data, session_id="training_job_001", policy=training_policy)

print(safe_data)
# Output might be: "Contact Michael Brown at jennifer.davis@fake-mail.org"
```
