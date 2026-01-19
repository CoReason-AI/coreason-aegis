# Product Requirements Document: coreason-aegis

**Domain:** Data Privacy, PII/PHI Redaction, & Anonymization
**Architectural Role:** The "Air Gap" / Privacy Shield
**Core Philosophy:** "The Model needs Logic, not Identity. What is not sent cannot be leaked."
**Dependencies:** coreason-vault (Encryption), coreason-veritas (Audit), Microsoft Presidio (NER Engine)

---

## 1. Executive Summary

coreason-aegis is the bidirectional privacy filter that sits between the CoReason platform and the external world (LLMs, Logging, Search).

It implements a **"Tokenize & Detokenize"** strategy. Before any text leaves the secure perimeter (e.g., to OpenAI), Aegis scans it for sensitive entities (Names, MRNs, SSNs, Emails) and replaces them with consistent, context-aware tokens (e.g., `[PATIENT_A]`). When the LLM responds using these tokens, Aegis intercepts the message and re-injects the real data *only* for the authorized user's eyes.

## 2. Functional Philosophy

The agent must implement the **Scan-Mask-Map-Reveal Loop**:

1.  **Deterministic Tokenization:** Random masking breaks reasoning. If "John Doe" is mentioned 5 times, it must always map to `[PATIENT_A]` so the LLM understands it is the same person.
2.  **The "Vault" of Identity:** The mapping table (`[PATIENT_A]` = "John Doe") is the most sensitive asset in the system. It is stored ephemerally, encrypted at rest, and never logged to coreason-veritas.
3.  **Context Preservation:** We do not replace "John Doe" with `[REDACTED]`. We replace it with `[NAME]` or `[PATIENT]`. This hints to the LLM *what* the entity is, preserving grammatical and logical structure.
4.  **Right to be Forgotten:** Deleting the mapping key effectively destroys the data. Even if the vector database contains the token `[PATIENT_A]`, without the key, it is mathematically anonymous.

---

## 3. Core Functional Requirements (Component Level)

### 3.1 The Scanner (The Eyes)

**Concept:** A high-speed Named Entity Recognition (NER) engine running locally.

*   **Technology:** Built on top of **Microsoft Presidio** or **Spacy** (Transformers). It must *not* use an external LLM for scanning (Infinite Loop/Leakage risk).
*   **Entity Types:**
    *   **Standard:** PERSON, EMAIL, PHONE, IP_ADDRESS, DATE.
    *   **Custom (Pharma):** MRN (Medical Record Number), PROTOCOL_ID, LOT_NUMBER.
*   **Confidence Thresholds:** Configurable (e.g., "If 80% sure it's a name, redact it").

### 3.2 The Masking Engine (The Shield)

**Concept:** Replaces detected entities with tokens.

*   **Consistency Scope:**
    *   **Session Scope:** "John" is `[PATIENT_A]` for the duration of this chat.
    *   **Global Scope:** "John" is `[PATIENT_882]` forever (used for coreason-archive storage).
*   **Faking Strategy:**
    *   **Replace:** `[PATIENT_A]` (Best for reasoning).
    *   **Hash:** SHA256("John") (Best for analytics).
    *   **Synthesize:** Replace "John" with "Michael" (Best for training data, hard to re-identify).

### 3.3 The Vault Manager (The Memory)

**Concept:** Manages the ephemeral Look-up Table (LUT).

*   **Storage:** Encrypted Redis or In-Memory Dict.
*   **Structure:** `{ "session_123": { "[PATIENT_A]": "John Doe", "[DR_B]": "Dr. Smith" } }`.
*   **TTL:** Mappings expire when the session ends (unless persisting to Archive).

### 3.4 The Re-Identifier (The Reveal)

**Concept:** The outbound filter for User UX.

*   **Trigger:** Intercepts the LLM response *before* it hits the UI.
*   **Action:** Scans for tokens (`[PATIENT_A]`). Lookups the real value. Substitutes it back.
*   **Safety Check:** Checks coreason-identity. Does this user have the "View PII" permission?
    *   *Yes:* Show "John Doe."
    *   *No:* Leave as `[PATIENT_A]`.

---

## 4. Integration Requirements (The Ecosystem)

*   **coreason-cortex (Runtime):**
    *   Cortex calls `aegis.sanitize(user_prompt)` before sending to OpenAI.
    *   Cortex calls `aegis.desanitize(llm_response)` before returning to User.
*   **coreason-refinery (Ingestion):**
    *   Refinery uses Aegis to scrub documents *permanently* before embedding them into the Vector DB. (One-way redaction).
*   **coreason-veritas (Logging):**
    *   Veritas logs the *sanitized* version of the prompt. The PII never enters the log stream.

---

## 5. User Stories (Behavioral Expectations)

### Story A: The "Safe Consultation" (Runtime Protection)

**User Prompt:** "Patient John Doe (DOB: 12/01/1980) has a rash."
**Aegis Action:**

1.  Detects "John Doe" -> Maps to `[PATIENT_1]`.
2.  Detects "12/01/1980" -> Maps to `[DATE_1]`.

**LLM Input:** "Patient [PATIENT_1] ([DATE_1]) has a rash."
**LLM Output:** "For [PATIENT_1], considering the rash..."
**Aegis Reverse:** Replaces `[PATIENT_1]` with "John Doe".
**User Sees:** "For John Doe, considering the rash..."
**OpenAI Sees:** Only tokens.

### Story B: The "Leak Prevention" (Aggressive Defense)

**User Prompt:** "Here is the API Key: sk-12345..."
**Aegis Action:** Detects API_KEY pattern.
**Action:** Redacts to `[SECRET_KEY]`.
**Alert:** Logs a warning to coreason-veritas (without the key) regarding "Credential Exposure Attempt."

### Story C: The "Vector Search" (Blind Retrieval)

**Context:** Archive contains processed notes.
**Query:** User asks about "John Doe."
**Aegis:** Converts "John Doe" to `[PATIENT_1]` before querying the Vector DB.
**Search:** Vector DB looks for `[PATIENT_1]`.
**Result:** Finds records. The DB never held the real name, but the search works because the mapping is consistent.

---

## 6. Data Schema

### AegisPolicy

```python
class RedactionMode(str, Enum):
    MASK = "MASK"           # [PERSON]
    REPLACE = "REPLACE"     # [PATIENT_A]
    SYNTHETIC = "SYNTHETIC" # "Jane Doe"

class AegisPolicy(BaseModel):
    allow_list: List[str]   # Terms to NEVER redact (e.g. "Tylenol")
    entity_types: List[str] # ["PERSON", "US_SSN", "UK_NHS_NUMBER"]
    mode: RedactionMode
    confidence_score: float = 0.85
```

### DeIdentificationMap (Internal/Encrypted)

```python
class DeIdentificationMap(BaseModel):
    session_id: str
    mappings: Dict[str, str] # { "[TOKEN]": "REAL_VALUE" }
    created_at: datetime
    expires_at: datetime
```

---

## 7. Implementation Directives

1.  **Use Microsoft Presidio:** It is the standard for PII engineering. Do not use regex unless absolutely necessary for custom custom formats (like internal Lot Numbers).
2.  **Singleton Pattern:** The PresidioAnalyzer engine is heavy to load. Load it once on startup, not per request.
3.  **Fail-Safe:** If the Aegis service crashes or fails to scan, **BLOCK** the traffic. Do not "Fail Open" (allow unscaned traffic). Fail Closed.
4.  **Custom Recognizers:** You must implement a custom recognizer for Gene Sequences or Chemical Formulas if they need protection, or conversely, add them to the Allow List so they aren't mistaken for random gibberish/names.
