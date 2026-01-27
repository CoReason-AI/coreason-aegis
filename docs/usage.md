# Usage Guide

coreason-aegis can be used in two modes:
1.  **Library Mode:** Integrated directly into your Python application.
2.  **Server Mode:** Deployed as a standalone Privacy Microservice ("The Shield").

## 1. Library Mode

Use this mode if you are building a Python application (like `coreason-cortex`) that needs direct access to the Aegis classes.

### Installation

```bash
pip install coreason-aegis
python -m spacy download en_core_web_lg
```

### Example

```python
from coreason_aegis.main import Aegis
from coreason_aegis.models import AegisPolicy, RedactionMode

# Initialize Aegis (this loads the NLP models, so do it once)
aegis = Aegis()

# Define a policy (optional, defaults are usually sufficient)
policy = AegisPolicy(
    allow_list=["Tylenol"],
    entity_types=["PERSON", "EMAIL", "PHONE_NUMBER", "SECRET_KEY"],
    mode=RedactionMode.REPLACE,
    confidence_score=0.4
)

# Sanitize user prompt
user_prompt = "Patient John Doe (DOB: 12/01/1980) has a rash."
session_id = "session_123"

# Returns the redacted text and the mapping object
sanitized_prompt, deid_map = aegis.sanitize(user_prompt, session_id, policy)

print(f"Sanitized: {sanitized_prompt}")
# Output: "Patient [PATIENT_A] (DOB: [DATE_B]) has a rash."

# ... Send to LLM ...
llm_response = "For [PATIENT_A], considering the rash..."

# Desanitize LLM response
# The mapping is stored in the Vault (in-memory by default)
final_response = aegis.desanitize(llm_response, session_id, authorized=True)

print(f"Final: {final_response}")
# Output: "For John Doe, considering the rash..."
```

---

## 2. Server Mode (Privacy Microservice)

Use this mode to deploy Aegis as a dedicated infrastructure component. This effectively "air gaps" your application from the external world.

### Installation & Startup

**Using Docker (Recommended):**

```bash
# Build the image
docker build -t coreason-aegis:latest .

# Run the container (exposing port 8000)
docker run -p 8000:8000 coreason-aegis:latest
```

**Running Locally:**

```bash
# Install dependencies
pip install coreason-aegis[server]
# Note: You need to install 'fastapi' and 'uvicorn' manually if using pip directly without the extra
# pip install fastapi uvicorn[standard] pydantic-settings

# Start the server
uvicorn coreason_aegis.server:app --host 0.0.0.0 --port 8000
```

### API Endpoints

The server exposes the following endpoints.

#### POST /sanitize

Scans text and returns a redacted version along with the de-identification map.

**Request:**
```json
{
  "text": "My email is john.doe@example.com",
  "session_id": "session_abc",
  "policy": {
    "mode": "REPLACE",
    "entity_types": ["EMAIL_ADDRESS"]
  }
}
```

**Response:**
```json
{
  "text": "My email is [EMAIL_A]",
  "map": {
    "session_id": "session_abc",
    "mappings": {
      "[EMAIL_A]": "john.doe@example.com"
    },
    ...
  }
}
```

**Example (curl):**
```bash
curl -X POST "http://localhost:8000/sanitize" \
     -H "Content-Type: application/json" \
     -d '{"text": "Call me at 555-0199", "session_id": "demo"}'
```

#### POST /desanitize

Re-identifies tokens in the text using the stored mapping.

**Request:**
```json
{
  "text": "Please contact [PHONE_A].",
  "session_id": "demo",
  "authorized": true
}
```

**Response:**
```json
{
  "text": "Please contact 555-0199."
}
```

**Example (curl):**
```bash
curl -X POST "http://localhost:8000/desanitize" \
     -H "Content-Type: application/json" \
     -d '{"text": "Please contact [PHONE_A].", "session_id": "demo", "authorized": true}'
```

#### GET /health

Checks if the service and NLP models are loaded.

**Response:**
```json
{
  "status": "protected",
  "engine": "presidio",
  "model": "en_core_web_lg"
}
```

### Architecture Notes

*   **Lifespan Management:** The server initializes the heavy NLP models once on startup, ensuring sub-second response times for requests.
*   **Fail-Closed:** If scanning fails for any reason, the server returns a 500 Error, blocking the traffic to prevent accidental data leakage.
*   **Vault:** Currently uses an in-memory TTL cache. In a multi-replica deployment, sticky sessions or a distributed Redis vault (future roadmap) would be required.
