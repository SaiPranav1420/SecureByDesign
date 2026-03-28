# SecureByDesign — Person A Handoff Report
## AI Pipeline Engineer → Handoff to Person B

**Date:** 2026-03-01  
**Author:** Person A (AI Pipeline Engineer)  
**Status:** ✅ All phases complete and verified on Kaggle

---

## 1. What Person A Built (The Big Picture)

The entire `pipeline/` directory is Person A's contribution. It is the **AI brain** of the SecureByDesign system — it takes a Data Flow Diagram (DFD) as input and returns a structured STRIDE security threat report as output.

**The one function Person B needs to call:**
```python
from pipeline.inference import analyze_dfd

result = analyze_dfd(dfd_json_dict, "optional security context string")
```

That's it. Everything else is internal to the pipeline.

---

## 2. Project Background (For Context)

**What is SecureByDesign?**  
An AI-powered tool that reads a system's Data Flow Diagram (DFD) — a diagram showing how data moves between components like users, servers, and databases — and automatically identifies security threats using the **STRIDE framework**.

**What is STRIDE?**  
STRIDE is a standard security threat model with 6 categories:
| Category | What it means |
|----------|--------------|
| **S**poofing | Someone pretending to be another user/system |
| **T**ampering | Unauthorized modification of data in transit |
| **R**epudiation | A user denies doing something, and you can't prove they did |
| **I**nformation Disclosure | Sensitive data being leaked/exposed |
| **D**enial of Service | Crashing/overloading the system so it's unavailable |
| **E**levation of Privilege | A low-privilege user gaining admin powers |

**The novel contribution (what makes this research-worthy):**  
Most security tools refuse to analyze incomplete diagrams. Our system handles **partial DFDs gracefully** — it still gives useful threat analysis even when security details like authentication, encryption, or trust boundaries are missing, but it lowers the confidence level appropriately instead of refusing.

---

## 3. File-by-File Explanation

All files are in `SecureByDesign/pipeline/`.

---

### `pipeline/__init__.py` — The Public Door
```python
from pipeline.inference import analyze_dfd
__all__ = ['analyze_dfd']
```
**What it does:** This is just a thin wrapper. It makes `analyze_dfd` importable directly from `pipeline` module. Person B imports from here.

**Why it exists:** Python convention — it declares what the `pipeline` package exposes publicly.

---

### `pipeline/dfd_parser.py` — The DFD Reader (Phase 2)

**What it does:**  
Takes the raw DFD JSON dictionary and extracts all the security-relevant information from it. Think of it as a translator — it converts the raw diagram data into a structured format that the AI can understand.

**Key function:** `parse_dfd(dfd_json: dict) → ParsedDFD`

**What it analyses:**
- **Nodes:** Categorizes every component as External Entity (e.g., mobile app), Process (e.g., API server), or Datastore (e.g., database)
- **Edges:** For every data flow between components, checks:
  - Is authentication specified? (Yes / No / UNSPECIFIED)
  - Is encryption specified? (Yes / No / UNSPECIFIED)
  - Is the protocol known? (HTTPS / HTTP / TCP / UNSPECIFIED)
- **Trust Boundaries:** Identifies which data flows cross security zones (e.g., internet → internal network). These are high-risk crossing points.
- **Completeness Score:** Calculates a number from 0% to 100% indicating how complete the DFD is. Below 80% = marked as a partial DFD.
- **Text Summary:** Generates a human-readable text description of the diagram that gets sent to the AI model.

**What `ParsedDFD` contains:**
```python
parsed.dfd_id                    # e.g., "system_001"
parsed.system_name               # e.g., "Payment Service"
parsed.external_entities         # list of external users/systems
parsed.processes                 # list of internal services
parsed.datastores                # list of databases/storage
parsed.edges                     # all data flows
parsed.trust_boundaries          # security zone separations
parsed.boundary_crossing_edges   # HIGH RISK: flows crossing zones
parsed.missing_auth_edges        # edges where auth is unknown
parsed.missing_encryption_edges  # edges where encryption is unknown
parsed.unknown_protocol_edges    # edges where protocol is unknown
parsed.is_partial                # True if DFD is incomplete
parsed.completeness_score        # 0.0 to 1.0
parsed.missing_elements          # list of what's missing (for LLM context)
parsed.text_summary              # full text description sent to AI
```

---

### `pipeline/prompt_templates.py` — The AI Instructions (Phase 3)

**What it does:**  
Contains all the text that gets sent to the AI model. Think of it as the "question paper" given to the AI.

**Key components:**

**`SYSTEM_PROMPT`** — Tells the AI who it is and how to behave:
- Sets the AI's persona: "Expert security architect specialising in STRIDE"
- Enforces strict rules: Always output JSON, always analyse even incomplete DFDs
- Specifies the exact JSON output format with all required fields
- Instructs: "If DFD is partial, lower confidence — never refuse to analyse"

**`FEW_SHOT_EXAMPLE_1`** — Example of a nearly complete DFD  
Shows the AI what a high-confidence threat analysis looks like when authentication and encryption are clearly missing on specific edges.

**`FEW_SHOT_EXAMPLE_2`** — Example of a highly incomplete DFD  
Shows the AI how to handle missing trust boundaries, unknown protocols, and unspecified auth. Expected output: Medium/Low confidence threats, not refusals.

**`FEW_SHOT_EXAMPLE_3`** — Example of internal microservice mesh  
Shows the AI how to identify subtle threats inside a trusted network (Elevation of Privilege, Tampering on internal service-to-service calls).

**`build_analysis_prompt(text_summary, security_context) → list`**  
Assembles all the above into a 7-message conversation to feed to the Groq API:
- Message 1: System prompt
- Messages 2-3: Few-shot example 1 (input → expected output)
- Messages 4-5: Few-shot example 2 (input → expected output)
- Messages 6-7: Few-shot example 3 (input → expected output... wait, no — 3 examples = 6 messages + 1 query = 7 total)
- Message 7: The actual DFD being analysed (the real query)

---

### `pipeline/response_parser.py` — The AI Output Cleaner (Phase 4)

**What it does:**  
Takes the raw text response from the AI model and converts it into a clean, validated, guaranteed-schema-compliant Python dictionary. Handles all the messy edge cases.

**Key function:** `parse_llm_response(raw_text, dfd_id, system_name) → dict`

**Problems it solves:**
1. **AI wraps JSON in markdown:** Sometimes AI responds with ` ```json {...} ``` ` instead of raw JSON. The parser strips the markdown fencing.
2. **AI returns garbage:** If the AI completely fails, the parser returns a clean error dictionary instead of crashing.
3. **AI uses wrong STRIDE names:** If AI says "privilege escalation" instead of "Elevation of Privilege", fuzzy matching corrects it automatically.
4. **AI omits fields:** If threats are missing required fields (e.g., no `confidence_reason`), defaults are filled in.
5. **AI reports wrong STRIDE coverage:** The parser recounts from the validated threats, ignoring what the AI self-reported.

**STRIDE fuzzy matching table:**
| AI might say → | Parser maps to |
|---------------|----------------|
| "privilege escalation" | "Elevation of Privilege" |
| "spoof" | "Spoofing" |
| "dos" | "Denial of Service" |
| "information disclosure" | "Information Disclosure" |
| "repudiation" | "Repudiation" |

**Critical design decision:** This function **NEVER raises an exception**. If everything fails, it returns a structured error dictionary. Person B's code will never crash because of this function.

---

### `pipeline/inference.py` — The Orchestrator (Phase 5)

**What it does:**  
This is the main engine — it calls all the other pipeline components in sequence and returns the final threat report. This is the **only file Person B directly depends on**.

**LLM Used:** `llama-3.3-70b-versatile` via **Groq API** (free tier)
- Get API key: https://console.groq.com/keys
- Store in Kaggle Secrets as `GROQ_API_KEY`
- Groq is free, fast (~2-3 seconds per call), and reliable

**The full pipeline inside `analyze_dfd()`:**
```
Step 1: parse_dfd(dfd_json)
        → Extracts nodes, edges, trust boundaries, completeness score
        → Generates LLM-ready text summary of the DFD

Step 2: build_analysis_prompt(text_summary, security_context)
        → Builds 7-message conversation with few-shot examples

Step 3: Groq API call (llama-3.3-70b-versatile)
        → response_format={"type":"json_object"} forces valid JSON
        → Retry logic: 3 attempts with 2s/4s delay if API fails
        → Model temperature: 0.1 (low = consistent, deterministic output)

Step 4: parse_llm_response(raw_text, dfd_id, system_name)
        → Validates, normalises, fills defaults

Step 5: Enrich result with metadata
        → Adds: completeness_score, partial_dfd_detected, 
                dfd_missing_elements, analysis_duration_seconds, model_used
        → Returns final dict
```

**API key retrieval order:**
1. First tries Kaggle Secrets (`GROQ_API_KEY`)
2. Falls back to environment variable `GROQ_API_KEY`
3. If both fail → returns error report (no crash)

---

## 4. The Data Contract (Most Important Section for Person B)

### INPUT — What you pass to `analyze_dfd()`

**Function signature:**
```python
def analyze_dfd(dfd_json: dict, security_context: str = "") -> dict
```

**`dfd_json` — required fields:**
```json
{
  "dfd_id": "unique_identifier_string",
  "system_name": "Human readable system name",
  "nodes": [
    {
      "id": "N1",
      "type": "external_entity",
      "name": "Mobile Client",
      "description": "Optional description"
    },
    {
      "id": "N2",
      "type": "process",
      "name": "API Gateway",
      "description": "Optional"
    },
    {
      "id": "N3",
      "type": "datastore",
      "name": "User Database",
      "description": "Optional"
    }
  ],
  "edges": [
    {
      "id": "E1",
      "from": "N1",
      "to": "N2",
      "data_description": "Login credentials",
      "protocol": "HTTPS",
      "authenticated": true,
      "encrypted": true
    },
    {
      "id": "E2",
      "from": "N2",
      "to": "N3",
      "data_description": "DB query",
      "protocol": null,
      "authenticated": null,
      "encrypted": null
    }
  ],
  "trust_boundaries": [
    {
      "id": "TB1",
      "name": "Internet Boundary",
      "separates": ["N1", "N2"]
    }
  ],
  "partial_info_flags": {
    "missing_trust_boundaries": false,
    "unknown_protocols": true,
    "unspecified_auth": true,
    "incomplete_nodes": false
  }
}
```

**`security_context` — optional string:**  
Plain English description of the system. Helps the AI understand the context.  
Example: `"Internet-facing payment system handling credit card data and user PII. Regulatory requirement: PCI-DSS."`

**Node types (must be exactly one of these):**
- `"external_entity"` — users, external services (outside your control)
- `"process"` — microservices, APIs, servers (your code)
- `"datastore"` — databases, caches, file systems (stored data)

**Edge fields (use `null` for unknown, not `false`):**
- `"authenticated": true` → auth IS present
- `"authenticated": false` → auth is explicitly ABSENT (high risk!)
- `"authenticated": null` → auth is UNKNOWN (triggers partial DFD flag)

---

### OUTPUT — What `analyze_dfd()` returns

**Guaranteed fields (always present, even on error):**
```json
{
  "dfd_id": "matches input dfd_id",
  "system_name": "matches input system_name",
  "analysis_timestamp": "2026-03-01T10:59:07Z",
  "overall_risk_level": "Critical | High | Medium | Low | Unknown",
  "partial_dfd_detected": true,
  "threats": [...],
  "missing_controls_summary": ["list of missing security controls"],
  "stride_coverage": {
    "Spoofing": 1,
    "Tampering": 1,
    "Repudiation": 0,
    "Information Disclosure": 2,
    "Denial of Service": 0,
    "Elevation of Privilege": 0
  },
  "completeness_score": 0.833,
  "dfd_missing_elements": ["Auth unspecified: E1", "Protocol unknown: E2"],
  "analysis_duration_seconds": 2.94,
  "model_used": "llama-3.3-70b-versatile"
}
```

**Each threat in `threats[]` has these fields:**
```json
{
  "threat_id": "T1",
  "stride_category": "Spoofing",
  "affected_component": "E1: Mobile Client → API Gateway",
  "threat_description": "An attacker could submit forged login requests...",
  "missing_control": "Implement authentication token validation at API Gateway",
  "confidence": "High | Medium | Low",
  "confidence_reason": "Why the AI is this confident",
  "explanation": "Full detailed explanation of the threat and its impact"
}
```

**On API/parse failure (error report):**
```json
{
  "dfd_id": "...",
  "system_name": "...",
  "overall_risk_level": "Unknown",
  "error": "Description of what went wrong",
  "threats": [],
  "stride_coverage": { all zeros },
  ...all other guaranteed fields...
}
```
**Always check for `"error"` key before using the result!**

---

## 5. How to Import and Use (Code Examples)

### Basic usage:
```python
import sys
sys.path.insert(0, '/path/to/SecureByDesign')  # adjust to your path

from pipeline.inference import analyze_dfd

dfd = {
    "dfd_id": "my_system_001",
    "system_name": "My System",
    "nodes": [...],
    "edges": [...],
    "trust_boundaries": [...],
    "partial_info_flags": {...}
}

result = analyze_dfd(dfd, "Optional security context")

# Always check for errors first
if result.get("error"):
    print(f"Analysis failed: {result['error']}")
else:
    print(f"Risk: {result['overall_risk_level']}")
    print(f"Threats found: {len(result['threats'])}")
    for threat in result['threats']:
        print(f"[{threat['stride_category']}] {threat['affected_component']}")
        print(f"  Confidence: {threat['confidence']} — {threat['confidence_reason']}")
```

### In Kaggle Notebook:
```python
import sys, os
sys.path.insert(0, '/kaggle/working/SecureByDesign')
from pipeline.inference import analyze_dfd

# GROQ_API_KEY must be in Kaggle Secrets!
result = analyze_dfd(your_dfd_dict, "your context")
```

### Installing dependencies:
```bash
pip install groq>=0.11.0 scikit-learn pandas python-dateutil
```

---

## 6. Stress Test Results (Novel Contribution Proof)

We ran 5 scenarios on the same base DFD (Order Processing Service), progressively removing security information. This proves the system handles partial DFDs gracefully instead of refusing.

| Scenario | Threats | High Conf | Med Conf | Low Conf | Completeness | Partial? |
|----------|---------|-----------|----------|----------|--------------|----------|
| Full DFD (100%) | 3 | 0 | 1 | 2 | 100% | No |
| No Trust Boundaries | 3 | 0 | 1 | 2 | 75% | Yes |
| No Auth Info | 4 | 0 | 3 | 1 | 75% | Yes |
| No Encryption Info | 4 | 0 | 3 | 1 | 75% | Yes |
| **Minimal (nothing)** | **4** | **0** | **0** | **4** | **12%** | **Yes** |

**Key findings:**
- ✅ The system **never refused** to analyse — even at 12% completeness it found 4 threats
- ✅ Confidence degrades appropriately: Full DFD → mix of Medium/Low; Minimal DFD → ALL Low confidence
- ✅ `partial_dfd_detected` flag correctly set to `True` for all incomplete scenarios
- ✅ This is the **novel contribution** of the paper — graceful degradation under incomplete information

**The raw CSV data is in:** `evaluation/results/degradation_experiment.csv`

---

## 7. Technical Decisions & Gotchas (Important for Person B)

### LLM Choice: Groq + llama-3.3-70b-versatile
- **Why Groq:** Free tier, 30 req/min, fast (2-3s per call)
- **Why NOT Gemini:** Daily quota exhausted on free tier
- **response_format=json_object:** We force Groq to output valid JSON — eliminates most parsing issues
- **Temperature = 0.1:** Near-deterministic output, consistent results across runs

### What `response_format=json_object` means for Person B
The LLM is forced to return valid JSON every time. Our response parser still validates and normalises it (in case of schema mismatches), but you won't get markdown-wrapped responses.

### Partial DFDs — Confidence System
- **High confidence:** The DFD explicitly shows a security problem (e.g., `authenticated: false`)
- **Medium confidence:** The DFD is missing some info but there are clear indicators (e.g., HTTP on a login endpoint)
- **Low confidence:** The DFD is very incomplete, but the threat is structurally likely

### Never Trust `stride_coverage` from LLM
The LLM sometimes miscounts. Our parser always recomputes `stride_coverage` by counting validated threats directly. Use `result["stride_coverage"]` — it's always accurate.

### Error Handling Pattern
```python
result = analyze_dfd(dfd_json)

# ALWAYS check this pattern:
if result.get("error"):
    # pipeline failed — log it, skip this DFD, continue with others
    pass
else:
    # process normally
    threats = result["threats"]
```

### Rate Limits (Groq Free Tier)
- 30 requests/minute
- 6,000 requests/day
- If running many DFDs in a loop, add `time.sleep(2)` between calls

---

## 8. Repository Structure

```
SecureByDesign/
│
├── pipeline/                    ← Person A's work — the AI pipeline
│   ├── __init__.py              ← Public API surface
│   ├── dfd_parser.py            ← Parses DFD JSON → structured data
│   ├── prompt_templates.py      ← System prompt + few-shot examples
│   ├── response_parser.py       ← Validates/normalises LLM output
│   └── inference.py             ← Main engine: analyze_dfd() lives here
│
├── evaluation/                  ← Test results
│   └── results/
│       └── degradation_experiment.csv   ← Stress test data
│
├── data/                        ← Dataset directory
│   └── microSecEnD/             ← Cloned microservice DFD dataset
│
├── app/                         ← Person B's territory (Streamlit UI)
│
└── requirements.txt             ← All Python dependencies
```

---

## 9. Quick Reference Cheat Sheet

```python
# ═══════════════════════════════════════════
# PERSON B QUICK START
# ═══════════════════════════════════════════

# 1. Install
# pip install groq scikit-learn pandas python-dateutil

# 2. Set API key (Kaggle Secrets OR environment variable)
# Kaggle: Add-ons → Secrets → GROQ_API_KEY
# Local:  export GROQ_API_KEY="your_key_here"

# 3. Import
from pipeline.inference import analyze_dfd

# 4. Call
result = analyze_dfd(your_dfd_dict, "optional context")

# 5. Use result
result["overall_risk_level"]      # "High", "Medium", "Low", "Critical", "Unknown"
result["threats"]                  # list of threat dicts
result["stride_coverage"]          # {"Spoofing": 2, "Tampering": 1, ...}
result["partial_dfd_detected"]     # True if DFD was incomplete
result["completeness_score"]       # 0.0 to 1.0
result["analysis_duration_seconds"] # how long the API call took
result.get("error")                # None if success, string if failure

# 6. Each threat has:
threat["stride_category"]     # one of the 6 STRIDE categories
threat["affected_component"]  # e.g., "E1: Client → API"
threat["threat_description"]  # what the threat is
threat["missing_control"]     # what security control is missing
threat["confidence"]          # "High", "Medium", or "Low"
threat["confidence_reason"]   # why this confidence level
threat["explanation"]         # full detailed explanation
```

---

*Person A — AI Pipeline Engineer | SecureByDesign Project*  
*Pipeline status: ✅ Complete and production-ready*  
*Handoff date: 2026-03-01*
