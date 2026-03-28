"""
Main Inference Engine for SecureByDesign
Orchestrates the full DFD → STRIDE threat analysis pipeline.

Author: Person A
Project: SecureByDesign — Explainable LLM-Based STRIDE Threat Inference

USAGE (Person B imports this):
    from pipeline.inference import analyze_dfd
    result = analyze_dfd(dfd_json_dict, security_context_string)

LLM BACKEND:
    Groq API — free tier, OpenAI-compatible
    Model: llama-3.3-70b-versatile (128k context, excellent JSON output)
    Get free API key: https://console.groq.com/keys

ENVIRONMENT:
    Reads GROQ_API_KEY from Kaggle Secrets, then falls back to env var.
"""

import time
import os
from datetime import datetime
from typing import Optional

from groq import Groq

from pipeline.dfd_parser import parse_dfd, normalize_dfd_json
from pipeline.prompt_templates import SYSTEM_PROMPT, build_analysis_prompt
from pipeline.response_parser import parse_llm_response


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_NAME = "llama-3.3-70b-versatile"   # Best free Groq model — 128k context
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2                       # seconds, linear backoff
MAX_OUTPUT_TOKENS = 4096
TEMPERATURE = 0.1                          # Low = deterministic, consistent JSON

STRIDE_CATS = [
    "Spoofing", "Tampering", "Repudiation",
    "Information Disclosure", "Denial of Service", "Elevation of Privilege"
]


# ============================================================
# API KEY RETRIEVAL
# ============================================================

def _get_api_key() -> str:
    """
    Retrieve Groq API key from Kaggle Secrets, then fall back to env var.
    Never raises — returns empty string if key not found.
    Get your key at: https://console.groq.com/keys
    """
    # Primary: Kaggle Secrets
    try:
        from kaggle_secrets import UserSecretsClient
        key = UserSecretsClient().get_secret("GROQ_API_KEY")
        if key:
            return key
    except Exception:
        pass

    # Fallback: Environment variable (local testing)
    return os.environ.get("GROQ_API_KEY", "")


def _build_groq_messages(messages: list) -> list:
    """
    Convert prompt_templates.py Gemini-format messages → Groq/OpenAI format.

    Gemini format:  {"role": "user"/"model", "parts": ["content string"]}
    Groq format:    {"role": "user"/"assistant", "content": "content string"}

    The system prompt is NOT included here — it is passed as a separate
    system message at index 0 by the caller.
    """
    groq_msgs = []
    for msg in messages:
        role = msg["role"]
        content = msg["parts"][0] if isinstance(msg.get("parts"), list) else msg.get("content", "")
        # Gemini uses "model" role; Groq/OpenAI uses "assistant"
        if role == "model":
            role = "assistant"
        groq_msgs.append({"role": role, "content": content})
    return groq_msgs


# ============================================================
# MAIN CONTRACT FUNCTION
# ============================================================

def analyze_dfd(dfd_json: dict, security_context: str = "") -> dict:
    """
    Analyze a Data Flow Diagram and return a STRIDE threat report.

    This is the single function Person B depends on. It is the contract
    between the pipeline module and the evaluation harness / Streamlit UI.

    Pipeline:
        1. Parse DFD JSON → ParsedDFD (nodes, edges, flags, completeness score)
        2. Build few-shot prompt → message list
        3. Call Groq API with retry logic → raw response string
        4. Parse + validate LLM response → clean threat report dict
        5. Enrich result with parser metadata

    Args:
        dfd_json: DFD dictionary matching the SecureByDesign input schema.
                  Minimum required: dfd_id, system_name, nodes, edges.
        security_context: Optional plain-English context string.
                          E.g., "This is an internet-facing payment system handling PII."

    Returns:
        Threat report dict matching the SecureByDesign output schema.

        GUARANTEED fields (always present, even on error):
            dfd_id, system_name, analysis_timestamp, overall_risk_level,
            partial_dfd_detected, threats[], missing_controls_summary[], stride_coverage{}

        ENRICHED fields:
            completeness_score (float), dfd_missing_elements (list),
            analysis_duration_seconds (float), model_used (str)

        On any failure: returns schema-compliant error dict with 'error' key.
        NEVER raises an exception.
    """
    t0 = time.time()

    # ── STEP 0: Normalize DFD JSON (format-agnostic) ─────────────────────────
    dfd_json = normalize_dfd_json(dfd_json)

    dfd_id = dfd_json.get("dfd_id", "unknown")
    sys_name = dfd_json.get("system_name", "Unknown System")

    print(f"\n[SecureByDesign] ─── Starting analysis ───")
    print(f"[SecureByDesign] DFD ID   : {dfd_id}")
    print(f"[SecureByDesign] System   : {sys_name}")
    print(f"[SecureByDesign] Model    : {MODEL_NAME} via Groq")

    # ── STEP 1: Parse DFD ────────────────────────────────────────────────────
    try:
        parsed = parse_dfd(dfd_json)
        print(f"[SecureByDesign] Parsed   : completeness={parsed.completeness_score:.0%}, "
              f"partial={parsed.is_partial}, nodes={len(parsed.nodes_all)}, "
              f"edges={len(parsed.edges)}, crossings={len(parsed.boundary_crossing_edges)}")
    except ValueError as e:
        print(f"[SecureByDesign] ✗ Parse error: {e}")
        return _err_result(dfd_id, sys_name, f"DFD parsing failed: {str(e)}")

    # ── STEP 2: Build prompt ──────────────────────────────────────────────────
    messages = build_analysis_prompt(parsed.text_summary, security_context)
    groq_messages = _build_groq_messages(messages)

    # Prepend system message (Groq uses a dedicated system role)
    groq_messages.insert(0, {"role": "system", "content": SYSTEM_PROMPT})

    total_chars = sum(len(m["content"]) for m in groq_messages)
    print(f"[SecureByDesign] Prompt   : {len(groq_messages)} messages, ~{total_chars} chars")

    # ── STEP 3: Call Groq with retry ─────────────────────────────────────────
    raw_response: Optional[str] = None
    last_error: Optional[str] = None
    client = Groq(api_key=_get_api_key())

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=groq_messages,
                temperature=TEMPERATURE,
                max_tokens=MAX_OUTPUT_TOKENS,
                # Force valid JSON output — Groq supports this natively
                response_format={"type": "json_object"},
            )
            raw_response = completion.choices[0].message.content
            usage = completion.usage
            print(f"[SecureByDesign] Groq OK  : attempt={attempt}, "
                  f"response_len={len(raw_response)}, "
                  f"in={usage.prompt_tokens} out={usage.completion_tokens} tokens")
            break

        except Exception as e:
            last_error = str(e)
            print(f"[SecureByDesign] Groq FAIL: attempt={attempt}/{MAX_RETRIES}: {last_error[:120]}")
            if attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY * attempt
                print(f"[SecureByDesign] Retrying in {delay}s...")
                time.sleep(delay)

    if raw_response is None:
        return _err_result(
            dfd_id, sys_name,
            f"Groq API failed after {MAX_RETRIES} attempts: {last_error}",
            parsed.completeness_score, parsed.is_partial, parsed.missing_elements
        )

    # ── STEP 4: Parse + validate LLM response ────────────────────────────────
    result = parse_llm_response(raw_response, dfd_id, sys_name)

    # ── STEP 5: Enrich result with parser metadata ────────────────────────────
    result["partial_dfd_detected"] = parsed.is_partial
    result["completeness_score"] = round(parsed.completeness_score, 3)
    result["dfd_missing_elements"] = parsed.missing_elements
    result["analysis_duration_seconds"] = round(time.time() - t0, 2)
    result["model_used"] = MODEL_NAME

    print(f"[SecureByDesign] Done     : threats={len(result.get('threats', []))}, "
          f"risk={result.get('overall_risk_level')}, "
          f"duration={result['analysis_duration_seconds']}s")
    print(f"[SecureByDesign] STRIDE   : {result.get('stride_coverage', {})}")
    print(f"[SecureByDesign] ─── Analysis complete ───\n")

    return result


# ============================================================
# PRIVATE HELPER
# ============================================================

def _err_result(
    dfd_id: str,
    sys_name: str,
    msg: str,
    cs: float = 0.0,
    partial: bool = True,
    missing: list = None,
) -> dict:
    """Return a fully schema-compliant error report. Never raises."""
    return {
        "dfd_id": dfd_id,
        "system_name": sys_name,
        "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
        "overall_risk_level": "Unknown",
        "partial_dfd_detected": partial,
        "error": msg,
        "threats": [],
        "missing_controls_summary": [f"⚠ Analysis failed: {msg}"],
        "stride_coverage": {c: 0 for c in STRIDE_CATS},
        "completeness_score": cs,
        "dfd_missing_elements": missing or [],
        "analysis_duration_seconds": 0.0,
        "model_used": MODEL_NAME,
    }


# ============================================================
# SELF-TEST (requires GROQ_API_KEY env var)
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("INFERENCE ENGINE INTEGRATION TEST (Groq)")
    print("=" * 60)
    print("NOTE: Requires GROQ_API_KEY env var — get free key at console.groq.com/keys\n")

    sample_dfd = {
        "dfd_id": "integration_test_001",
        "system_name": "User Authentication Microservice",
        "nodes": [
            {"id": "N1", "type": "external_entity", "name": "Mobile Client", "description": "iOS/Android app"},
            {"id": "N2", "type": "process",         "name": "API Gateway",   "description": "Reverse proxy"},
            {"id": "N3", "type": "process",         "name": "Auth Service",  "description": "JWT issuer"},
            {"id": "N4", "type": "datastore",       "name": "User Database", "description": "Credentials"},
        ],
        "edges": [
            {"id": "E1", "from": "N1", "to": "N2", "data_description": "Login credentials",
             "protocol": "HTTPS", "authenticated": None, "encrypted": True},
            {"id": "E2", "from": "N2", "to": "N3", "data_description": "Auth request",
             "protocol": "HTTP",  "authenticated": False, "encrypted": False},
            {"id": "E3", "from": "N3", "to": "N4", "data_description": "User lookup",
             "protocol": "TCP",   "authenticated": True,  "encrypted": None},
        ],
        "trust_boundaries": [
            {"id": "TB1", "name": "Internet Boundary",         "separates": ["N1", "N2"]},
            {"id": "TB2", "name": "Internal Service Boundary", "separates": ["N2", "N3"]},
        ],
        "partial_info_flags": {
            "missing_trust_boundaries": False, "unknown_protocols": False,
            "unspecified_auth": True, "incomplete_nodes": False
        }
    }

    result = analyze_dfd(
        sample_dfd,
        "Internet-facing authentication service for a fintech app. Handles user login and JWT issuance."
    )

    print("\n=== RESULTS ===")
    print(f"Risk Level     : {result.get('overall_risk_level')}")
    print(f"Threats Found  : {len(result.get('threats', []))}")
    print(f"Partial DFD    : {result.get('partial_dfd_detected')}")
    print(f"Completeness   : {result.get('completeness_score', 0):.0%}")
    print(f"Duration       : {result.get('analysis_duration_seconds')}s")
    print(f"Model          : {result.get('model_used')}")
    print(f"STRIDE Coverage: {result.get('stride_coverage', {})}")

    if result.get("error"):
        print(f"\n⚠ Error: {result['error']}")
    elif result.get("threats"):
        t = result["threats"][0]
        print(f"\nTop Threat:")
        print(f"  [{t['stride_category']}] {t['affected_component']}")
        print(f"  Confidence: {t['confidence']} — {t['confidence_reason']}")
        print(f"  {t['explanation'][:200]}")

    # Graceful failure test
    bad = analyze_dfd({"system_name": "Bad"})
    assert "error" in bad and bad["threats"] == []
    print("\n✅ Error handling: bad input handled gracefully")
    print("✅ INTEGRATION TEST COMPLETE")
