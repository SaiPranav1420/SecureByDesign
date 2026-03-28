"""
Response Parser for SecureByDesign
Parses, validates, and normalizes LLM JSON output into clean threat reports.

Author: Person A
Project: SecureByDesign — Explainable LLM-Based STRIDE Threat Inference

Design principle: NEVER raises an exception. Every code path returns a valid dict.
Bad LLM output is degraded gracefully, not discarded.
"""

import json
import re
from datetime import datetime
from typing import Optional, Dict, Any


# ============================================================
# VALID VALUES (schema constants)
# ============================================================

VALID_STRIDE_CATEGORIES = {
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
}

VALID_CONFIDENCE_LEVELS = {"High", "Medium", "Low"}
VALID_RISK_LEVELS = {"Critical", "High", "Medium", "Low"}

# Fuzzy matching table for common LLM variations
STRIDE_ALIASES = {
    "spoof": "Spoofing",
    "spoofing": "Spoofing",
    "tamper": "Tampering",
    "tampering": "Tampering",
    "repudiat": "Repudiation",
    "repudiation": "Repudiation",
    "information disclosure": "Information Disclosure",
    "info disclosure": "Information Disclosure",
    "disclosure": "Information Disclosure",
    "denial of service": "Denial of Service",
    "dos": "Denial of Service",
    "denial": "Denial of Service",
    "elevation of privilege": "Elevation of Privilege",
    "privilege escalation": "Elevation of Privilege",
    "privilege": "Elevation of Privilege",
    "escalation": "Elevation of Privilege",
    "eop": "Elevation of Privilege",
}


# ============================================================
# PUBLIC API
# ============================================================

def parse_llm_response(raw_response: str, dfd_id: str, system_name: str) -> dict:
    """
    Parse and validate an LLM's raw response into a clean, schema-compliant threat report.

    Never raises — returns a structured error report on complete failure.

    Args:
        raw_response: Raw string output from Gemini API.
        dfd_id: DFD identifier used as fallback if LLM omits it.
        system_name: System name used as fallback.

    Returns:
        Validated threat report dict matching the SecureByDesign output schema.
        Always contains: dfd_id, system_name, analysis_timestamp, overall_risk_level,
        partial_dfd_detected, threats[], missing_controls_summary[], stride_coverage{}.
    """
    # Step 1: Extract JSON string from raw response
    json_str = _extract_json(raw_response)
    if json_str is None:
        return _error_report(
            dfd_id, system_name,
            f"LLM did not return parseable JSON. Raw response starts with: "
            f"'{raw_response[:100] if raw_response else 'EMPTY'}'"
        )

    # Step 2: Parse JSON string
    try:
        report = json.loads(json_str)
    except json.JSONDecodeError as e:
        # Try once more after stripping trailing commas (common LLM mistake)
        cleaned = re.sub(r',\s*([}\]])', r'\1', json_str)
        try:
            report = json.loads(cleaned)
        except json.JSONDecodeError:
            return _error_report(dfd_id, system_name, f"JSON parse error: {str(e)}")

    if not isinstance(report, dict):
        return _error_report(dfd_id, system_name, "LLM returned a JSON array instead of an object")

    # Step 3: Normalize and fill all fields
    report = _normalize_report(report, dfd_id, system_name)

    return report


# ============================================================
# PRIVATE: JSON EXTRACTION
# ============================================================

def _extract_json(text: str) -> Optional[str]:
    """
    Extract a JSON object string from LLM response text.
    Handles: clean JSON, markdown code blocks, JSON embedded in prose.

    Returns:
        JSON string starting with '{', or None if not found.
    """
    if not text:
        return None

    text = text.strip()

    # Case 1: Response is already clean JSON
    if text.startswith('{'):
        return text

    # Case 2: JSON wrapped in markdown code blocks (LLMs often do this)
    markdown_patterns = [
        r'```json\s*([\s\S]*?)\s*```',   # ```json ... ```
        r'```\s*([\s\S]*?)\s*```',        # ``` ... ```
        r'`([\s\S]*?)`',                  # ` ... `
    ]
    for pattern in markdown_patterns:
        match = re.search(pattern, text)
        if match:
            candidate = match.group(1).strip()
            if candidate.startswith('{'):
                return candidate

    # Case 3: Find the outermost { ... } in the full text
    # Use brace depth counting for robustness
    start = text.find('{')
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False

    for i, char in enumerate(text[start:], start=start):
        if escape_next:
            escape_next = False
            continue
        if char == '\\':
            escape_next = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return text[start:i+1]

    return None


# ============================================================
# PRIVATE: NORMALIZATION
# ============================================================

def _normalize_report(report: dict, dfd_id: str, system_name: str) -> dict:
    """
    Validate all fields and fill in safe defaults for any missing ones.
    Never rejects a report — always returns something usable.
    """
    # ── Top-level scalar fields ───────────────────────────────────────────────
    report.setdefault('dfd_id', dfd_id)
    report.setdefault('system_name', system_name)
    report.setdefault('analysis_timestamp', datetime.utcnow().isoformat() + 'Z')
    report.setdefault('partial_dfd_detected', False)
    report.setdefault('missing_controls_summary', [])

    # Validate overall_risk_level — must be one of our four levels
    if report.get('overall_risk_level') not in VALID_RISK_LEVELS:
        report['overall_risk_level'] = 'High'  # Conservative safe default

    # Ensure missing_controls_summary is a list of strings
    mcs = report.get('missing_controls_summary', [])
    if not isinstance(mcs, list):
        report['missing_controls_summary'] = [str(mcs)] if mcs else []

    # ── Threats array ─────────────────────────────────────────────────────────
    raw_threats = report.get('threats', [])
    if not isinstance(raw_threats, list):
        raw_threats = []

    valid_threats = []
    for i, threat in enumerate(raw_threats):
        normalized = _normalize_threat(threat, i + 1)
        if normalized is not None:
            valid_threats.append(normalized)

    report['threats'] = valid_threats

    # ── Recompute stride_coverage from validated threats ──────────────────────
    # Do NOT trust the LLM's self-reported counts — compute from ground truth
    coverage = {cat: 0 for cat in VALID_STRIDE_CATEGORIES}
    for threat in valid_threats:
        cat = threat.get('stride_category')
        if cat in coverage:
            coverage[cat] += 1
    report['stride_coverage'] = coverage

    return report


def _normalize_threat(threat: Any, index: int) -> Optional[dict]:
    """
    Normalize and validate a single threat entry.
    Fills in defaults for missing fields. Returns None only if threat is
    completely unsalvageable (e.g., not a dict at all).
    """
    if not isinstance(threat, dict):
        return None

    # Required fields — fill with safe defaults if missing
    threat.setdefault('threat_id', f'T{index}')
    threat.setdefault('affected_component', 'Unspecified component')
    threat.setdefault('threat_description', 'Threat description not provided by model')
    threat.setdefault('missing_control', 'No specific control recommended')
    threat.setdefault('confidence_reason', 'Confidence rationale not specified')
    threat.setdefault('explanation', 'No additional explanation provided')

    # ── Validate STRIDE category ──────────────────────────────────────────────
    raw_cat = str(threat.get('stride_category', '')).strip()

    if raw_cat in VALID_STRIDE_CATEGORIES:
        pass  # Already valid
    else:
        # Try fuzzy matching via alias table
        raw_lower = raw_cat.lower()
        matched = None

        # Direct alias lookup
        for alias, canonical in STRIDE_ALIASES.items():
            if alias in raw_lower:
                matched = canonical
                break

        # Substring match against canonical names
        if not matched:
            for canonical in VALID_STRIDE_CATEGORIES:
                if canonical.lower() in raw_lower or raw_lower in canonical.lower():
                    matched = canonical
                    break

        threat['stride_category'] = matched if matched else 'Information Disclosure'

    # ── Validate confidence level ─────────────────────────────────────────────
    conf = str(threat.get('confidence', '')).strip().capitalize()
    if conf not in VALID_CONFIDENCE_LEVELS:
        threat['confidence'] = 'Low'  # Conservative: when uncertain, go Low
    else:
        threat['confidence'] = conf

    return threat


def _error_report(dfd_id: str, system_name: str, error_message: str) -> dict:
    """
    Return a fully structured error report when parsing fails completely.
    Schema-compliant so callers don't need special error handling.
    """
    return {
        "dfd_id": dfd_id,
        "system_name": system_name,
        "analysis_timestamp": datetime.utcnow().isoformat() + 'Z',
        "overall_risk_level": "Unknown",
        "partial_dfd_detected": True,
        "error": error_message,
        "threats": [],
        "missing_controls_summary": [f"⚠ Analysis failed: {error_message}"],
        "stride_coverage": {cat: 0 for cat in VALID_STRIDE_CATEGORIES},
    }


# ============================================================
# SELF-TEST
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("RESPONSE PARSER SELF-TEST")
    print("=" * 60)

    # Test 1: Clean, valid JSON
    clean_json = json.dumps({
        "dfd_id": "t1",
        "system_name": "Test System",
        "overall_risk_level": "High",
        "partial_dfd_detected": False,
        "threats": [
            {
                "threat_id": "T1",
                "stride_category": "Spoofing",
                "affected_component": "E1: Client → API",
                "threat_description": "No authentication on entry point",
                "missing_control": "Implement JWT validation",
                "confidence": "High",
                "confidence_reason": "Trust boundary crossed without auth",
                "explanation": "An attacker can impersonate any user."
            },
            {
                "threat_id": "T2",
                "stride_category": "Information Disclosure",
                "affected_component": "E2: API → DB",
                "threat_description": "Data transmitted unencrypted",
                "missing_control": "Enable TLS on DB connection",
                "confidence": "High",
                "confidence_reason": "Explicitly not encrypted",
                "explanation": "Database queries are readable by any network observer."
            }
        ],
        "missing_controls_summary": ["No auth on E1", "No encryption on E2"],
        "stride_coverage": {"Spoofing": 1, "Tampering": 0, "Repudiation": 0,
                             "Information Disclosure": 1, "Denial of Service": 0,
                             "Elevation of Privilege": 0}
    })
    r1 = parse_llm_response(clean_json, "t1", "Test System")
    assert len(r1['threats']) == 2, f"Expected 2 threats, got {len(r1['threats'])}"
    assert r1['stride_coverage']['Spoofing'] == 1
    print(f"✅ Test 1 PASSED — Clean JSON: {len(r1['threats'])} threats, coverage correct")

    # Test 2: JSON wrapped in markdown code block
    wrapped = f"Sure, here is the analysis:\n\n```json\n{clean_json}\n```\n\nLet me know if you need anything else."
    r2 = parse_llm_response(wrapped, "t1", "Test System")
    assert len(r2['threats']) == 2
    print(f"✅ Test 2 PASSED — Markdown-wrapped JSON extracted: {len(r2['threats'])} threats")

    # Test 3: Complete garbage input
    r3 = parse_llm_response("Sorry, I cannot analyze this DFD.", "t1", "Test System")
    assert 'error' in r3
    assert r3['threats'] == []
    print(f"✅ Test 3 PASSED — Garbage input handled: error='{r3['error'][:60]}...'")

    # Test 4: Invalid STRIDE category gets fuzzy-matched
    bad_stride_json = json.dumps({
        "threats": [
            {"stride_category": "privilege escalation", "confidence": "High",
             "affected_component": "E1", "threat_description": "x",
             "missing_control": "y", "confidence_reason": "z", "explanation": "w"}
        ]
    })
    r4 = parse_llm_response(bad_stride_json, "t2", "Test2")
    assert r4['threats'][0]['stride_category'] == "Elevation of Privilege"
    print(f"✅ Test 4 PASSED — Fuzzy STRIDE match: 'privilege escalation' → '{r4['threats'][0]['stride_category']}'")

    # Test 5: Missing fields get defaults applied
    minimal_threat_json = json.dumps({"threats": [{"stride_category": "Tampering"}]})
    r5 = parse_llm_response(minimal_threat_json, "t3", "Test3")
    t = r5['threats'][0]
    assert t['confidence'] == 'Low'  # Conservative default
    assert t['threat_id'] == 'T1'
    print(f"✅ Test 5 PASSED — Missing fields filled with defaults (confidence={t['confidence']})")

    print("\n✅ ALL RESPONSE PARSER TESTS PASSED")
