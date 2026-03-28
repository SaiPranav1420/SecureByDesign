"""
Prompt Templates for SecureByDesign
All LLM prompts for STRIDE threat inference from DFD JSON.

Author: Person A
Project: SecureByDesign — Explainable LLM-Based STRIDE Threat Inference

ENGINEERING NOTES:
  - System prompt establishes STRIDE expert persona and enforces JSON-only output
  - Three few-shot examples cover: complete DFD, highly incomplete DFD, internal microservice
  - Partial DFD instructions tell the model to LOWER confidence, not refuse to analyze
  - JSON output is always enforced — no markdown, no preamble, no explanation outside JSON
  - Temperature should be set to 0.1 in the model config (done in inference.py)
"""


# ============================================================
# SYSTEM PROMPT
# Sets LLM persona, rules, output schema, and handling of partial DFDs
# ============================================================

SYSTEM_PROMPT = """You are an expert software security architect specializing in threat modeling using the STRIDE framework. You have 15 years of experience analyzing Data Flow Diagrams (DFDs) and identifying architectural security risks in enterprise microservice systems, payment platforms, and cloud-native architectures.

Your task is to analyze a software system's Data Flow Diagram and produce a comprehensive STRIDE threat analysis. You must follow ALL of these rules precisely:

ANALYSIS RULES:
1. Identify all credible security threats based ONLY on the DFD information provided
2. Map each threat to EXACTLY ONE STRIDE category:
   Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege
3. Reference specific DFD components (exact node names and edge IDs like E1, E2) in every threat finding
4. Assign confidence based strictly on information completeness:
   - HIGH: Explicit evidence in DFD — confirmed missing control or confirmed insecure configuration
   - MEDIUM: Probable risk based on common patterns — some DFD information is absent
   - LOW: Possible risk but substantial information is missing — reasoning is largely inferential
5. For INCOMPLETE/PARTIAL DFDs: Still produce findings but lower your confidence accordingly — do NOT refuse to analyze or say you cannot determine anything
6. Write architect-facing explanations: practical, specific to this system's components, actionable

CRITICAL OUTPUT RULES:
- Respond ONLY with valid JSON. No markdown. No preamble. No explanation outside the JSON object.
- Your response MUST start exactly with { and end exactly with }
- Every threat object MUST have ALL required fields populated (no nulls, no omissions)
- Do NOT invent threats that have no basis in the DFD — ground every finding in specific edges, nodes, or missing boundaries
- Do NOT claim a system is "secure" — always note what cannot be verified from the available information
- Produce at minimum 2 threats and at maximum 8 threats per analysis

OUTPUT SCHEMA (follow exactly):
{
  "dfd_id": "string — copy from input",
  "system_name": "string — copy from input",
  "analysis_timestamp": "ISO 8601 timestamp (e.g. 2025-01-01T10:00:00Z)",
  "overall_risk_level": "Critical | High | Medium | Low",
  "partial_dfd_detected": true or false,
  "threats": [
    {
      "threat_id": "T1",
      "stride_category": "exact STRIDE category name",
      "affected_component": "e.g. E1: Mobile Client → API Gateway",
      "threat_description": "concise, specific description of what the threat is",
      "missing_control": "the specific security control that is absent",
      "confidence": "High | Medium | Low",
      "confidence_reason": "one sentence: why this specific confidence level was assigned",
      "explanation": "2-3 sentences in plain English for an architect: what happens, why it matters, what to do"
    }
  ],
  "missing_controls_summary": ["array of top-level missing security controls — 2-5 items"],
  "stride_coverage": {
    "Spoofing": 0,
    "Tampering": 0,
    "Repudiation": 0,
    "Information Disclosure": 0,
    "Denial of Service": 0,
    "Elevation of Privilege": 0
  }
}"""


# ============================================================
# FEW-SHOT EXAMPLE 1
# Scenario: E-Commerce Order Service — 75% complete, clear High-confidence threats
# Teaches: High-confidence findings on explicitly missing controls
# ============================================================

FEW_SHOT_EXAMPLE_1_INPUT = """Analyze the following Data Flow Diagram for STRIDE security threats. Respond with ONLY valid JSON matching the output schema. No markdown. No preamble.

SYSTEM: E-Commerce Order Service
DFD ID: example_001
COMPLETENESS: 75%

=== COMPONENTS ===
External Entities (untrusted/outside system boundary): Web Browser
Processes (application logic): Order API, Payment Processor
Datastores (data at rest): Orders Database, Payment Vault

=== TRUST BOUNDARIES ===
  [TB1] Internet Boundary: separates Web Browser | Order API

=== DATA FLOWS ===
  [E1] Web Browser → Order API
       Data: Order request with payment info | Protocol: HTTPS | AUTHENTICATION UNSPECIFIED | encrypted
  [E2] Order API → Payment Processor
       Data: Payment card data | Protocol: HTTP | NOT authenticated | NOT encrypted
  [E3] Payment Processor → Payment Vault
       Data: Tokenized payment data | Protocol: TCP | AUTHENTICATION UNSPECIFIED | ENCRYPTION UNSPECIFIED
  [E4] Order API → Orders Database
       Data: Order records | Protocol: TCP | NOT authenticated | encrypted

=== TRUST BOUNDARY CROSSINGS (HIGH SECURITY RELEVANCE) ===
  [E1] Web Browser → Order API
       Crosses: Internet Boundary
       Auth: UNSPECIFIED | Encrypted: YES

Produce the complete STRIDE threat analysis now:"""

FEW_SHOT_EXAMPLE_1_OUTPUT = """{
  "dfd_id": "example_001",
  "system_name": "E-Commerce Order Service",
  "analysis_timestamp": "2025-01-01T00:00:00Z",
  "overall_risk_level": "Critical",
  "partial_dfd_detected": true,
  "threats": [
    {
      "threat_id": "T1",
      "stride_category": "Information Disclosure",
      "affected_component": "E2: Order API → Payment Processor",
      "threat_description": "Payment card data transmitted over unencrypted HTTP between internal services",
      "missing_control": "Enforce TLS/HTTPS on E2; implement end-to-end encryption for all payment data in transit",
      "confidence": "High",
      "confidence_reason": "Edge E2 is explicitly marked NOT encrypted while carrying payment card data — a confirmed critical violation",
      "explanation": "Edge E2 carries raw payment card data between the Order API and Payment Processor over plain HTTP with no encryption. Any attacker with access to the internal network — such as a malicious insider or a compromised service — can intercept and read card numbers verbatim. This is a PCI-DSS violation. Immediately replace HTTP with mutual TLS on this connection."
    },
    {
      "threat_id": "T2",
      "stride_category": "Spoofing",
      "affected_component": "E1: Web Browser → Order API (crosses Internet Boundary TB1)",
      "threat_description": "No authentication mechanism specified on the only internet-facing entry point",
      "missing_control": "Implement JWT/OAuth 2.0 token validation at the Order API before processing any request",
      "confidence": "High",
      "confidence_reason": "E1 crosses the internet trust boundary with authentication explicitly marked UNSPECIFIED",
      "explanation": "Any request entering the system through E1 is from the untrusted internet. With authentication unspecified, an attacker can submit arbitrary order requests while impersonating any user identity. Implement server-side JWT validation so every request is bound to a verified identity before execution."
    },
    {
      "threat_id": "T3",
      "stride_category": "Tampering",
      "affected_component": "E4: Order API → Orders Database",
      "threat_description": "Unauthenticated database connection allows any process to modify order records",
      "missing_control": "Enforce database-level authentication using least-privilege service accounts with parameterized queries",
      "confidence": "High",
      "confidence_reason": "E4 is explicitly NOT authenticated on a datastore containing financial records",
      "explanation": "The connection from Order API to Orders Database on E4 has no authentication enforced. A compromised process anywhere in the system can freely query, modify, or delete order records without restriction. Implement authenticated service-account access with role-based permissions scoped to exactly what the Order API requires."
    },
    {
      "threat_id": "T4",
      "stride_category": "Repudiation",
      "affected_component": "Order API (process)",
      "threat_description": "No audit logging mechanism present for order or payment processing actions",
      "missing_control": "Implement immutable audit logs for all order creation, modification, cancellation, and payment events",
      "confidence": "Medium",
      "confidence_reason": "Audit logging is not modeled in the DFD — may exist but cannot be confirmed from available information",
      "explanation": "The DFD models no logging or audit trail component for the Order API or Payment Processor. Without tamper-evident logs, a malicious actor can place fraudulent orders and credibly deny it. Implement write-once audit logs capturing actor, action, timestamp, and affected record for every order operation."
    },
    {
      "threat_id": "T5",
      "stride_category": "Denial of Service",
      "affected_component": "E1: Web Browser → Order API (crosses Internet Boundary TB1)",
      "threat_description": "No rate limiting or throttling mechanism on the internet-facing Order API entry point",
      "missing_control": "Implement rate limiting, request throttling, and DDoS protection at the API Gateway layer",
      "confidence": "Medium",
      "confidence_reason": "No rate limiting component modeled in DFD; absence of defense-in-depth for internet-facing entry point",
      "explanation": "The single internet-facing entry point E1 shows no rate limiting or request throttling controls. An attacker could flood the Order API with requests, exhausting backend resources and making the system unavailable to legitimate users. Implement per-IP and per-user rate limits with exponential backoff enforcement."
    }
  ],
  "missing_controls_summary": [
    "Encryption absent on internal payment data flow E2 — Critical PCI-DSS violation requiring immediate remediation",
    "Authentication unspecified on internet-facing entry point E1 — spoofing risk",
    "Database authentication absent on Orders Database connection E4 — tampering risk",
    "No audit logging modeled — repudiation risk on all financial operations"
  ],
  "stride_coverage": {
    "Spoofing": 1,
    "Tampering": 1,
    "Repudiation": 1,
    "Information Disclosure": 1,
    "Denial of Service": 1,
    "Elevation of Privilege": 0
  }
}"""


# ============================================================
# FEW-SHOT EXAMPLE 2
# Scenario: Auth Service — 35% complete, barely any info
# Teaches: How to handle partial DFDs with MEDIUM/LOW confidence
# ============================================================

FEW_SHOT_EXAMPLE_2_INPUT = """Analyze the following Data Flow Diagram for STRIDE security threats. Respond with ONLY valid JSON matching the output schema. No markdown. No preamble.

SYSTEM: Microservice Auth Service
DFD ID: example_002
COMPLETENESS: 35%

=== COMPONENTS ===
External Entities (untrusted/outside system boundary): API Client
Processes (application logic): Auth Service
Datastores (data at rest): Token Store

=== TRUST BOUNDARIES ===
  WARNING: No trust boundaries defined. Attack surface cannot be determined.

=== DATA FLOWS ===
  [E1] API Client → Auth Service
       Data: Credentials | Protocol: UNKNOWN PROTOCOL | AUTHENTICATION UNSPECIFIED | ENCRYPTION UNSPECIFIED
  [E2] Auth Service → Token Store
       Data: Token data | Protocol: UNKNOWN PROTOCOL | AUTHENTICATION UNSPECIFIED | ENCRYPTION UNSPECIFIED

=== PARTIAL DFD WARNINGS — REASON FOR LOWER CONFIDENCE ===
  ⚠  Trust boundaries not defined — cannot determine attack surface perimeter
  ⚠  Authentication unspecified on edges: E1, E2
  ⚠  Encryption unspecified on edges: E1, E2
  ⚠  Protocol unknown on edges: E1, E2

Produce the complete STRIDE threat analysis now:"""

FEW_SHOT_EXAMPLE_2_OUTPUT = """{
  "dfd_id": "example_002",
  "system_name": "Microservice Auth Service",
  "analysis_timestamp": "2025-01-01T00:00:00Z",
  "overall_risk_level": "High",
  "partial_dfd_detected": true,
  "threats": [
    {
      "threat_id": "T1",
      "stride_category": "Spoofing",
      "affected_component": "E1: API Client → Auth Service",
      "threat_description": "Credential flow uses unknown protocol with unspecified authentication — potential identity spoofing",
      "missing_control": "Specify and enforce HTTPS; define how the Auth Service validates client identity before processing credentials",
      "confidence": "Medium",
      "confidence_reason": "Authentication and protocol are unspecified — threat is probable for an auth service but severity cannot be confirmed without DFD detail",
      "explanation": "For an authentication service, the credential intake flow E1 must be secured with a known protocol and clear authentication enforcement. Both are unspecified in this DFD. If the protocol is not HTTPS or the endpoint lacks request validation, attackers can submit forged credential requests. Confidence is Medium because the controls may exist but simply are not modeled here."
    },
    {
      "threat_id": "T2",
      "stride_category": "Information Disclosure",
      "affected_component": "E1: API Client → Auth Service",
      "threat_description": "Credentials may be transmitted without encryption — encryption status is unspecified",
      "missing_control": "Confirm TLS encryption on all credential-bearing flows and document the encryption configuration explicitly",
      "confidence": "Medium",
      "confidence_reason": "Encryption is marked UNSPECIFIED on a flow carrying credentials — this gap must be clarified before deployment",
      "explanation": "Edge E1 carries credentials with no confirmed encryption. For an auth service, any unencrypted credential transmission is a critical exposure risk — attackers on the same network segment can capture passwords or tokens in plaintext. This is not confirmed to be absent; it is simply not confirmed to be present. Clarify immediately."
    },
    {
      "threat_id": "T3",
      "stride_category": "Elevation of Privilege",
      "affected_component": "E2: Auth Service → Token Store",
      "threat_description": "Absence of trust boundaries makes it impossible to determine privilege separation around the Token Store",
      "missing_control": "Define trust boundaries; enforce least-privilege access from Auth Service to Token Store with authenticated, scoped connections",
      "confidence": "Low",
      "confidence_reason": "No trust boundaries are defined — privilege scope cannot be assessed; threat is entirely inferential from architectural patterns",
      "explanation": "Without trust boundaries, we cannot determine whether the Token Store is accessible only to the Auth Service or to other services as well. If improperly scoped, a compromised microservice could read or forge tokens belonging to any user. Confidence is Low because the DFD provides insufficient information to confirm this risk — but the pattern is common enough to flag for design review."
    },
    {
      "threat_id": "T4",
      "stride_category": "Tampering",
      "affected_component": "E2: Auth Service → Token Store",
      "threat_description": "No authentication on the connection to Token Store — any process could write or modify tokens",
      "missing_control": "Enforce authenticated, write-restricted connections to the Token Store using service identity credentials",
      "confidence": "Medium",
      "confidence_reason": "Authentication is unspecified on a connection to a security-critical datastore — the risk is probable given the sensitivity of token data",
      "explanation": "The Token Store contains the authentication tokens for every user in the system. Edge E2 has no specified authentication mechanism for the Auth Service's connection. An attacker who can reach this service could inject forged tokens or invalidate existing ones. Even within a trusted network segment, cryptographic authentication should be enforced on this connection."
    }
  ],
  "missing_controls_summary": [
    "Trust boundaries entirely absent — attack surface and privilege separation are undefined",
    "Protocol unspecified on all data flows — security properties cannot be assessed",
    "Encryption unspecified on credential-bearing flow E1 — potential plaintext credential exposure",
    "Authentication unspecified on Token Store connection E2 — tampering risk on security-critical datastore"
  ],
  "stride_coverage": {
    "Spoofing": 1,
    "Tampering": 1,
    "Repudiation": 0,
    "Information Disclosure": 1,
    "Denial of Service": 0,
    "Elevation of Privilege": 1
  }
}"""


# ============================================================
# FEW-SHOT EXAMPLE 3 (ADDED FOR ROBUSTNESS)
# Scenario: Internal Service Mesh — 60% complete, internal microservice risks
# Teaches: EoP, Tampering in internal mesh; risks even without external entities
# ============================================================

FEW_SHOT_EXAMPLE_3_INPUT = """Analyze the following Data Flow Diagram for STRIDE security threats. Respond with ONLY valid JSON matching the output schema. No markdown. No preamble.

SYSTEM: Order Fulfillment Microservice Mesh
DFD ID: example_003
COMPLETENESS: 60%

=== COMPONENTS ===
External Entities (untrusted/outside system boundary): API Gateway
Processes (application logic): Order Service, Inventory Service, Notification Service
Datastores (data at rest): Orders DB, Inventory DB

=== TRUST BOUNDARIES ===
  [TB1] External Ingress: separates API Gateway | Order Service

=== DATA FLOWS ===
  [E1] API Gateway → Order Service
       Data: Order placement request | Protocol: HTTPS | authenticated | encrypted
  [E2] Order Service → Inventory Service
       Data: Stock reservation request | Protocol: HTTP | NOT authenticated | NOT encrypted
  [E3] Order Service → Orders DB
       Data: Order record | Protocol: TCP | authenticated | ENCRYPTION UNSPECIFIED
  [E4] Inventory Service → Inventory DB
       Data: Stock level update | Protocol: TCP | NOT authenticated | NOT encrypted
  [E5] Order Service → Notification Service
       Data: Order confirmation event | Protocol: AMQP | AUTHENTICATION UNSPECIFIED | NOT encrypted

=== TRUST BOUNDARY CROSSINGS (HIGH SECURITY RELEVANCE) ===
  [E1] API Gateway → Order Service
       Crosses: External Ingress
       Auth: YES | Encrypted: YES

=== PARTIAL DFD WARNINGS — REASON FOR LOWER CONFIDENCE ===
  ⚠  Encryption unspecified on edges: E3
  ⚠  Authentication unspecified on edges: E5

Produce the complete STRIDE threat analysis now:"""

FEW_SHOT_EXAMPLE_3_OUTPUT = """{
  "dfd_id": "example_003",
  "system_name": "Order Fulfillment Microservice Mesh",
  "analysis_timestamp": "2025-01-01T00:00:00Z",
  "overall_risk_level": "High",
  "partial_dfd_detected": true,
  "threats": [
    {
      "threat_id": "T1",
      "stride_category": "Elevation of Privilege",
      "affected_component": "E2: Order Service → Inventory Service",
      "threat_description": "Unauthenticated HTTP call between internal services allows any process to invoke Inventory Service operations",
      "missing_control": "Implement mutual TLS (mTLS) or service-to-service JWT tokens on all internal service mesh calls",
      "confidence": "High",
      "confidence_reason": "E2 is explicitly NOT authenticated over HTTP — confirmed absence of service identity enforcement on an inter-service call",
      "explanation": "Without authentication on E2, any compromised service or rogue container in the same network can call the Inventory Service and reserve or deplete stock without authorization. In a microservice mesh, lateral movement begins exactly here. Implement mTLS with service identity certificates so that only the Order Service can call Inventory Service endpoints."
    },
    {
      "threat_id": "T2",
      "stride_category": "Information Disclosure",
      "affected_component": "E2: Order Service → Inventory Service",
      "threat_description": "Stock reservation requests transmitted over unencrypted HTTP — internal network eavesdropping possible",
      "missing_control": "Enforce TLS on all inter-service links regardless of internal network trust assumptions",
      "confidence": "High",
      "confidence_reason": "E2 is explicitly NOT encrypted — internal traffic is readable by any host on the same network segment",
      "explanation": "In cloud and Kubernetes environments, 'internal' traffic crosses shared network fabric that is not inherently private. Edge E2 sends business-sensitive inventory data in plaintext. Enable TLS encryption on all service mesh links; this is the default posture in zero-trust network architectures."
    },
    {
      "threat_id": "T3",
      "stride_category": "Tampering",
      "affected_component": "E4: Inventory Service → Inventory DB",
      "threat_description": "Unauthenticated, unencrypted connection to Inventory DB allows arbitrary stock manipulation",
      "missing_control": "Enforce authenticated database connections with least-privilege service accounts; enable TLS on E4",
      "confidence": "High",
      "confidence_reason": "E4 is explicitly NOT authenticated and NOT encrypted on a critical financial datastore",
      "explanation": "The Inventory Database connection on E4 has no authentication or encryption. Any process that can reach the database port — including a compromised Inventory Service or a lateral-movement attacker — can freely read or manipulate stock levels. This enables inventory fraud and supply chain attacks. Enforce service-account authentication and encrypt this connection."
    },
    {
      "threat_id": "T4",
      "stride_category": "Spoofing",
      "affected_component": "E5: Order Service → Notification Service",
      "threat_description": "Unspecified authentication on the AMQP message queue allows any producer to inject fake order events",
      "missing_control": "Enforce AMQP authentication with publisher credentials; validate message signatures in Notification Service",
      "confidence": "Medium",
      "confidence_reason": "Authentication is UNSPECIFIED on a message queue — the risk is probable for event-driven architectures where message forgery is a known attack pattern",
      "explanation": "AMQP message queues without authentication allow any client that can reach the broker to publish messages. A forged order confirmation event could trigger fraudulent notifications (e.g., false shipping confirmations) without any actual order existing. Require AMQP credentials and consider signing event payloads so the Notification Service can verify their origin."
    },
    {
      "threat_id": "T5",
      "stride_category": "Information Disclosure",
      "affected_component": "E3: Order Service → Orders DB",
      "threat_description": "Encryption status of database connection containing order records is unspecified",
      "missing_control": "Confirm and enforce TLS encryption on the Orders DB connection string; log the encryption configuration in the DFD",
      "confidence": "Medium",
      "confidence_reason": "Encryption is UNSPECIFIED on E3 — cannot confirm order records are protected in transit",
      "explanation": "The Order Service writes order records (which likely include customer PII and payment references) to Orders DB over a connection with unspecified encryption. If TLS is not configured, this data is readable to any observer on the network path. Verify that the database driver is configured for encrypted connections and update the DFD to reflect this."
    }
  ],
  "missing_controls_summary": [
    "Service authentication absent on internal mesh calls E2 and E4 — lateral movement risk",
    "Encryption absent on inter-service calls E2 and E4 — internal eavesdropping risk",
    "AMQP authentication unspecified on E5 — message injection risk on event bus",
    "Encryption unspecified on Orders DB connection E3 — potential PII exposure in transit"
  ],
  "stride_coverage": {
    "Spoofing": 1,
    "Tampering": 1,
    "Repudiation": 0,
    "Information Disclosure": 2,
    "Denial of Service": 0,
    "Elevation of Privilege": 1
  }
}"""


# ============================================================
# PROMPT BUILDER
# ============================================================

def build_analysis_prompt(dfd_text_summary: str, security_context: str = "") -> list:
    """
    Build the complete few-shot prompt for the Gemini API.

    Assembles:
      - 3 few-shot input/output pairs (teach the model via examples)
      - Final user message with the actual DFD to analyze

    Args:
        dfd_text_summary: Text summary produced by dfd_parser._build_text_summary()
        security_context: Optional architect-provided context string
                          (e.g., "This system is internet-facing and handles PII")

    Returns:
        List of message dicts compatible with Gemini API chat history format.
        Each dict has 'role' ('user' or 'model') and 'parts' (list with one string).
        The last element is the actual user query (the DFD to analyze).
    """
    # Optional security context block
    context_block = ""
    if security_context and security_context.strip():
        context_block = (
            f"\n=== ADDITIONAL SECURITY CONTEXT (PROVIDED BY ARCHITECT) ===\n"
            f"{security_context.strip()}\n"
        )

    # The actual query — will be the final message in the chat history
    user_query = (
        "Analyze the following Data Flow Diagram for STRIDE security threats. "
        "Respond with ONLY valid JSON matching the output schema. No markdown. No preamble.\n\n"
        f"{dfd_text_summary}"
        f"{context_block}"
        "\nProduce the complete STRIDE threat analysis now:"
    )

    return [
        # Few-shot Example 1: Complete-ish DFD with clear High threats
        {"role": "user",  "parts": [FEW_SHOT_EXAMPLE_1_INPUT]},
        {"role": "model", "parts": [FEW_SHOT_EXAMPLE_1_OUTPUT]},

        # Few-shot Example 2: Highly incomplete DFD with Medium/Low threats
        {"role": "user",  "parts": [FEW_SHOT_EXAMPLE_2_INPUT]},
        {"role": "model", "parts": [FEW_SHOT_EXAMPLE_2_OUTPUT]},

        # Few-shot Example 3: Internal service mesh threats (EoP, Tampering)
        {"role": "user",  "parts": [FEW_SHOT_EXAMPLE_3_INPUT]},
        {"role": "model", "parts": [FEW_SHOT_EXAMPLE_3_OUTPUT]},

        # Actual query
        {"role": "user",  "parts": [user_query]},
    ]


# ============================================================
# SELF-TEST
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("PROMPT TEMPLATES SELF-TEST")
    print("=" * 60)

    test_summary = (
        "SYSTEM: Test Microservice\n"
        "DFD ID: test_001\n"
        "COMPLETENESS: 50%\n\n"
        "=== COMPONENTS ===\n"
        "External Entities: Mobile Client\n"
        "Processes: API Gateway, Auth Service\n\n"
        "=== DATA FLOWS ===\n"
        "  [E1] Mobile Client → API Gateway\n"
        "       Data: Login | Protocol: HTTPS | AUTHENTICATION UNSPECIFIED | encrypted\n"
    )

    messages = build_analysis_prompt(test_summary, "This system is internet-facing")

    assert len(messages) == 7, f"Expected 7 messages (3 pairs + query), got {len(messages)}"
    assert messages[-1]['role'] == 'user', "Last message must be user (the query)"
    assert messages[-1]['parts'][0].startswith("Analyze"), "Last message must start with 'Analyze'"
    assert "internet-facing" in messages[-1]['parts'][0], "Security context must be included"

    print(f"✅ Message count: {len(messages)} (3 few-shot pairs + 1 query = correct)")
    print(f"✅ Final message role: {messages[-1]['role']}")
    print(f"✅ Final message length: {len(messages[-1]['parts'][0])} characters")
    print(f"✅ Security context included: {'internet-facing' in messages[-1]['parts'][0]}")
    print(f"✅ System prompt length: {len(SYSTEM_PROMPT)} characters")
    print("\n✅ ALL PROMPT TEMPLATE TESTS PASSED")
