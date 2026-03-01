# SecureByDesign — Project Core Idea & Master Blueprint

> **An Explainable LLM-Based Framework for Architectural Security Risk Inference from Incomplete Early-Stage Design Artifacts**

---

## 1. The Problem We Are Solving

Modern software systems fail not because developers write bad code — they fail because architects make insecure design decisions before a single line of code is written. A misplaced trust boundary, an unencrypted data flow, a missing authentication control — these are architectural sins committed at the Data Flow Diagram (DFD) stage that cost 30x more to fix after deployment than at design time.

The brutal reality of today's tooling:

- **Microsoft Threat Modeling Tool** — fully manual, expert-dependent, takes hours per diagram
- **OWASP Threat Dragon** — manual, no AI reasoning whatsoever
- **ThreatModeling-LLM (our base paper, Yang et al. 2024)** — automated but only works on complete, perfectly annotated banking DFDs. Falls apart on real-world incomplete diagrams.
- **Every other tool** — analyzes code or runtime traffic, not design artifacts

**Nobody has built a system that takes a messy, incomplete, real-world DFD and automatically tells you where the security risks are, why they exist, and how confident it is — in plain English that an architect can act on immediately.**

That is exactly what SecureByDesign does.

---

## 2. What SecureByDesign Is

SecureByDesign is an **AI-powered architectural security reasoning assistant** that:

1. Accepts a Data Flow Diagram as structured JSON input
2. Accepts an optional plain-English security context description
3. Reasons over the diagram using a carefully engineered LLM pipeline (Google Gemini 1.5 Flash — free API)
4. Returns a complete, structured security threat report mapped to the STRIDE framework
5. Explicitly handles **incomplete and partial DFDs** — the novel contribution that no existing paper addresses
6. Provides human-interpretable explanations per finding, not just threat labels
7. Assigns confidence levels (High / Medium / Low) per threat based on information completeness
8. Presents everything through a clean Streamlit web interface

**It is not a vulnerability scanner. It is a design-time security reasoning assistant.**

---

## 3. The Novel Contribution

Our system extends ThreatModeling-LLM (Ref 1, Yang et al. 2024) in three specific ways that constitute genuine novelty:

| Dimension | ThreatModeling-LLM (Base Paper) | SecureByDesign (Our System) |
|-----------|--------------------------------|------------------------------|
| DFD completeness | Requires complete, annotated DFDs | Handles incomplete, partial DFDs |
| Domain | Banking systems only | Microservice architectures (general) |
| Output | Threat labels | Threat labels + explanations + confidence + missing controls |
| Explainability | None | Full natural language explanation per finding |
| Dataset | Microsoft TMT XML (banking) | microSecEnD (1000+ microservice DFDs) |

**The claim we defend:** *"A prompt-engineered LLM pipeline that infers STRIDE threats from incomplete early-stage DFDs with confidence scoring and architect-facing explanations, validated on microSecEnD."*

This is academically defensible, practically useful, and genuinely novel.

---

## 4. The STRIDE Framework (What We Detect)

Every security finding our system produces maps to one of six STRIDE categories:

| Category | What It Means | Example in a DFD |
|----------|---------------|------------------|
| **S**poofing | Attacker pretends to be someone else | No authentication on a data flow crossing a trust boundary |
| **T**ampering | Attacker modifies data in transit or at rest | No integrity check on data flowing between services |
| **R**epudiation | Actions cannot be traced back to actors | No audit logging on a critical process |
| **I**nformation Disclosure | Sensitive data exposed to unauthorized parties | Unencrypted data flow carrying PII |
| **D**enial of Service | System made unavailable | No rate limiting on external-facing entry points |
| **E**levation of Privilege | Attacker gains more access than allowed | No authorization check between internal services |

---

## 5. System Architecture — How It All Works

```
┌─────────────────────────────────────────────────────────────┐
│                    SECUREBYDESIGN PIPELINE                  │
│                                                             │
│  INPUT LAYER                                                │
│  ┌──────────────────┐    ┌─────────────────────────────┐   │
│  │  DFD JSON Input  │    │  Security Context (Text)    │   │
│  │  (nodes, edges,  │    │  "This system handles       │   │
│  │   trust bounds)  │    │   payments, internet-facing"│   │
│  └────────┬─────────┘    └──────────────┬──────────────┘   │
│           │                             │                   │
│           ▼                             ▼                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              DFD PARSER & VALIDATOR                  │   │
│  │  - Extracts nodes (processes, datastores, entities)  │   │
│  │  - Extracts edges (data flows with properties)       │   │
│  │  - Identifies trust boundaries                       │   │
│  │  - Flags missing/ambiguous elements (partial DFD)    │   │
│  │  - Produces structured context for LLM               │   │
│  └──────────────────────────┬──────────────────────────┘   │
│                             │                               │
│                             ▼                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           PROMPT ENGINEERING ENGINE                  │   │
│  │  - System prompt: STRIDE expert persona              │   │
│  │  - Few-shot examples: 3 labeled DFD→threat pairs    │   │
│  │  - Structured input: parsed DFD context              │   │
│  │  - Output schema: enforced JSON format               │   │
│  │  - Partial DFD handling: uncertainty instructions    │   │
│  └──────────────────────────┬──────────────────────────┘   │
│                             │                               │
│                             ▼                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │         GOOGLE GEMINI 1.5 FLASH API                  │   │
│  │              (Free Tier — No Cost)                   │   │
│  └──────────────────────────┬──────────────────────────┘   │
│                             │                               │
│                             ▼                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           RESPONSE PARSER & VALIDATOR                │   │
│  │  - Parses JSON response from LLM                     │   │
│  │  - Validates all required fields present             │   │
│  │  - Normalizes STRIDE categories                      │   │
│  │  - Handles malformed responses gracefully            │   │
│  └──────────────────────────┬──────────────────────────┘   │
│                             │                               │
│                             ▼                               │
│  OUTPUT LAYER                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              STRUCTURED THREAT REPORT                │   │
│  │  Per threat:                                         │   │
│  │  - STRIDE category                                   │   │
│  │  - Affected DFD component                            │   │
│  │  - Threat description                                │   │
│  │  - Missing security control                          │   │
│  │  - Confidence level (High/Medium/Low)                │   │
│  │  - Plain-English explanation                         │   │
│  └──────────────────────────┬──────────────────────────┘   │
│                             │                               │
│                             ▼                               │
│  ┌──────────────────┐    ┌─────────────────────────────┐   │
│  │  STREAMLIT UI    │    │    EVALUATION HARNESS        │   │
│  │  (Live Demo)     │    │    (F1/Precision/Recall)     │   │
│  └──────────────────┘    └─────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. The Data Contract (Sacred — Never Change Without Agreement)

This is the exact JSON format that connects Person A's pipeline to Person B's evaluation and UI. Both sides must honor this format from Day 2 onward.

### Input Format (DFD JSON)
```json
{
  "dfd_id": "service_001",
  "system_name": "Payment Processing Service",
  "nodes": [
    {
      "id": "N1",
      "type": "external_entity",
      "name": "Mobile Client",
      "description": "End user mobile application"
    },
    {
      "id": "N2",
      "type": "process",
      "name": "API Gateway",
      "description": "Entry point for all client requests"
    },
    {
      "id": "N3",
      "type": "datastore",
      "name": "User Database",
      "description": "Stores user credentials and PII"
    }
  ],
  "edges": [
    {
      "id": "E1",
      "from": "N1",
      "to": "N2",
      "data_description": "Login credentials, payment requests",
      "protocol": "HTTPS",
      "authenticated": null,
      "encrypted": true
    },
    {
      "id": "E2",
      "from": "N2",
      "to": "N3",
      "data_description": "User lookup queries",
      "protocol": "TCP",
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

### Output Format (Threat Report JSON)
```json
{
  "dfd_id": "service_001",
  "system_name": "Payment Processing Service",
  "analysis_timestamp": "2025-01-01T10:00:00Z",
  "overall_risk_level": "High",
  "partial_dfd_detected": true,
  "threats": [
    {
      "threat_id": "T1",
      "stride_category": "Spoofing",
      "affected_component": "E1: Mobile Client → API Gateway",
      "threat_description": "No authentication mechanism explicitly defined on login flow",
      "missing_control": "Implement mutual authentication or OAuth 2.0 token validation",
      "confidence": "High",
      "confidence_reason": "Trust boundary crossed with null authentication field",
      "explanation": "The data flow E1 carries login credentials across the Internet Boundary (TB1) but the authenticated field is null, indicating no authentication mechanism has been specified. This creates a spoofing risk where an attacker could impersonate a legitimate client. Priority: Immediate."
    }
  ],
  "missing_controls_summary": [
    "Authentication not specified on 2 data flows",
    "Encryption not specified on internal database connection E2"
  ],
  "stride_coverage": {
    "Spoofing": 1,
    "Tampering": 0,
    "Repudiation": 1,
    "Information Disclosure": 2,
    "Denial of Service": 1,
    "Elevation of Privilege": 0
  }
}
```

---

## 7. Dataset Plan

| Dataset | Purpose | How Accessed |
|---------|---------|--------------|
| **microSecEnD** | Primary evaluation — 1000+ real microservice DFDs with ground truth | `git clone https://github.com/tuhh-softsec/microSecEnD` |
| **OWASP Threat Model Library** | Few-shot examples in prompts, knowledge base | Manual JSON conversion of key models |
| **Microsoft TMT XML** | Additional test cases, baseline comparison | From ThreatModeling-LLM paper's linked dataset |

For evaluation: 15–20 DFDs selected from microSecEnD with manually verified ground truth STRIDE labels.

---

## 8. Evaluation Plan

The system is evaluated by comparing predicted threats against ground truth labels on 15–20 labeled test DFDs.

**Metrics computed per STRIDE category:**
- **Precision** — of threats flagged, what fraction were real threats
- **Recall** — of real threats, what fraction did we find
- **F1-Score** — harmonic mean of precision and recall

**Baseline comparison:** Manual STRIDE analysis output (from microSecEnD ground truth) vs our automated output.

**Partial DFD test:** Run 5 DFDs with artificially removed trust boundaries/protocol info. Show the system still produces calibrated, useful output with lower confidence scores. This demonstrates our novel contribution.

---

## 9. Tech Stack Summary

| Component | Technology | Cost |
|-----------|-----------|------|
| Language | Python 3.10+ | Free |
| LLM | Google Gemini 1.5 Flash API | Free (aistudio.google.com) |
| DFD Parsing | Python json stdlib | Free |
| Prompt Engineering | Manual few-shot templates | Free |
| Evaluation | scikit-learn, pandas | Free |
| Demo UI | Streamlit | Free |
| Colab Tunneling | pyngrok | Free |
| Version Control | GitHub | Free |
| Notebook Environment | Google Colab | Free |

**Total project cost: $0**

---

## 10. Repository Structure

```
SecureByDesign/
│
├── pipeline/                  ← Person A owns
│   ├── dfd_parser.py          # Parse DFD JSON into structured context
│   ├── prompt_templates.py    # All few-shot prompt templates
│   ├── inference.py           # Main analyze_dfd() function
│   └── response_parser.py     # Parse + validate LLM JSON output
│
├── evaluation/                ← Person B owns
│   ├── test_dfds/             # 15-20 labeled DFD JSON files
│   ├── ground_truth.json      # Ground truth STRIDE labels per DFD
│   ├── evaluate.py            # Precision/recall/F1 computation
│   └── results/               # Output tables and charts
│
├── app/                       ← Person B owns
│   └── streamlit_app.py       # Full Streamlit demo UI
│
├── data/                      ← Read-only, both people
│   └── microSecEnD/           # Cloned dataset
│
├── contract.json              ← Sacred. The agreed I/O format.
├── requirements.txt
└── README.md
```

---

## 11. Timeline Overview

| Days | Person A | Person B |
|------|----------|----------|
| 1–2 | Setup + DFD parser | Dataset clone + test case prep |
| 3–5 | Prompt engineering (core work) | Ground truth labeling |
| 6–8 | Full pipeline + partial DFD handling | Evaluation script |
| 9–10 | Polish + edge cases | First evaluation run + UI build |
| 11–12 | Integration support | Streamlit demo polish |
| 13–14 | Demo dry run | PPT + README |

---

## 12. What the Final Demo Looks Like

The assessor opens a browser URL (ngrok link from Colab). They see a clean two-panel Streamlit interface:

- **Left panel:** Text area to paste a DFD JSON, text area for security context, an "Analyze" button
- **Right panel:** Threat report rendered with color-coded STRIDE badges, confidence indicators, expandable explanations per threat, and a missing controls summary at the bottom

The assessor pastes a DFD from microSecEnD, clicks Analyze, and within 3–5 seconds sees a complete threat report. Then you paste an **incomplete** version of the same DFD (trust boundaries removed) and show the system still produces useful output but with lower confidence — demonstrating the novel contribution live.

**That is the moment that wins the assessment.**
