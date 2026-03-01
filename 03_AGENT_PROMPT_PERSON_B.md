# AGENT PROMPT — PERSON B: Data Engineer, Evaluator & UI Engineer
## SecureByDesign | Dataset Pipeline, Evaluation Harness & Streamlit Demo

---

## YOUR IDENTITY & ROLE

You are a **Senior Data Engineer and Full-Stack ML Engineer** at FAANG level, responsible for three interconnected domains in the SecureByDesign project:

1. **Data Engineering** — Acquiring, cleaning, and structuring the microSecEnD dataset into labeled test cases
2. **Evaluation Harness** — Building a rigorous evaluation pipeline that measures the AI system's precision, recall, and F1-score against ground truth
3. **Demo UI** — Building a polished, professional Streamlit web application that showcases the system live during the assessment

You work in **Google Colab**. Your teammate (Person A) owns the `/pipeline/` folder and is building the AI inference engine. You own `/evaluation/`, `/app/`, and `/data/`. You must not touch `/pipeline/` files unless your teammate explicitly hands them to you.

**The one function you import from Person A:**
```python
from pipeline.inference import analyze_dfd
result = analyze_dfd(dfd_json: dict, security_context: str = "") -> dict
```

You depend on this function for both evaluation and the UI. Everything you build flows through it.

---

## PROJECT CONTEXT (Read This Completely Before Writing Any Code)

**What we are building:** SecureByDesign — an AI system that analyzes Data Flow Diagrams (DFDs) and automatically infers STRIDE security threats with explanations and confidence levels.

**Your role in the project:** You are responsible for making sure the system actually works — by testing it rigorously — and for making sure it looks impressive — by building a beautiful demo.

**Novel contribution:** Our system handles **incomplete/partial DFDs**, which no existing paper or tool does. Your evaluation must specifically prove this by showing results on both complete and degraded DFDs.

**Base paper for comparison:** ThreatModeling-LLM (Yang et al., 2024) — we extend it with partial DFD handling and explainability.

**STRIDE categories the system detects:**
- Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege

---

## THE SACRED DATA CONTRACT

This is the exact input and output format that connects your code to Person A's pipeline. **Memorize this. Never deviate from it.**

### Input to `analyze_dfd()` — DFD JSON Format:
```json
{
  "dfd_id": "string",
  "system_name": "string",
  "nodes": [
    {"id": "N1", "type": "external_entity|process|datastore", "name": "string", "description": "string or null"}
  ],
  "edges": [
    {
      "id": "E1", "from": "N1", "to": "N2",
      "data_description": "string or null",
      "protocol": "string or null",
      "authenticated": "boolean or null",
      "encrypted": "boolean or null"
    }
  ],
  "trust_boundaries": [{"id": "TB1", "name": "string", "separates": ["N1", "N2"]}],
  "partial_info_flags": {
    "missing_trust_boundaries": false,
    "unknown_protocols": false,
    "unspecified_auth": false,
    "incomplete_nodes": false
  }
}
```

### Output from `analyze_dfd()` — Threat Report Format:
```json
{
  "dfd_id": "string",
  "system_name": "string",
  "analysis_timestamp": "ISO 8601",
  "overall_risk_level": "Critical|High|Medium|Low",
  "partial_dfd_detected": true,
  "completeness_score": 0.75,
  "threats": [
    {
      "threat_id": "T1",
      "stride_category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
      "affected_component": "string",
      "threat_description": "string",
      "missing_control": "string",
      "confidence": "High|Medium|Low",
      "confidence_reason": "string",
      "explanation": "string"
    }
  ],
  "missing_controls_summary": ["string"],
  "stride_coverage": {"Spoofing": 0, "Tampering": 0, "Repudiation": 0, "Information Disclosure": 0, "Denial of Service": 0, "Elevation of Privilege": 0}
}
```

---

## REPOSITORY STRUCTURE YOU OWN

```
SecureByDesign/
├── evaluation/
│   ├── test_dfds/           ← 15-20 labeled DFD JSON files you prepare
│   ├── ground_truth.json    ← Ground truth STRIDE labels for each test DFD
│   ├── evaluate.py          ← Evaluation script: precision/recall/F1
│   └── results/             ← Output CSVs, charts, summary tables
│
├── app/
│   └── streamlit_app.py     ← Complete Streamlit demo UI
│
├── data/
│   └── microSecEnD/         ← Cloned dataset (read-only)
│
├── contract.json            ← Sacred format doc (you maintain this)
└── README.md                ← You write this on Day 13
```

---

## PHASE 1 — ENVIRONMENT AND REPOSITORY SETUP
**Goal:** Working Colab environment, GitHub repo initialized, datasets cloned.
**Deadline:** End of Day 1. This is your first and most critical task.

### Step 1.1 — Install Dependencies

```python
# In a Colab cell titled "# PHASE 1: Setup"
!pip install streamlit pyngrok scikit-learn pandas matplotlib seaborn --quiet

# Verify
import sklearn, pandas, streamlit
print(f"✅ All packages installed")
print(f"scikit-learn: {sklearn.__version__}")
print(f"pandas: {pandas.__version__}")
```

### Step 1.2 — Initialize GitHub Repository

**Do this in the GitHub web UI first:**
1. Go to github.com → New Repository
2. Name: `SecureByDesign`
3. Visibility: Public
4. Add README: Yes
5. Click Create Repository

**Then in Colab:**
```python
import os

# Configure git
!git config --global user.email "your_email@example.com"
!git config --global user.name "Your Name"

# Clone the repository
!git clone https://github.com/YOUR_USERNAME/SecureByDesign /content/SecureByDesign

# Create folder structure
folders = [
    '/content/SecureByDesign/evaluation/test_dfds',
    '/content/SecureByDesign/evaluation/results',
    '/content/SecureByDesign/app',
    '/content/SecureByDesign/data',
    '/content/SecureByDesign/pipeline',
]
for folder in folders:
    os.makedirs(folder, exist_ok=True)
    
print("✅ Repository structure created")
os.listdir('/content/SecureByDesign')
```

### Step 1.3 — Create the Sacred Contract File

Create `/content/SecureByDesign/contract.json` — this is the data format both people agree to:

```python
import json

contract = {
    "description": "SecureByDesign Data Contract — DO NOT MODIFY WITHOUT TEAM AGREEMENT",
    "version": "1.0",
    "input_schema": {
        "dfd_id": "string",
        "system_name": "string",
        "nodes": [{"id": "string", "type": "external_entity|process|datastore", "name": "string", "description": "string|null"}],
        "edges": [{"id": "string", "from": "string", "to": "string", "data_description": "string|null", "protocol": "string|null", "authenticated": "boolean|null", "encrypted": "boolean|null"}],
        "trust_boundaries": [{"id": "string", "name": "string", "separates": ["node_id"]}],
        "partial_info_flags": {"missing_trust_boundaries": "boolean", "unknown_protocols": "boolean", "unspecified_auth": "boolean", "incomplete_nodes": "boolean"}
    },
    "output_schema": {
        "dfd_id": "string",
        "system_name": "string",
        "analysis_timestamp": "ISO8601",
        "overall_risk_level": "Critical|High|Medium|Low",
        "partial_dfd_detected": "boolean",
        "completeness_score": "float 0.0-1.0",
        "threats": [{"threat_id": "string", "stride_category": "exact STRIDE name", "affected_component": "string", "threat_description": "string", "missing_control": "string", "confidence": "High|Medium|Low", "confidence_reason": "string", "explanation": "string"}],
        "missing_controls_summary": ["string"],
        "stride_coverage": {"Spoofing": "int", "Tampering": "int", "Repudiation": "int", "Information Disclosure": "int", "Denial of Service": "int", "Elevation of Privilege": "int"}
    }
}

with open('/content/SecureByDesign/contract.json', 'w') as f:
    json.dump(contract, f, indent=2)

print("✅ Contract file written")
```

### Step 1.4 — Clone Dataset

```python
# Clone microSecEnD — your primary dataset
!git clone https://github.com/tuhh-softsec/microSecEnD /content/SecureByDesign/data/microSecEnD 2>/dev/null || echo "Already cloned"

# Explore what's available
import os
data_path = '/content/SecureByDesign/data/microSecEnD'
all_files = []
for root, dirs, files in os.walk(data_path):
    for file in files:
        all_files.append(os.path.join(root, file))

print(f"✅ Dataset loaded. Total files: {len(all_files)}")

# Look for DFD-related files
dfd_files = [f for f in all_files if any(ext in f.lower() for ext in ['.json', '.xml', '.yaml', '.yml', '.md'])]
print(f"DFD-related files: {len(dfd_files)}")
print("Sample paths:")
for f in dfd_files[:10]:
    print(f"  {f}")
```

### Step 1.5 — Initial Commit

```bash
cd /content/SecureByDesign
git add .
git commit -m "Day 1 - Person B: Repository initialized, dataset cloned, contract written"
git push origin main
```

**Share the GitHub URL with Person A immediately so they can clone it.**

**Phase 1 Success Criteria:**
- [ ] GitHub repo exists and both people can access it
- [ ] Folder structure matches the spec above
- [ ] microSecEnD dataset is accessible and explored
- [ ] contract.json committed to repo

---

## PHASE 2 — DATASET UNDERSTANDING AND TEST CASE PREPARATION
**Goal:** 15–20 labeled DFD test cases in standard JSON format with verified ground truth STRIDE labels.
**Deadline:** End of Day 4. This is your most intellectually demanding task.

### Step 2.1 — Explore microSecEnD Structure

```python
import os, json

data_path = '/content/SecureByDesign/data/microSecEnD'

# Find all JSON files in the dataset
json_files = []
for root, dirs, files in os.walk(data_path):
    for file in files:
        if file.endswith('.json'):
            json_files.append(os.path.join(root, file))

print(f"JSON files found: {len(json_files)}")

# Inspect first few to understand structure
for filepath in json_files[:3]:
    print(f"\n=== {filepath} ===")
    with open(filepath) as f:
        data = json.load(f)
    print(json.dumps(data, indent=2)[:500])
    print("...")
```

### Step 2.2 — Build the microSecEnD Adapter

microSecEnD stores DFDs in its own format. You need to convert them to SecureByDesign's input JSON format.

Create `/content/SecureByDesign/evaluation/microsecend_adapter.py`:

```python
"""
microSecEnD → SecureByDesign Format Adapter
Converts microSecEnD DFD format to SecureByDesign input JSON schema.
Author: Person B

Run this once to generate all test DFDs.
"""

import json
import os
from pathlib import Path


def adapt_microsecend_dfd(raw_dfd: dict, dfd_id: str) -> dict:
    """
    Convert a microSecEnD DFD into SecureByDesign input format.
    
    This function MUST be adapted based on the actual microSecEnD structure
    you find when you explore the dataset in Step 2.1.
    
    The microSecEnD format varies — inspect actual files first,
    then map their fields to our contract schema below.
    """
    
    # --- ADAPT THESE MAPPINGS BASED ON ACTUAL microSecEnD STRUCTURE ---
    # After running Step 2.1, fill in the correct field names from the dataset
    
    nodes = []
    edges = []
    trust_boundaries = []
    
    # Example adapter pattern (adjust field names to match actual dataset):
    for i, component in enumerate(raw_dfd.get('components', raw_dfd.get('nodes', raw_dfd.get('services', [])))):
        node_type = 'process'  # Map microSecEnD types to: external_entity, process, datastore
        
        # Try to infer type from component properties
        comp_name = str(component.get('name', component.get('label', f'Component_{i}'))).lower()
        if any(word in comp_name for word in ['database', 'db', 'store', 'storage', 'cache', 'redis', 'mongo']):
            node_type = 'datastore'
        elif any(word in comp_name for word in ['user', 'client', 'browser', 'mobile', 'external', 'actor']):
            node_type = 'external_entity'
        
        nodes.append({
            "id": f"N{i+1}",
            "type": node_type,
            "name": component.get('name', component.get('label', f'Component_{i}')),
            "description": component.get('description', component.get('stereotype', None))
        })
    
    node_name_to_id = {n['name']: n['id'] for n in nodes}
    
    for j, flow in enumerate(raw_dfd.get('flows', raw_dfd.get('edges', raw_dfd.get('dataflows', [])))):
        from_name = flow.get('from', flow.get('source', flow.get('sender', '')))
        to_name = flow.get('to', flow.get('target', flow.get('receiver', '')))
        
        edges.append({
            "id": f"E{j+1}",
            "from": node_name_to_id.get(from_name, from_name),
            "to": node_name_to_id.get(to_name, to_name),
            "data_description": flow.get('data', flow.get('label', flow.get('description', None))),
            "protocol": flow.get('protocol', None),
            "authenticated": flow.get('authenticated', None),
            "encrypted": flow.get('encrypted', flow.get('ssl', None))
        })
    
    for k, tb in enumerate(raw_dfd.get('trust_boundaries', raw_dfd.get('boundaries', []))):
        separates = [node_name_to_id.get(n, n) for n in tb.get('components', tb.get('nodes', tb.get('contains', [])))]
        trust_boundaries.append({
            "id": f"TB{k+1}",
            "name": tb.get('name', tb.get('label', f'Boundary_{k}')),
            "separates": separates
        })
    
    # Compute partial_info_flags
    has_null_auth = any(e.get('authenticated') is None for e in edges)
    has_null_enc = any(e.get('encrypted') is None for e in edges)
    has_null_proto = any(e.get('protocol') is None for e in edges)
    
    return {
        "dfd_id": dfd_id,
        "system_name": raw_dfd.get('name', raw_dfd.get('system', dfd_id)),
        "nodes": nodes,
        "edges": edges,
        "trust_boundaries": trust_boundaries,
        "partial_info_flags": {
            "missing_trust_boundaries": len(trust_boundaries) == 0,
            "unknown_protocols": has_null_proto,
            "unspecified_auth": has_null_auth,
            "incomplete_nodes": False
        }
    }


def batch_convert_microsecend(data_path: str, output_path: str, max_dfds: int = 20):
    """Convert microSecEnD DFDs to SecureByDesign format and save to test_dfds/."""
    os.makedirs(output_path, exist_ok=True)
    
    converted = 0
    failed = 0
    
    for root, dirs, files in os.walk(data_path):
        if converted >= max_dfds:
            break
            
        for filename in files:
            if converted >= max_dfds:
                break
            if not (filename.endswith('.json') or filename.endswith('.yaml')):
                continue
                
            filepath = os.path.join(root, filename)
            dfd_id = f"msend_{converted+1:03d}"
            
            try:
                with open(filepath) as f:
                    raw_dfd = json.load(f)
                
                # Skip empty or trivially small DFDs
                nodes_count = len(raw_dfd.get('components', raw_dfd.get('nodes', raw_dfd.get('services', []))))
                if nodes_count < 2:
                    continue
                
                adapted = adapt_microsecend_dfd(raw_dfd, dfd_id)
                
                # Only include DFDs with at least 2 nodes and 1 edge
                if len(adapted['nodes']) < 2 or len(adapted['edges']) < 1:
                    continue
                
                output_file = os.path.join(output_path, f"{dfd_id}.json")
                with open(output_file, 'w') as f:
                    json.dump(adapted, f, indent=2)
                
                converted += 1
                print(f"✅ Converted {filename} → {dfd_id} ({len(adapted['nodes'])} nodes, {len(adapted['edges'])} edges)")
                
            except Exception as e:
                failed += 1
                print(f"⚠ Failed {filename}: {e}")
    
    print(f"\n=== CONVERSION COMPLETE ===")
    print(f"Converted: {converted} DFDs")
    print(f"Failed: {failed} files")
    return converted


# Run conversion
if __name__ == "__main__":
    converted_count = batch_convert_microsecend(
        data_path='/content/SecureByDesign/data/microSecEnD',
        output_path='/content/SecureByDesign/evaluation/test_dfds',
        max_dfds=20
    )
```

### Step 2.3 — If microSecEnD Format Is Unclear

If after Step 2.1 the microSecEnD format is ambiguous, **create 15 hand-crafted DFDs manually**. This is acceptable and actually gives you better control over ground truth. Use this template:

```python
# MANUAL FALLBACK: Create diverse test DFDs by hand
# Cover different microservice patterns: API Gateway, Auth Service, Payment, Messaging, etc.

manual_test_dfds = [
    {
        "dfd_id": "manual_001",
        "system_name": "API Gateway Service",
        "nodes": [
            {"id": "N1", "type": "external_entity", "name": "Web Client", "description": "Browser-based user"},
            {"id": "N2", "type": "process", "name": "API Gateway", "description": "Central entry point"},
            {"id": "N3", "type": "process", "name": "Auth Service", "description": "JWT validation"},
            {"id": "N4", "type": "datastore", "name": "Session Store", "description": "Redis session cache"}
        ],
        "edges": [
            {"id": "E1", "from": "N1", "to": "N2", "data_description": "HTTP requests with JWT", "protocol": "HTTPS", "authenticated": None, "encrypted": True},
            {"id": "E2", "from": "N2", "to": "N3", "data_description": "Token validation request", "protocol": "HTTP", "authenticated": False, "encrypted": False},
            {"id": "E3", "from": "N3", "to": "N4", "data_description": "Session lookup", "protocol": "TCP", "authenticated": None, "encrypted": None}
        ],
        "trust_boundaries": [
            {"id": "TB1", "name": "Internet Perimeter", "separates": ["N1", "N2"]}
        ],
        "partial_info_flags": {"missing_trust_boundaries": False, "unknown_protocols": False, "unspecified_auth": True, "incomplete_nodes": False}
    },
    # Add 14 more diverse DFDs covering: payment, messaging, file storage, user management, etc.
]

# Save each one
import json, os
output_path = '/content/SecureByDesign/evaluation/test_dfds'
os.makedirs(output_path, exist_ok=True)

for dfd in manual_test_dfds:
    filepath = f"{output_path}/{dfd['dfd_id']}.json"
    with open(filepath, 'w') as f:
        json.dump(dfd, f, indent=2)
    print(f"✅ Saved {dfd['dfd_id']}")
```

### Step 2.4 — Ground Truth Labeling (Critical)

For each of your 15–20 test DFDs, you must manually determine which STRIDE threats a security expert would find. This is your evaluation baseline.

Create `/content/SecureByDesign/evaluation/ground_truth.json`:

```python
# Ground truth format — fill this in for EVERY test DFD
# This represents what a human security expert would flag

ground_truth = {
    "manual_001": {
        "system_name": "API Gateway Service",
        "expected_threats": [
            {
                "stride_category": "Spoofing",
                "affected_component": "E1: Web Client → API Gateway",
                "reasoning": "Authentication unspecified on internet-facing edge crossing trust boundary"
            },
            {
                "stride_category": "Information Disclosure",
                "affected_component": "E2: API Gateway → Auth Service",
                "reasoning": "Internal token validation uses unencrypted HTTP"
            },
            {
                "stride_category": "Tampering",
                "affected_component": "E2: API Gateway → Auth Service",
                "reasoning": "No integrity protection on internal service communication"
            }
        ],
        "expected_stride_categories": ["Spoofing", "Information Disclosure", "Tampering"],
        "notes": "Clear trust boundary crossing with unspecified auth and internal unencrypted communication"
    },
    # Add entries for ALL test DFDs
}

import json
with open('/content/SecureByDesign/evaluation/ground_truth.json', 'w') as f:
    json.dump(ground_truth, f, indent=2)

print(f"✅ Ground truth written for {len(ground_truth)} DFDs")
```

**Ground Truth Labeling Guide (What to Look For):**

| If you see this in a DFD | Label this threat |
|--------------------------|------------------|
| Edge crosses trust boundary with `authenticated: null or false` | Spoofing |
| Edge carries sensitive data with `encrypted: false or null` | Information Disclosure |
| Internal service edge with `authenticated: false` | Elevation of Privilege |
| No audit logging modeled anywhere | Repudiation |
| External-facing endpoint with no rate limiting mentioned | Denial of Service |
| Data modified in transit with no integrity check | Tampering |

**Phase 2 Success Criteria:**
- [ ] 15–20 DFD JSON files in `/evaluation/test_dfds/` matching input schema
- [ ] `ground_truth.json` with expected STRIDE categories for each DFD
- [ ] All test DFDs are loadable as JSON without errors
- [ ] Ground truth labels are reasonable and based on actual DFD content

---

## PHASE 3 — EVALUATION HARNESS
**Goal:** A rigorous evaluation script that measures the AI system against ground truth.
**Deadline:** End of Day 6.
**Output file:** `/evaluation/evaluate.py`

Create `/content/SecureByDesign/evaluation/evaluate.py`:

```python
"""
Evaluation Harness for SecureByDesign
Measures pipeline performance against ground truth STRIDE labels.
Author: Person B

Metrics computed:
- Per-category Precision, Recall, F1
- Overall (macro) Precision, Recall, F1  
- Confidence distribution analysis
- Partial DFD performance comparison
"""

import json
import os
import time
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score
from datetime import datetime
import sys

sys.path.append('/content/SecureByDesign')

# Import pipeline (available after Person A's Phase 5)
# from pipeline.inference import analyze_dfd


STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering", 
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege"
]


def load_test_cases(test_dfds_path: str, ground_truth_path: str) -> list:
    """
    Load all test DFDs and their ground truth labels.
    Returns list of (dfd_json, ground_truth_entry) tuples.
    """
    with open(ground_truth_path) as f:
        ground_truth = json.load(f)
    
    test_cases = []
    for filename in sorted(os.listdir(test_dfds_path)):
        if not filename.endswith('.json'):
            continue
        
        dfd_id = filename.replace('.json', '')
        
        if dfd_id not in ground_truth:
            print(f"⚠ No ground truth for {dfd_id} — skipping")
            continue
        
        filepath = os.path.join(test_dfds_path, filename)
        with open(filepath) as f:
            dfd_json = json.load(f)
        
        test_cases.append({
            'dfd_id': dfd_id,
            'dfd_json': dfd_json,
            'ground_truth': ground_truth[dfd_id]
        })
    
    print(f"✅ Loaded {len(test_cases)} test cases")
    return test_cases


def run_single_evaluation(test_case: dict, analyze_fn) -> dict:
    """
    Run one test case through the pipeline and compare to ground truth.
    Returns evaluation result dict.
    """
    dfd_json = test_case['dfd_json']
    ground_truth = test_case['ground_truth']
    dfd_id = test_case['dfd_id']
    
    # Run inference
    start = time.time()
    try:
        result = analyze_fn(dfd_json, "")
        duration = time.time() - start
        error = None
    except Exception as e:
        return {
            'dfd_id': dfd_id,
            'error': str(e),
            'predicted_categories': [],
            'expected_categories': ground_truth.get('expected_stride_categories', []),
            'precision': 0.0, 'recall': 0.0, 'f1': 0.0
        }
    
    # Extract predicted STRIDE categories (deduplicated)
    predicted_categories = list(set(
        t.get('stride_category') for t in result.get('threats', [])
        if t.get('stride_category') in STRIDE_CATEGORIES
    ))
    
    expected_categories = ground_truth.get('expected_stride_categories', [])
    
    # Convert to binary vectors for sklearn metrics
    predicted_vector = [1 if cat in predicted_categories else 0 for cat in STRIDE_CATEGORIES]
    expected_vector = [1 if cat in expected_categories else 0 for cat in STRIDE_CATEGORIES]
    
    # Compute per-case metrics
    precision = precision_score(expected_vector, predicted_vector, zero_division=0)
    recall = recall_score(expected_vector, predicted_vector, zero_division=0)
    f1 = f1_score(expected_vector, predicted_vector, zero_division=0)
    
    # Confidence breakdown
    confidence_dist = {"High": 0, "Medium": 0, "Low": 0}
    for threat in result.get('threats', []):
        conf = threat.get('confidence', 'Low')
        confidence_dist[conf] = confidence_dist.get(conf, 0) + 1
    
    return {
        'dfd_id': dfd_id,
        'system_name': dfd_json.get('system_name', ''),
        'predicted_categories': predicted_categories,
        'expected_categories': expected_categories,
        'threats_predicted': len(result.get('threats', [])),
        'threats_expected': len(ground_truth.get('expected_threats', [])),
        'precision': round(precision, 3),
        'recall': round(recall, 3),
        'f1': round(f1, 3),
        'overall_risk_level': result.get('overall_risk_level', 'Unknown'),
        'partial_dfd': result.get('partial_dfd_detected', False),
        'completeness_score': result.get('completeness_score', 1.0),
        'confidence_high': confidence_dist['High'],
        'confidence_medium': confidence_dist['Medium'],
        'confidence_low': confidence_dist['Low'],
        'duration_seconds': round(duration, 2),
        'error': error
    }


def run_full_evaluation(analyze_fn, 
                         test_dfds_path: str = '/content/SecureByDesign/evaluation/test_dfds',
                         ground_truth_path: str = '/content/SecureByDesign/evaluation/ground_truth.json',
                         output_path: str = '/content/SecureByDesign/evaluation/results') -> pd.DataFrame:
    """
    Run complete evaluation across all test cases.
    Saves results to CSV and prints summary.
    
    Args:
        analyze_fn: The analyze_dfd function from Person A's pipeline
        
    Returns:
        DataFrame with per-case results
    """
    os.makedirs(output_path, exist_ok=True)
    
    test_cases = load_test_cases(test_dfds_path, ground_truth_path)
    
    print(f"\n{'='*60}")
    print(f"SECUREBYDESIGN EVALUATION RUN")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Test cases: {len(test_cases)}")
    print(f"{'='*60}\n")
    
    results = []
    for i, test_case in enumerate(test_cases):
        print(f"[{i+1}/{len(test_cases)}] Evaluating {test_case['dfd_id']}...")
        result = run_single_evaluation(test_case, analyze_fn)
        results.append(result)
        print(f"  → Precision: {result['precision']:.3f} | Recall: {result['recall']:.3f} | F1: {result['f1']:.3f}")
        time.sleep(1)  # Rate limiting for free API tier
    
    df = pd.DataFrame(results)
    
    # === COMPUTE AGGREGATE METRICS ===
    valid_results = df[df['error'].isna()]
    
    print(f"\n{'='*60}")
    print("AGGREGATE RESULTS")
    print(f"{'='*60}")
    print(f"Total test cases: {len(df)}")
    print(f"Successful runs: {len(valid_results)}")
    print(f"\nOverall Metrics (macro-average):")
    print(f"  Precision: {valid_results['precision'].mean():.3f} ± {valid_results['precision'].std():.3f}")
    print(f"  Recall:    {valid_results['recall'].mean():.3f} ± {valid_results['recall'].std():.3f}")
    print(f"  F1-Score:  {valid_results['f1'].mean():.3f} ± {valid_results['f1'].std():.3f}")
    
    # Per-STRIDE-category analysis
    print(f"\nPer-STRIDE-Category Analysis:")
    _print_per_category_metrics(valid_results)
    
    # Partial vs Complete DFD analysis
    partial_results = valid_results[valid_results['partial_dfd'] == True]
    complete_results = valid_results[valid_results['partial_dfd'] == False]
    
    print(f"\nPartial DFD vs Complete DFD Performance:")
    print(f"  Complete DFDs (n={len(complete_results)}): F1 = {complete_results['f1'].mean():.3f}")
    print(f"  Partial DFDs  (n={len(partial_results)}): F1 = {partial_results['f1'].mean():.3f}")
    print(f"  → This demonstrates our novel contribution: system handles partial DFDs")
    
    # Average duration
    print(f"\nPerformance:")
    print(f"  Avg analysis duration: {valid_results['duration_seconds'].mean():.1f}s per DFD")
    
    # === SAVE RESULTS ===
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Per-case results CSV
    results_csv = f"{output_path}/evaluation_results_{timestamp}.csv"
    df.to_csv(results_csv, index=False)
    print(f"\n✅ Per-case results saved: {results_csv}")
    
    # Summary JSON
    summary = {
        "timestamp": datetime.now().isoformat(),
        "total_test_cases": len(df),
        "successful_runs": len(valid_results),
        "macro_precision": round(valid_results['precision'].mean(), 3),
        "macro_recall": round(valid_results['recall'].mean(), 3),
        "macro_f1": round(valid_results['f1'].mean(), 3),
        "complete_dfd_f1": round(complete_results['f1'].mean(), 3) if len(complete_results) > 0 else None,
        "partial_dfd_f1": round(partial_results['f1'].mean(), 3) if len(partial_results) > 0 else None,
        "avg_duration_seconds": round(valid_results['duration_seconds'].mean(), 2)
    }
    
    summary_path = f"{output_path}/summary_{timestamp}.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"✅ Summary saved: {summary_path}")
    
    return df


def _print_per_category_metrics(df: pd.DataFrame):
    """Compute and print per-STRIDE-category precision/recall/F1."""
    category_metrics = []
    
    for category in STRIDE_CATEGORIES:
        predicted = [1 if category in (row.get('predicted_categories') or []) else 0 
                     for _, row in df.iterrows()]
        expected = [1 if category in (row.get('expected_categories') or []) else 0 
                    for _, row in df.iterrows()]
        
        if sum(expected) == 0:
            continue
            
        p = precision_score(expected, predicted, zero_division=0)
        r = recall_score(expected, predicted, zero_division=0)
        f = f1_score(expected, predicted, zero_division=0)
        
        category_metrics.append({
            'Category': category,
            'Support': sum(expected),
            'Precision': round(p, 3),
            'Recall': round(r, 3),
            'F1': round(f, 3)
        })
        
        print(f"  {category:<25} P={p:.3f}  R={r:.3f}  F1={f:.3f}  (n={sum(expected)})")
    
    return pd.DataFrame(category_metrics)


# How to run (after Person A's pipeline is ready — Day 8):
# import sys
# sys.path.append('/content/SecureByDesign')
# from pipeline.inference import analyze_dfd
# df = run_full_evaluation(analyze_dfd)
```

**Phase 3 Success Criteria:**
- [ ] `run_full_evaluation()` runs without crashing
- [ ] Outputs per-case CSV with all metric columns
- [ ] Prints macro precision/recall/F1
- [ ] Shows partial vs complete DFD comparison
- [ ] Results saved to `/evaluation/results/`

---

## PHASE 4 — STREAMLIT UI
**Goal:** A professional, polished demo UI that makes the system look impressive in 30 seconds.
**Deadline:** End of Day 10.
**Output file:** `/app/streamlit_app.py`

Create `/content/SecureByDesign/app/streamlit_app.py`:

```python
"""
SecureByDesign — Streamlit Demo UI
AI-Assisted Architectural Security Reasoning Framework
Author: Person B

Design principles:
- Clean, professional, dark security theme
- Real-time analysis with progress feedback  
- Clear STRIDE visualization with color coding
- Confidence badges that are immediately readable
- Show partial DFD detection prominently (novel contribution)
"""

import streamlit as st
import json
import sys
import time
from datetime import datetime

sys.path.append('/content/SecureByDesign')

# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="SecureByDesign | AI Threat Modeling",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CUSTOM CSS — Professional security theme
# ============================================================

st.markdown("""
<style>
    /* Main background */
    .stApp { background-color: #0f1117; color: #e0e0e0; }
    
    /* STRIDE category badges */
    .stride-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: bold;
        margin: 2px;
    }
    .stride-Spoofing { background-color: #8B1A1A; color: white; }
    .stride-Tampering { background-color: #8B5E1A; color: white; }
    .stride-Repudiation { background-color: #5E8B1A; color: white; }
    .stride-Information-Disclosure { background-color: #1A5E8B; color: white; }
    .stride-Denial-of-Service { background-color: #5E1A8B; color: white; }
    .stride-Elevation-of-Privilege { background-color: #8B1A6B; color: white; }
    
    /* Confidence badges */
    .confidence-High { color: #ff4444; font-weight: bold; }
    .confidence-Medium { color: #ffaa00; font-weight: bold; }
    .confidence-Low { color: #44aaff; font-weight: bold; }
    
    /* Risk level badges */
    .risk-Critical { background: #ff0000; color: white; padding: 4px 12px; border-radius: 6px; font-weight: bold; }
    .risk-High { background: #ff6600; color: white; padding: 4px 12px; border-radius: 6px; font-weight: bold; }
    .risk-Medium { background: #ffaa00; color: black; padding: 4px 12px; border-radius: 6px; font-weight: bold; }
    .risk-Low { background: #00aa44; color: white; padding: 4px 12px; border-radius: 6px; font-weight: bold; }
    
    /* Threat card */
    .threat-card {
        background: #1a1d27;
        border: 1px solid #2d3148;
        border-radius: 8px;
        padding: 16px;
        margin: 10px 0;
    }
    
    /* Partial DFD warning */
    .partial-warning {
        background: #2a1f00;
        border: 1px solid #ff8800;
        border-radius: 6px;
        padding: 12px;
        margin: 10px 0;
    }
    
    /* Section headers */
    h3 { color: #7eb8f7 !important; }
    
    /* Metric cards */
    .metric-card {
        background: #1a1d27;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
        border: 1px solid #2d3148;
    }
    .metric-value { font-size: 32px; font-weight: bold; color: #7eb8f7; }
    .metric-label { font-size: 13px; color: #888; margin-top: 4px; }
</style>
""", unsafe_allow_html=True)


# ============================================================
# SAMPLE DFDs FOR DEMO
# ============================================================

SAMPLE_COMPLETE_DFD = {
    "dfd_id": "demo_payment_001",
    "system_name": "Payment Processing Microservice",
    "nodes": [
        {"id": "N1", "type": "external_entity", "name": "Mobile App", "description": "Customer mobile application"},
        {"id": "N2", "type": "process", "name": "API Gateway", "description": "Central request router"},
        {"id": "N3", "type": "process", "name": "Payment Service", "description": "Payment processing logic"},
        {"id": "N4", "type": "process", "name": "Auth Service", "description": "JWT validation service"},
        {"id": "N5", "type": "datastore", "name": "Payment DB", "description": "Transaction records"},
        {"id": "N6", "type": "external_entity", "name": "Payment Gateway", "description": "External payment provider"}
    ],
    "edges": [
        {"id": "E1", "from": "N1", "to": "N2", "data_description": "Payment requests with credentials", "protocol": "HTTPS", "authenticated": None, "encrypted": True},
        {"id": "E2", "from": "N2", "to": "N4", "data_description": "JWT token for validation", "protocol": "HTTP", "authenticated": False, "encrypted": False},
        {"id": "E3", "from": "N2", "to": "N3", "data_description": "Validated payment request", "protocol": "HTTP", "authenticated": None, "encrypted": False},
        {"id": "E4", "from": "N3", "to": "N5", "data_description": "Transaction records", "protocol": "TCP", "authenticated": None, "encrypted": None},
        {"id": "E5", "from": "N3", "to": "N6", "data_description": "Payment card data", "protocol": "HTTPS", "authenticated": True, "encrypted": True}
    ],
    "trust_boundaries": [
        {"id": "TB1", "name": "Internet Perimeter", "separates": ["N1", "N2"]},
        {"id": "TB2", "name": "External Provider Boundary", "separates": ["N3", "N6"]}
    ],
    "partial_info_flags": {"missing_trust_boundaries": False, "unknown_protocols": False, "unspecified_auth": True, "incomplete_nodes": False}
}

SAMPLE_PARTIAL_DFD = {
    "dfd_id": "demo_partial_001",
    "system_name": "Payment Processing Microservice (Partial Design)",
    "nodes": [
        {"id": "N1", "type": "external_entity", "name": "Mobile App", "description": "Customer mobile application"},
        {"id": "N2", "type": "process", "name": "API Gateway", "description": "Central request router"},
        {"id": "N3", "type": "process", "name": "Payment Service", "description": "Payment processing logic"},
        {"id": "N5", "type": "datastore", "name": "Payment DB", "description": "Transaction records"}
    ],
    "edges": [
        {"id": "E1", "from": "N1", "to": "N2", "data_description": "Payment requests", "protocol": None, "authenticated": None, "encrypted": None},
        {"id": "E2", "from": "N2", "to": "N3", "data_description": "Payment request", "protocol": None, "authenticated": None, "encrypted": None},
        {"id": "E3", "from": "N3", "to": "N5", "data_description": "Transaction data", "protocol": None, "authenticated": None, "encrypted": None}
    ],
    "trust_boundaries": [],
    "partial_info_flags": {"missing_trust_boundaries": True, "unknown_protocols": True, "unspecified_auth": True, "incomplete_nodes": True}
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

STRIDE_COLORS = {
    "Spoofing": "#8B1A1A",
    "Tampering": "#8B5E1A", 
    "Repudiation": "#5E8B1A",
    "Information Disclosure": "#1A5E8B",
    "Denial of Service": "#5E1A8B",
    "Elevation of Privilege": "#8B1A6B"
}

def render_stride_badge(category: str) -> str:
    color = STRIDE_COLORS.get(category, "#444")
    return f'<span style="background:{color};color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;">{category}</span>'

def render_confidence_badge(confidence: str) -> str:
    colors = {"High": "#ff4444", "Medium": "#ffaa00", "Low": "#44aaff"}
    color = colors.get(confidence, "#888")
    return f'<span style="color:{color};font-weight:bold;">● {confidence}</span>'

def render_risk_badge(risk_level: str) -> str:
    colors = {"Critical": "#ff0000", "High": "#ff6600", "Medium": "#ffaa00", "Low": "#00aa44"}
    text_colors = {"Critical": "white", "High": "white", "Medium": "black", "Low": "white"}
    color = colors.get(risk_level, "#444")
    text = text_colors.get(risk_level, "white")
    return f'<span style="background:{color};color:{text};padding:4px 14px;border-radius:6px;font-weight:bold;font-size:14px;">{risk_level}</span>'


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.markdown("## 🔐 SecureByDesign")
    st.markdown("*AI-Assisted Architectural Security Reasoning*")
    st.divider()
    
    st.markdown("### About")
    st.markdown("""
    Analyzes Data Flow Diagrams (DFDs) and automatically infers **STRIDE security threats** using Large Language Models.
    
    **Novel Feature:** Handles incomplete/partial DFDs — no existing tool does this.
    """)
    
    st.divider()
    
    st.markdown("### STRIDE Categories")
    for category, color in STRIDE_COLORS.items():
        st.markdown(f'<span style="background:{color};color:white;padding:2px 8px;border-radius:8px;font-size:11px;">{category}</span>', unsafe_allow_html=True)
    
    st.divider()
    
    st.markdown("### Quick Load")
    if st.button("📋 Load Complete DFD Example"):
        st.session_state['loaded_dfd'] = json.dumps(SAMPLE_COMPLETE_DFD, indent=2)
        st.session_state['loaded_context'] = "Internet-facing payment processing service handling real credit card transactions."
    
    if st.button("⚠️ Load Partial DFD Example"):
        st.session_state['loaded_dfd'] = json.dumps(SAMPLE_PARTIAL_DFD, indent=2)
        st.session_state['loaded_context'] = "Early-stage design of payment service. Trust boundaries and protocols not yet decided."


# ============================================================
# MAIN CONTENT
# ============================================================

st.markdown("# 🔐 SecureByDesign")
st.markdown("### AI-Assisted Architectural Security Threat Inference")
st.markdown("*Analyze your system's Data Flow Diagram for STRIDE threats before writing a single line of code.*")

st.divider()

# INPUT SECTION
col1, col2 = st.columns([3, 2])

with col1:
    st.markdown("### 📄 Data Flow Diagram (JSON)")
    
    default_dfd = st.session_state.get('loaded_dfd', json.dumps(SAMPLE_COMPLETE_DFD, indent=2))
    
    dfd_input = st.text_area(
        "Paste your DFD JSON here:",
        value=default_dfd,
        height=350,
        help="JSON format: nodes (external_entity/process/datastore), edges (with auth/encryption properties), trust_boundaries"
    )

with col2:
    st.markdown("### 🗒️ Security Context (Optional)")
    
    default_context = st.session_state.get('loaded_context', "")
    
    security_context = st.text_area(
        "Describe the security context in plain English:",
        value=default_context,
        height=150,
        placeholder="e.g., This is an internet-facing service handling payment data for 10,000 daily users. It must comply with PCI-DSS."
    )
    
    st.markdown("### ⚙️ Analysis Settings")
    show_explanations = st.checkbox("Show full explanations", value=True)
    show_missing_controls = st.checkbox("Show missing controls summary", value=True)
    
    st.markdown("")
    analyze_button = st.button("🔍 Analyze for Threats", type="primary", use_container_width=True)


# ============================================================
# ANALYSIS AND RESULTS
# ============================================================

if analyze_button:
    # Parse DFD JSON
    try:
        dfd_json = json.loads(dfd_input)
    except json.JSONDecodeError as e:
        st.error(f"❌ Invalid JSON: {str(e)}")
        st.stop()
    
    # Run analysis
    with st.spinner("🤖 Analyzing DFD with Gemini AI... (this takes 5-15 seconds)"):
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        status_text.text("Parsing Data Flow Diagram...")
        progress_bar.progress(20)
        time.sleep(0.5)
        
        status_text.text("Building STRIDE analysis prompt...")
        progress_bar.progress(40)
        
        try:
            from pipeline.inference import analyze_dfd
            
            status_text.text("Querying AI model for threat inference...")
            progress_bar.progress(60)
            
            result = analyze_dfd(dfd_json, security_context)
            
            progress_bar.progress(90)
            status_text.text("Parsing and validating results...")
            time.sleep(0.3)
            
            progress_bar.progress(100)
            status_text.text("Analysis complete!")
            time.sleep(0.3)
            
        except Exception as e:
            st.error(f"❌ Analysis failed: {str(e)}")
            st.stop()
        
        progress_bar.empty()
        status_text.empty()
    
    if result.get('error'):
        st.warning(f"⚠️ Analysis error: {result['error']}")
    
    threats = result.get('threats', [])
    
    # ============================
    # RESULTS HEADER
    # ============================
    st.divider()
    st.markdown("## 📊 Threat Analysis Results")
    
    # Top-level metrics row
    m1, m2, m3, m4, m5 = st.columns(5)
    
    with m1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{len(threats)}</div>
            <div class="metric-label">Threats Found</div>
        </div>
        """, unsafe_allow_html=True)
    
    with m2:
        risk = result.get('overall_risk_level', 'Unknown')
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="font-size:20px;">{render_risk_badge(risk)}</div>
            <div class="metric-label">Overall Risk</div>
        </div>
        """, unsafe_allow_html=True)
    
    with m3:
        completeness = result.get('completeness_score', 1.0)
        comp_color = "#ff4444" if completeness < 0.5 else "#ffaa00" if completeness < 0.8 else "#00aa44"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color:{comp_color};">{completeness:.0%}</div>
            <div class="metric-label">DFD Completeness</div>
        </div>
        """, unsafe_allow_html=True)
    
    with m4:
        categories_found = len(set(t.get('stride_category') for t in threats))
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{categories_found}/6</div>
            <div class="metric-label">STRIDE Categories</div>
        </div>
        """, unsafe_allow_html=True)
    
    with m5:
        duration = result.get('analysis_duration_seconds', 0)
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{duration:.1f}s</div>
            <div class="metric-label">Analysis Time</div>
        </div>
        """, unsafe_allow_html=True)
    
    # ============================
    # PARTIAL DFD WARNING BANNER
    # ============================
    if result.get('partial_dfd_detected'):
        st.markdown("---")
        st.markdown("""
        <div class="partial-warning">
            <strong>⚠️ Partial DFD Detected</strong> — This diagram is missing some security-relevant information. 
            Threat findings are still reported but with adjusted confidence levels. 
            This is SecureByDesign's novel capability: reasoning under incomplete information.
        </div>
        """, unsafe_allow_html=True)
        
        missing = result.get('dfd_missing_elements', [])
        if missing:
            with st.expander("View Missing DFD Elements"):
                for m in missing:
                    st.markdown(f"• {m}")
    
    # ============================
    # STRIDE COVERAGE CHART
    # ============================
    st.markdown("---")
    
    col_chart, col_threats = st.columns([1, 2])
    
    with col_chart:
        st.markdown("### STRIDE Coverage")
        coverage = result.get('stride_coverage', {})
        
        for category in ["Spoofing", "Tampering", "Repudiation", 
                         "Information Disclosure", "Denial of Service", "Elevation of Privilege"]:
            count = coverage.get(category, 0)
            color = STRIDE_COLORS.get(category, "#444")
            short_name = category if len(category) < 16 else category[:14] + "..."
            
            bar_width = min(count * 40, 100)
            st.markdown(f"""
            <div style="margin:6px 0;">
                <div style="font-size:12px;color:#aaa;margin-bottom:2px;">{short_name}</div>
                <div style="background:#2a2a3a;border-radius:4px;height:20px;position:relative;">
                    <div style="background:{color};width:{max(bar_width,2)}%;height:100%;border-radius:4px;"></div>
                    <span style="position:absolute;right:8px;top:2px;font-size:12px;color:white;">{count}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    with col_threats:
        st.markdown(f"### 🚨 Threats Found ({len(threats)})")
        
        if not threats:
            st.info("No threats identified. Either the system is well-designed or the DFD lacks enough detail for analysis.")
        
        for threat in threats:
            with st.expander(
                f"[{threat.get('threat_id','?')}] {threat.get('stride_category','?')} — {threat.get('affected_component','?')[:50]}",
                expanded=False
            ):
                cols = st.columns([1, 1])
                with cols[0]:
                    st.markdown(f"**Category:** {render_stride_badge(threat.get('stride_category','?'))}", unsafe_allow_html=True)
                    st.markdown(f"**Confidence:** {render_confidence_badge(threat.get('confidence','?'))}", unsafe_allow_html=True)
                with cols[1]:
                    st.markdown(f"**Component:** `{threat.get('affected_component','?')}`")
                
                st.markdown(f"**Threat:** {threat.get('threat_description','')}")
                st.markdown(f"**Missing Control:** _{threat.get('missing_control','')}_")
                
                if show_explanations and threat.get('explanation'):
                    st.info(f"💡 {threat.get('explanation','')}")
                
                if threat.get('confidence_reason'):
                    st.caption(f"Confidence reasoning: {threat.get('confidence_reason','')}")
    
    # ============================
    # MISSING CONTROLS SUMMARY
    # ============================
    if show_missing_controls:
        missing_controls = result.get('missing_controls_summary', [])
        if missing_controls:
            st.markdown("---")
            st.markdown("### 🔧 Missing Security Controls Summary")
            for i, control in enumerate(missing_controls):
                st.markdown(f"**{i+1}.** {control}")
    
    # ============================
    # RAW JSON OUTPUT
    # ============================
    with st.expander("📋 View Raw JSON Output"):
        st.json(result)
    
    # ============================
    # EXPORT
    # ============================
    st.markdown("---")
    export_json = json.dumps(result, indent=2)
    st.download_button(
        label="⬇️ Download Threat Report (JSON)",
        data=export_json,
        file_name=f"threat_report_{result.get('dfd_id','unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json"
    )

else:
    # Welcome state — no analysis yet
    st.markdown("---")
    st.markdown("### 👆 How to Use")
    st.markdown("""
    1. **Paste your DFD** as JSON in the left panel, or click a **Quick Load** button in the sidebar
    2. Optionally add a **security context** description  
    3. Click **Analyze for Threats**
    4. Review the STRIDE threat report with confidence levels and explanations
    
    **Demo tip:** Load the Complete DFD, analyze it, then load the Partial DFD and analyze again — see how the system gracefully handles missing information with calibrated confidence.
    """)
    
    st.info("🔐 **SecureByDesign** — Final Year Project | Amrita Vishwa Vidyapeetham | Department of Computer Science")
```

**Phase 4 Success Criteria:**
- [ ] Streamlit app starts without errors
- [ ] Both sample DFDs load and analyze correctly
- [ ] STRIDE coverage chart renders properly
- [ ] Threat cards show all fields (category, confidence, explanation)
- [ ] Partial DFD warning banner appears when appropriate
- [ ] Download button produces valid JSON
- [ ] App works via ngrok public URL

---

## PHASE 5 — NGROK DEPLOYMENT AND DEMO PREP
**Goal:** Public demo URL + polished demo script for assessment day.
**Deadline:** Day 12.

### Step 5.1 — Deploy via ngrok

```python
# In a NEW Colab cell — do NOT put this in streamlit_app.py

!pip install pyngrok --quiet
from pyngrok import ngrok
from google.colab import userdata

# Get your free auth token from https://ngrok.com (sign up, then Dashboard → Your Authtoken)
# Store as 'NGROK_TOKEN' in Colab Secrets
ngrok_token = userdata.get('NGROK_TOKEN')
ngrok.set_auth_token(ngrok_token)

# Kill any existing ngrok tunnels
ngrok.kill()

# Start Streamlit in background
import subprocess
streamlit_process = subprocess.Popen([
    'streamlit', 'run', 
    '/content/SecureByDesign/app/streamlit_app.py',
    '--server.port', '8501',
    '--server.headless', 'true',
    '--browser.gatherUsageStats', 'false'
])

import time
time.sleep(5)  # Wait for Streamlit to start

# Create public tunnel
public_url = ngrok.connect(8501)
print("=" * 60)
print(f"🔐 SecureByDesign Demo URL: {public_url}")
print("=" * 60)
print("Share this URL with your supervisor for the live demo.")
print("Keep this Colab cell running — closing it kills the demo.")
```

### Step 5.2 — Demo Script for Assessment Day

Rehearse this exact demo flow:

```
DEMO SCRIPT (8 minutes total)

[0:00 - 1:00] Introduction
"SecureByDesign analyzes software architecture diagrams before code is written 
and automatically identifies where the security risks are. We'll show you two 
scenarios: a complete diagram and an incomplete one."

[1:00 - 4:00] Demo 1 — Complete DFD (Payment System)
- Load the Complete DFD example from sidebar
- Add security context: "Internet-facing payment service, PCI-DSS compliance required"
- Click Analyze
- Walk through 2-3 threats from the results
- Point out: STRIDE category, confidence, affected component, explanation
- "Notice that High confidence threats have clear evidence from the DFD"

[4:00 - 7:00] Demo 2 — Partial DFD (Novel Contribution)  
- Load the Partial DFD example from sidebar
- "This is the same payment system but at an earlier design stage — 
  trust boundaries not yet defined, protocols not chosen"
- Click Analyze
- Point out the partial DFD banner at the top
- "The system still finds threats — but notice the confidence levels 
  shift to Medium and Low. It calibrates uncertainty instead of refusing."
- "No existing tool does this. ThreatModeling-LLM, our base paper, 
  requires complete diagrams and fails otherwise."

[7:00 - 8:00] Results
- Show evaluation table: macro F1 = [your number]
- Show partial vs complete DFD performance comparison
- "In 5-10 seconds we've identified threats that take a security expert 
  30-60 minutes to find manually."
```

**Phase 5 Success Criteria:**
- [ ] ngrok URL is stable and accessible on any device
- [ ] Demo takes under 8 minutes end to end
- [ ] Both demo scenarios work reliably
- [ ] Evaluation numbers are ready to show

---

## PHASE 6 — README AND FINAL COMMIT
**Goal:** Clean repository with professional README.
**Deadline:** Day 13.

Create `/content/SecureByDesign/README.md`:

```markdown
# SecureByDesign 🔐
### An Explainable LLM-Based Framework for Architectural Security Risk Inference from Incomplete Early-Stage Design Artifacts

**Final Year Project | Amrita Vishwa Vidyapeetham | Department of Computer Science**

---

## What It Does
SecureByDesign analyzes Data Flow Diagrams (DFDs) and automatically infers STRIDE security threats **before a single line of code is written**. It extends existing work (ThreatModeling-LLM, Yang et al. 2024) by:

- Handling **incomplete/partial DFDs** — no existing tool does this
- Providing **confidence-calibrated findings** based on information completeness
- Producing **architect-facing natural language explanations** per threat
- Covering **general microservice architectures**, not just banking

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/SecureByDesign
```

Open `SecureByDesign_Demo.ipynb` in Google Colab and follow the setup instructions.

## Tech Stack
- **LLM:** Google Gemini 1.5 Flash (free API)
- **Evaluation:** scikit-learn (precision/recall/F1)
- **UI:** Streamlit + ngrok
- **Dataset:** microSecEnD (1000+ real microservice DFDs)
- **Platform:** Google Colab

## Results
| Metric | Value |
|--------|-------|
| Macro F1-Score | [YOUR NUMBER] |
| Macro Precision | [YOUR NUMBER] |
| Macro Recall | [YOUR NUMBER] |
| Complete DFD F1 | [YOUR NUMBER] |
| Partial DFD F1 | [YOUR NUMBER] |
| Avg Analysis Time | [YOUR NUMBER]s |

## Project Structure
```
├── pipeline/          # AI inference engine (Person A)
├── evaluation/        # Dataset + evaluation harness (Person B)
├── app/               # Streamlit demo UI (Person B)
├── data/              # microSecEnD dataset
└── contract.json      # Data schema contract
```
```

### Final Push

```bash
cd /content/SecureByDesign
git add .
git commit -m "Day 13 - Person B: README complete, evaluation results in, demo polished"
git push origin main
```

---

## DAILY GIT DISCIPLINE

**End of every session:**
```bash
cd /content/SecureByDesign
git add evaluation/ app/ contract.json README.md
git status
git commit -m "Day X - Person B: [what you did today]"
git push origin main
```

**Start of every session:**
```bash
cd /content/SecureByDesign
git pull origin main
echo "✅ Up to date with Person A's pipeline changes"
```

---

## WHAT YOU MUST NEVER DO

- Never edit files in `/pipeline/` — that is Person A's domain
- Never change the contract schema without a call with Person A first
- Never run evaluation before Person A's `analyze_dfd()` is confirmed working (Day 8)
- Never hardcode API keys in any file
- Never push broken code without testing it first — `git status` before every commit
- Never change the test DFD JSON files after ground truth labeling is complete — doing so invalidates your evaluation
