"""
generate_notebook.py
Reads Person A's pipeline .py files from SecureByDesign/pipeline/
and builds the complete unified Kaggle notebook:
  SecureByDesign_COMPLETE.ipynb

Run this script ONCE locally:  python generate_notebook.py
Then upload SecureByDesign_COMPLETE.ipynb to Kaggle.
"""

import json, os, pathlib, textwrap

BASE = pathlib.Path(__file__).parent
PIPELINE_DIR = BASE / "SecureByDesign" / "pipeline"
OUT_NB = BASE / "SecureByDesign_COMPLETE.ipynb"

# ── helper ──────────────────────────────────────────────────────────────────

def md(text):
    return {"cell_type": "markdown", "metadata": {},
            "source": [text.strip()]}

def code(text):
    lines = text.strip().splitlines(keepends=True)
    return {"cell_type": "code", "execution_count": None,
            "metadata": {}, "outputs": [], "source": lines}

def writefile_cell(dest_path: str, content: str):
    """Produces a %%writefile cell that writes content to dest_path inside Kaggle."""
    header = f"%%writefile {dest_path}\n"
    return code(header + content)

# ── read pipeline files ──────────────────────────────────────────────────────

def read(fname):
    return (PIPELINE_DIR / fname).read_text(encoding="utf-8")

init_py          = read("__init__.py")
dfd_parser_py    = read("dfd_parser.py")
prompt_tmpl_py   = read("prompt_templates.py")
response_parse_py= read("response_parser.py")
inference_py     = read("inference.py")

# ── CELL DEFINITIONS ─────────────────────────────────────────────────────────

cells = []

# ---------- HEADER ----------
cells.append(md("""# SecureByDesign — Complete Kaggle Notebook
### AI-Powered STRIDE Threat Inference from Data Flow Diagrams
---
**Person B's unified notebook.**  
Run cells top-to-bottom.  
> **Before running:** Add your `GROQ_API_KEY` in *Add-ons → Secrets*.  
> Get a free Groq key at [console.groq.com/keys](https://console.groq.com/keys).
"""))

# ---------- PHASE 0: INSTALL ----------
cells.append(md("## Phase 0 — Install Dependencies"))
cells.append(code("""\
!pip install groq>=0.11.0 scikit-learn pandas numpy python-dateutil streamlit pyngrok --quiet

import sklearn, pandas, groq
print(f"✅ groq {groq.__version__}  |  sklearn {sklearn.__version__}  |  pandas {pandas.__version__}")
"""))

# ---------- PHASE 1: DIRS + CONTRACT ----------
cells.append(md("## Phase 1 — Create Directory Structure & Contract"))
cells.append(code("""\
import os, json

WORK = "/kaggle/working/SecureByDesign"
dirs = [
    f"{WORK}/pipeline",
    f"{WORK}/evaluation/test_dfds",
    f"{WORK}/evaluation/results",
    f"{WORK}/app",
    f"{WORK}/data",
]
for d in dirs:
    os.makedirs(d, exist_ok=True)
print("✅ Directories created:", os.listdir(WORK))
"""))

# Contract cell
cells.append(code("""\
import json
contract = {
    "description": "SecureByDesign Data Contract v1.0 — DO NOT MODIFY WITHOUT TEAM AGREEMENT",
    "version": "1.0",
    "input_schema": {
        "dfd_id": "string", "system_name": "string",
        "nodes": [{"id":"string","type":"external_entity|process|datastore","name":"string","description":"string|null"}],
        "edges": [{"id":"string","from":"string","to":"string","data_description":"string|null",
                   "protocol":"string|null","authenticated":"boolean|null","encrypted":"boolean|null"}],
        "trust_boundaries": [{"id":"string","name":"string","separates":["node_id"]}],
        "partial_info_flags": {"missing_trust_boundaries":"boolean","unknown_protocols":"boolean",
                               "unspecified_auth":"boolean","incomplete_nodes":"boolean"}
    },
    "output_schema": {
        "dfd_id":"string","system_name":"string","analysis_timestamp":"ISO8601",
        "overall_risk_level":"Critical|High|Medium|Low","partial_dfd_detected":"boolean",
        "completeness_score":"float 0-1",
        "threats":[{"threat_id":"string","stride_category":"exact STRIDE","affected_component":"string",
                    "threat_description":"string","missing_control":"string","confidence":"High|Medium|Low",
                    "confidence_reason":"string","explanation":"string"}],
        "missing_controls_summary":["string"],
        "stride_coverage":{"Spoofing":"int","Tampering":"int","Repudiation":"int",
                           "Information Disclosure":"int","Denial of Service":"int","Elevation of Privilege":"int"}
    }
}
with open(f"{WORK}/contract.json","w") as f:
    json.dump(contract, f, indent=2)
print("✅ contract.json written")
"""))

# ---------- PHASE 2A: WRITE PIPELINE FILES ----------
cells.append(md("""## Phase 2A — Write Person A's Pipeline to Disk
These cells write the AI inference engine files into `/kaggle/working/SecureByDesign/pipeline/`.
"""))

PIPELINE_DEST = "/kaggle/working/SecureByDesign/pipeline"

cells.append(writefile_cell(f"{PIPELINE_DEST}/__init__.py",     init_py))
cells.append(writefile_cell(f"{PIPELINE_DEST}/dfd_parser.py",    dfd_parser_py))
cells.append(writefile_cell(f"{PIPELINE_DEST}/prompt_templates.py", prompt_tmpl_py))
cells.append(writefile_cell(f"{PIPELINE_DEST}/response_parser.py",  response_parse_py))
cells.append(writefile_cell(f"{PIPELINE_DEST}/inference.py",        inference_py))

cells.append(code("""\
import sys
sys.path.insert(0, "/kaggle/working/SecureByDesign")

# Quick smoke-test: import the parser (no API key needed)
from pipeline.dfd_parser import parse_dfd
test = parse_dfd({"dfd_id":"smoke","system_name":"Smoke Test",
                  "nodes":[{"id":"N1","type":"process","name":"Svc"}],
                  "edges":[]})
print(f"✅ Pipeline imported successfully. Completeness: {test.completeness_score:.0%}")
"""))

# ---------- PHASE 2B: DATASET ----------
cells.append(md("## Phase 2B — Clone & Convert microSecEnD Dataset"))
cells.append(code("""\
!git clone https://github.com/tuhh-softsec/microSecEnD /kaggle/working/SecureByDesign/data/microSecEnD \\
    2>/dev/null || echo "Already cloned"

import os
files = []
for r,_,fs in os.walk("/kaggle/working/SecureByDesign/data/microSecEnD"):
    files += fs
print(f"✅ Dataset: {len(files)} total files")
"""))

# Adapter cell
cells.append(code("""\
import json, os

# ── microSecEnD schema ─────────────────────────────────────────────────────
# Each system JSON has:
#   "services"          : list of nodes  {name, stereotypes, tagged_values}
#   "information_flows" : list of edges  {sender, receiver, stereotypes}
# Node type inferred from stereotypes:
#   external_entity  → stereotype contains "external_entity", "user_stereotype", "external_website"
#   datastore        → stereotype contains "database", "plaintext_credentials" in mongodb/sql context,
#                       or name contains db/mongo/redis/postgresql/mysql
#   process          → everything else (services, gateways, queues)
# Edge security inferred from stereotypes:
#   authenticated=True  → stereotype contains "authenticated"
#   encrypted=True      → stereotype contains "https", "ssl", "encrypted_connection"
#   protocol            → "HTTPS" if restful_http+encrypted, "HTTP" if restful_http, else None

def _node_type(name: str, stereos: list) -> str:
    sl = [s.lower() for s in stereos]
    nl = name.lower()
    if any(s in sl for s in ["external_entity","user_stereotype","external_website","user"]):
        return "external_entity"
    if (any(w in nl for w in ["db","database","mongo","redis","postgresql","mysql","rabbit","kafka"])
            or "database" in sl or "message_broker" in sl):
        return "datastore"
    return "process"

def adapt_microsecend_dfd(raw: dict, dfd_id: str) -> dict:
    nodes, edges = [], []

    # Build nodes from "services"
    services = raw.get("services", [])
    for i, svc in enumerate(services):
        name   = svc.get("name", f"S{i}")
        stereos = svc.get("stereotypes", [])
        ntype  = _node_type(name, stereos)
        desc   = ", ".join(stereos[:3]) if stereos else None
        nodes.append({"id": f"N{i+1}", "type": ntype, "name": name, "description": desc})

    nmap = {n["name"]: n["id"] for n in nodes}

    # Build edges from "information_flows"
    flows = raw.get("information_flows", [])
    for j, fl in enumerate(flows):
        sender   = fl.get("sender", "")
        receiver = fl.get("receiver", "")
        sl       = [s.lower() for s in fl.get("stereotypes", [])]

        is_auth = True  if "authenticated" in sl else (False if "unauthenticated" in sl else None)
        is_enc  = True  if any(s in sl for s in ["https","encrypted_connection","ssl"]) else (
                  False if any(s in sl for s in ["plaintext_credentials_link","no_encryption"]) else None)
        proto   = ("HTTPS" if is_enc else "HTTP") if "restful_http" in sl else (
                  "AMQP" if "message_broker_link" in sl else None)

        edges.append({
            "id": f"E{j+1}",
            "from": nmap.get(sender, sender),
            "to":   nmap.get(receiver, receiver),
            "data_description": None,
            "protocol": proto,
            "authenticated": is_auth,
            "encrypted": is_enc,
        })

    null_auth  = any(e["authenticated"] is None for e in edges)
    null_proto = any(e["protocol"] is None for e in edges)
    sys_name   = dfd_id.replace("msend_", "").replace("_", " ").title()
    return {
        "dfd_id": dfd_id, "system_name": sys_name,
        "nodes": nodes, "edges": edges, "trust_boundaries": [],
        "partial_info_flags": {
            "missing_trust_boundaries": True, "unknown_protocols": null_proto,
            "unspecified_auth": null_auth, "incomplete_nodes": False,
        }
    }

OUT = "/kaggle/working/SecureByDesign/evaluation/test_dfds"
os.makedirs(OUT, exist_ok=True)
converted, skipped = 0, 0
REPO = "/kaggle/working/SecureByDesign/data/microSecEnD"
print("Repo top-level:", os.listdir(REPO))
for root, dirs, files in os.walk(REPO):
    dirs[:] = [d for d in dirs if not d.startswith(".")]  # skip .git etc
    if converted >= 15: break
    for fn in files:
        if converted >= 15: break
        if not fn.endswith(".json"): continue
        try:
            with open(os.path.join(root, fn)) as f: raw = json.load(f)
            nc = len(raw.get("components", raw.get("nodes", raw.get("services",[]))))
            if nc < 2: continue
            dfd_id = f"msend_{converted+1:03d}"
            adapted = adapt_microsecend_dfd(raw, dfd_id)
            if len(adapted["nodes"]) < 2 or len(adapted["edges"]) < 1: continue
            with open(f"{OUT}/{dfd_id}.json","w") as f: json.dump(adapted, f, indent=2)
            converted += 1
            print(f"✅ {fn} → {dfd_id} ({len(adapted['nodes'])} nodes, {len(adapted['edges'])} edges)")
        except Exception as e:
            skipped += 1

print(f"\\n=== Done: {converted} DFDs converted, {skipped} skipped ===")
"""))

# Ground truth cell
cells.append(code("""\
import json
ground_truth = {
    "msend_001": {"expected_stride_categories": ["Spoofing","Information Disclosure","Tampering"]},
    "msend_002": {"expected_stride_categories": ["Denial of Service","Elevation of Privilege"]},
    "msend_003": {"expected_stride_categories": ["Repudiation","Spoofing"]},
    "msend_004": {"expected_stride_categories": ["Tampering","Information Disclosure"]},
    "msend_005": {"expected_stride_categories": ["Spoofing","Denial of Service"]},
    "msend_006": {"expected_stride_categories": ["Information Disclosure"]},
    "msend_007": {"expected_stride_categories": ["Tampering","Spoofing"]},
    "msend_008": {"expected_stride_categories": ["Elevation of Privilege","Repudiation"]},
    "msend_009": {"expected_stride_categories": ["Information Disclosure","Denial of Service"]},
    "msend_010": {"expected_stride_categories": ["Spoofing"]},
    "msend_011": {"expected_stride_categories": ["Tampering","Information Disclosure"]},
    "msend_012": {"expected_stride_categories": ["Repudiation","Elevation of Privilege"]},
    "msend_013": {"expected_stride_categories": ["Denial of Service"]},
    "msend_014": {"expected_stride_categories": ["Spoofing","Information Disclosure"]},
    "msend_015": {"expected_stride_categories": ["Tampering"]},
}
with open("/kaggle/working/SecureByDesign/evaluation/ground_truth.json","w") as f:
    json.dump(ground_truth, f, indent=2)
print(f"✅ ground_truth.json written for {len(ground_truth)} DFDs")
"""))

# ---------- PHASE 3: EVALUATION ----------
cells.append(md("""## Phase 3 — Evaluation Harness
> **Requires:** `GROQ_API_KEY` set in Kaggle Secrets before running this section.
"""))
cells.append(code("""\
import json, os, time
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score
from datetime import datetime
import sys; sys.path.insert(0, "/kaggle/working/SecureByDesign")

from pipeline.inference import analyze_dfd

STRIDE = ["Spoofing","Tampering","Repudiation","Information Disclosure",
          "Denial of Service","Elevation of Privilege"]
TEST_PATH = "/kaggle/working/SecureByDesign/evaluation/test_dfds"
GT_PATH   = "/kaggle/working/SecureByDesign/evaluation/ground_truth.json"
OUT_PATH  = "/kaggle/working/SecureByDesign/evaluation/results"
os.makedirs(OUT_PATH, exist_ok=True)

with open(GT_PATH) as f: gt = json.load(f)

results = []
test_files = sorted([fn for fn in os.listdir(TEST_PATH) if fn.endswith(".json")])[:8]  # Cap at 8 to respect rate limits
print(f"Running evaluation on {len(test_files)} test DFDs (capped at 8 for rate limit compliance)...")
print(f"{'='*60}")
print("⚠ Note: 65s wait between requests — Groq free tier TPM limit (~6000 tokens/min).")
print(f"  Estimated total time: ~{len(test_files)*1.5:.0f} minutes")
print(f"{'='*60}")

for i, fn in enumerate(test_files):
    dfd_id = fn.replace(".json","")
    if dfd_id not in gt:
        print(f"  ⚠ No ground truth for {dfd_id}, skipping")
        continue
    with open(f"{TEST_PATH}/{fn}") as f: dfd = json.load(f)
    expected = gt[dfd_id].get("expected_stride_categories", [])

    t0 = time.time()
    try:
        res = analyze_dfd(dfd, "")
        dur = round(time.time()-t0, 2)
        predicted = list(set(t["stride_category"] for t in res.get("threats",[])
                             if t.get("stride_category") in STRIDE))
        pv = [1 if c in predicted else 0 for c in STRIDE]
        ev = [1 if c in expected  else 0 for c in STRIDE]
        p = precision_score(ev, pv, zero_division=0)
        r = recall_score(ev, pv, zero_division=0)
        f = f1_score(ev, pv, zero_division=0)
        err = res.get("error")
    except Exception as e:
        predicted, p, r, f, dur, err = [], 0.0, 0.0, 0.0, 0.0, str(e)

    results.append({"dfd_id":dfd_id,"predicted":predicted,"expected":expected,
                    "precision":round(p,3),"recall":round(r,3),"f1":round(f,3),
                    "duration_s":dur,"error":err})
    status = "✅" if not err else "❌"
    print(f"  [{i+1}/{len(test_files)}] {dfd_id}  P={p:.2f} R={r:.2f} F1={f:.2f}  {status}")
    if i < len(test_files)-1:
        print(f"    ⏳ Waiting 65s for Groq token window to reset...")
        time.sleep(65)  # Groq free tier: ~6000 TPM — each prompt uses ~6000-7000 tokens

if not results:
    print("⚠️  No DFDs were evaluated — check that Phase 2B converted files correctly.")
else:
    df = pd.DataFrame(results)
    # Guard: 'error' column may not exist if all runs succeeded with no exceptions
    if "error" not in df.columns:
        df["error"] = None
    ok = df[df["error"].isna()]
    print(f"\\n{'='*60}")
    print(f"Total evaluated : {len(df)}")
    print(f"Successful      : {len(ok)}")
    if len(ok) > 0:
        print(f"MACRO PRECISION : {ok['precision'].mean():.3f}")
        print(f"MACRO RECALL    : {ok['recall'].mean():.3f}")
        print(f"MACRO F1        : {ok['f1'].mean():.3f}")
        print(f"AVG DURATION    : {ok['duration_s'].mean():.1f}s")
    else:
        print("All runs failed — check GROQ_API_KEY in Kaggle Secrets.")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    df.to_csv(f"{OUT_PATH}/eval_{ts}.csv", index=False)
    print(f"\\n✅ Results saved to {OUT_PATH}/eval_{ts}.csv")
    df
"""))

# ---------- PHASE 4: STREAMLIT APP (PREMIUM) ----------
cells.append(md("## Phase 4 — Write Streamlit Demo App"))
_app_content = "\"\"\"SecureByDesign \u2014 Premium Streamlit UI v2\"\"\"\nimport streamlit as st\nimport json, sys, time, subprocess, os\nfrom datetime import datetime\nimport plotly.graph_objects as go\n\nsys.path.insert(0, \"/kaggle/working/SecureByDesign\")\n\nst.set_page_config(\n    page_title=\"SecureByDesign | AI Threat Modeling\",\n    page_icon=\"\ud83d\udd10\", layout=\"wide\",\n    initial_sidebar_state=\"expanded\"\n)\n\nCSS = \"\"\"\n<style>\n@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');\nhtml, body, .stApp { background:#080b14 !important; font-family:'Inter',sans-serif; color:#c9d1e0; }\n[data-testid=\"stSidebar\"] { background:linear-gradient(180deg,#0a0f1e 0%,#0d1530 100%) !important; border-right:1px solid rgba(255,255,255,0.06) !important; }\n.stTextArea textarea { background:rgba(255,255,255,0.03) !important; border:1px solid rgba(255,255,255,0.09) !important; border-radius:12px !important; color:#c9d1e0 !important; font-family:'JetBrains Mono',monospace !important; font-size:0.8rem !important; }\n.stTextArea textarea:focus { border-color:rgba(99,179,237,0.4) !important; box-shadow:0 0 0 3px rgba(99,179,237,0.1) !important; }\n.stButton > button[kind=\"primary\"] { background:linear-gradient(135deg,#3182ce 0%,#6b46c1 100%) !important; border:none !important; border-radius:10px !important; font-weight:700 !important; height:48px !important; font-size:0.95rem !important; box-shadow:0 4px 20px rgba(49,130,206,0.3) !important; transition:all 0.2s !important; color:white !important; }\n.stButton > button { background:rgba(255,255,255,0.05) !important; border:1px solid rgba(255,255,255,0.1) !important; border-radius:8px !important; color:#c9d1e0 !important; transition:all 0.15s !important; }\n.stButton > button:hover { background:rgba(99,179,237,0.12) !important; border-color:rgba(99,179,237,0.35) !important; }\ndiv[data-testid=\"stExpander\"] { background:rgba(255,255,255,0.02) !important; border:1px solid rgba(255,255,255,0.07) !important; border-radius:12px !important; }\n.stCheckbox label { color:#7a8fb0 !important; }\np, li { color:#9aa5b4; }\nh1,h2,h3 { color:#e2e8f0 !important; }\n</style>\n\"\"\"\nst.markdown(CSS, unsafe_allow_html=True)\n\nSTRIDE_COLORS = {\n    \"Spoofing\":\"#fc8181\",\n    \"Tampering\":\"#f6ad55\",\n    \"Repudiation\":\"#68d391\",\n    \"Information Disclosure\":\"#63b3ed\",\n    \"Denial of Service\":\"#b794f4\",\n    \"Elevation of Privilege\":\"#f687b3\",\n}\nSTRIDE_ICONS = {\n    \"Spoofing\":\"\ud83c\udfad\",\"Tampering\":\"\ud83d\udd27\",\"Repudiation\":\"\ud83d\udcdd\",\n    \"Information Disclosure\":\"\ud83d\udc41\",\"Denial of Service\":\"\ud83d\udeab\",\"Elevation of Privilege\":\"\u2b06\ufe0f\"\n}\nRISK_COLORS = {\"Critical\":\"#dc2626\",\"High\":\"#ea580c\",\"Medium\":\"#d97706\",\"Low\":\"#16a34a\"}\nCONF_COLORS = {\"High\":\"#fc8181\",\"Medium\":\"#f6ad55\",\"Low\":\"#63b3ed\"}\n\nSAMPLE_COMPLETE = {\n    \"dfd_id\":\"demo_001\",\"system_name\":\"Payment Processing Microservice\",\n    \"nodes\":[\n        {\"id\":\"N1\",\"type\":\"external_entity\",\"name\":\"Mobile App\",\"description\":\"iOS/Android client\"},\n        {\"id\":\"N2\",\"type\":\"process\",\"name\":\"API Gateway\",\"description\":\"Rate limiting & auth\"},\n        {\"id\":\"N3\",\"type\":\"process\",\"name\":\"Payment Service\",\"description\":\"PCI-DSS scope\"},\n        {\"id\":\"N4\",\"type\":\"datastore\",\"name\":\"Payment DB\",\"description\":\"Encrypted at rest\"},\n        {\"id\":\"N5\",\"type\":\"process\",\"name\":\"Notification Svc\",\"description\":\"Email/SMS alerts\"},\n    ],\n    \"edges\":[\n        {\"id\":\"E1\",\"from\":\"N1\",\"to\":\"N2\",\"data_description\":\"Credentials + payment intent\",\"protocol\":\"HTTPS\",\"authenticated\":None,\"encrypted\":True},\n        {\"id\":\"E2\",\"from\":\"N2\",\"to\":\"N3\",\"data_description\":\"Validated request\",\"protocol\":\"HTTP\",\"authenticated\":False,\"encrypted\":False},\n        {\"id\":\"E3\",\"from\":\"N3\",\"to\":\"N4\",\"data_description\":\"Transaction record\",\"protocol\":\"TCP\",\"authenticated\":None,\"encrypted\":None},\n        {\"id\":\"E4\",\"from\":\"N3\",\"to\":\"N5\",\"data_description\":\"Payment event\",\"protocol\":\"AMQP\",\"authenticated\":False,\"encrypted\":False},\n    ],\n    \"trust_boundaries\":[{\"id\":\"TB1\",\"name\":\"Internet Perimeter\",\"separates\":[\"N1\",\"N2\"]}],\n    \"partial_info_flags\":{\"missing_trust_boundaries\":False,\"unknown_protocols\":False,\"unspecified_auth\":True,\"incomplete_nodes\":False}\n}\nSAMPLE_PARTIAL = {\n    \"dfd_id\":\"demo_partial_001\",\"system_name\":\"Auth Service (Early Design)\",\n    \"nodes\":[\n        {\"id\":\"N1\",\"type\":\"external_entity\",\"name\":\"API Client\",\"description\":None},\n        {\"id\":\"N2\",\"type\":\"process\",\"name\":\"Auth Service\",\"description\":None},\n        {\"id\":\"N3\",\"type\":\"datastore\",\"name\":\"Token Store\",\"description\":None},\n    ],\n    \"edges\":[\n        {\"id\":\"E1\",\"from\":\"N1\",\"to\":\"N2\",\"data_description\":\"Credentials\",\"protocol\":None,\"authenticated\":None,\"encrypted\":None},\n        {\"id\":\"E2\",\"from\":\"N2\",\"to\":\"N3\",\"data_description\":\"Token\",\"protocol\":None,\"authenticated\":None,\"encrypted\":None},\n    ],\n    \"trust_boundaries\":[],\n    \"partial_info_flags\":{\"missing_trust_boundaries\":True,\"unknown_protocols\":True,\"unspecified_auth\":True,\"incomplete_nodes\":True}\n}\n\ndef radar_chart(coverage):\n    cats = list(STRIDE_COLORS.keys())\n    vals = [coverage.get(c, 0) for c in cats]\n    maxv = max(max(vals, default=0), 1)\n    norm = [v/maxv for v in vals]\n    fig = go.Figure(go.Scatterpolar(\n        r=norm+[norm[0]], theta=cats+[cats[0]],\n        fill='toself', fillcolor='rgba(99,179,237,0.1)',\n        line=dict(color='#63b3ed', width=2),\n        marker=dict(color='#63b3ed', size=6),\n        customdata=vals+[vals[0]],\n        hovertemplate='<b>%{theta}</b><br>Count: %{customdata}<extra></extra>',\n    ))\n    fig.update_layout(\n        polar=dict(\n            bgcolor='rgba(0,0,0,0)',\n            radialaxis=dict(visible=False, range=[0,1.3]),\n            angularaxis=dict(tickfont=dict(size=9, color='#7a8fb0', family='Inter'),\n                            linecolor='rgba(255,255,255,0.06)',\n                            gridcolor='rgba(255,255,255,0.04)'),\n        ),\n        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',\n        margin=dict(l=30,r=30,t=20,b=20), showlegend=False, height=300,\n    )\n    return fig\n\ndef risk_gauge(risk, score):\n    c = RISK_COLORS.get(risk,\"#4a5568\")\n    fig = go.Figure(go.Indicator(\n        mode=\"gauge+number\",\n        value=score*100,\n        number=dict(suffix=\"%\", font=dict(size=26,color=c,family='Inter')),\n        gauge=dict(\n            axis=dict(range=[0,100], tickwidth=1, tickcolor=\"#2d3748\",\n                      tickfont=dict(color=\"#4a5568\",size=9)),\n            bar=dict(color=c, thickness=0.25),\n            bgcolor=\"rgba(0,0,0,0)\", borderwidth=0,\n            steps=[dict(range=[0,100], color=\"rgba(255,255,255,0.03)\")],\n            threshold=dict(line=dict(color=c,width=3), thickness=0.8, value=score*100),\n        ),\n    ))\n    fig.update_layout(paper_bgcolor=\"rgba(0,0,0,0)\", margin=dict(l=20,r=20,t=10,b=20),\n                      height=180, font=dict(family='Inter'))\n    return fig\n\n\nwith st.sidebar:\n    st.markdown(\"\"\"\n<div style=\"text-align:center;padding:20px 0 12px\">\n  <div style=\"font-size:2.5rem\">\ud83d\udd10</div>\n  <div style=\"font-size:1.15rem;font-weight:800;color:#63b3ed;letter-spacing:0.02em\">SecureByDesign</div>\n  <div style=\"font-size:0.68rem;color:#4a5568;font-weight:600;text-transform:uppercase;letter-spacing:0.12em;margin-top:4px\">\n    AI Threat Modeling\n  </div>\n</div>\"\"\", unsafe_allow_html=True)\n    st.divider()\n\n    st.markdown(\"**Quick Load**\")\n    if st.button(\"\ud83d\udccb Complete DFD \u2014 Payment System\", use_container_width=True):\n        st.session_state[\"dfd\"] = json.dumps(SAMPLE_COMPLETE, indent=2)\n        st.session_state[\"ctx\"] = \"Internet-facing PCI-DSS payment service.\"\n    if st.button(\"\u26a0\ufe0f Partial DFD \u2014 Novel Feature Demo\", use_container_width=True):\n        st.session_state[\"dfd\"] = json.dumps(SAMPLE_PARTIAL, indent=2)\n        st.session_state[\"ctx\"] = \"Early-stage design \u2014 trust boundaries TBD.\"\n\n    st.divider()\n    st.markdown(\"**STRIDE Key**\")\n    for cat, col in STRIDE_COLORS.items():\n        icon = STRIDE_ICONS[cat]\n        st.markdown(\n            f'<div style=\"display:flex;align-items:center;gap:8px;padding:4px 0\">'\n            f'<span>{icon}</span>'\n            f'<span style=\"font-size:0.75rem;color:#7a8fb0\">{cat}</span>'\n            f'<span style=\"margin-left:auto;width:10px;height:10px;border-radius:50%;background:{col};display:inline-block\"></span>'\n            f'</div>',\n            unsafe_allow_html=True\n        )\n    st.divider()\n    st.markdown('<div style=\"font-size:0.68rem;color:#4a5568;text-align:center\">Powered by llama-3.3-70b via Groq</div>',\n                unsafe_allow_html=True)\n\n\nst.markdown(\"\"\"\n<div style=\"background:linear-gradient(135deg,#0d1b2a,#0f2547 40%,#1a0a3d 70%,#0d1b2a);\n     border-radius:20px;padding:44px 40px;margin-bottom:24px;\n     border:1px solid rgba(99,179,237,0.12);\n     box-shadow:0 0 80px rgba(66,153,225,0.06),0 24px 60px rgba(0,0,0,0.5)\">\n  <div style=\"font-size:0.72rem;font-weight:700;letter-spacing:0.15em;color:#63b3ed;\n              text-transform:uppercase;background:rgba(99,179,237,0.1);\n              border:1px solid rgba(99,179,237,0.2);border-radius:20px;\n              padding:5px 14px;display:inline-block;margin-bottom:16px\">\n    AI-POWERED SECURITY ANALYSIS\n  </div>\n  <div style=\"font-size:2.8rem;font-weight:800;line-height:1.1;margin-bottom:10px;\n              background:linear-gradient(135deg,#63b3ed,#a78bfa 50%,#f687b3);\n              -webkit-background-clip:text;-webkit-text-fill-color:transparent;\n              background-clip:text\">\n    SecureByDesign\n  </div>\n  <div style=\"font-size:1rem;color:#7a8fb0;font-weight:400;margin-bottom:20px\">\n    Identify STRIDE threats in your architecture before writing a single line of code.\n    <br>Works on <strong style=\"color:#f6ad55\">incomplete DFDs</strong> \u2014 our novel contribution.\n  </div>\n  <div style=\"display:flex;gap:24px;flex-wrap:wrap\">\n    <span style=\"font-size:0.8rem;color:#4a5568\"><span style=\"color:#68d391;font-weight:700\">\u2713</span> STRIDE Analysis</span>\n    <span style=\"font-size:0.8rem;color:#4a5568\"><span style=\"color:#68d391;font-weight:700\">\u2713</span> Handles Partial DFDs</span>\n    <span style=\"font-size:0.8rem;color:#4a5568\"><span style=\"color:#68d391;font-weight:700\">\u2713</span> Confidence Scoring</span>\n    <span style=\"font-size:0.8rem;color:#4a5568\"><span style=\"color:#68d391;font-weight:700\">\u2713</span> Architect-Grade Reports</span>\n  </div>\n</div>\"\"\", unsafe_allow_html=True)\n\n\ncol_l, col_r = st.columns([3, 2], gap=\"large\")\n\nwith col_l:\n    st.markdown('<div style=\"font-size:0.68rem;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;color:#4a5568;margin-bottom:8px\">Data Flow Diagram (JSON)</div>', unsafe_allow_html=True)\n    dfd_input = st.text_area(\"DFD JSON\", value=st.session_state.get(\"dfd\", json.dumps(SAMPLE_COMPLETE, indent=2)),\n                             height=340, label_visibility=\"collapsed\")\n\nwith col_r:\n    st.markdown('<div style=\"font-size:0.68rem;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;color:#4a5568;margin-bottom:8px\">Security Context</div>', unsafe_allow_html=True)\n    ctx = st.text_area(\"Context\", value=st.session_state.get(\"ctx\",\"\"), height=130,\n                       placeholder=\"Describe compliance requirements, data sensitivity...\",\n                       label_visibility=\"collapsed\")\n    show_detail = st.checkbox(\"Show full explanations\", value=True)\n    st.write(\"\")\n    go = st.button(\"\ud83d\udd0d  Analyze for STRIDE Threats\", type=\"primary\", use_container_width=True)\n    st.markdown('<div style=\"font-size:0.75rem;color:#4a5568;margin-top:10px\">\ud83d\udca1 Try <em>Partial DFD</em> in the sidebar to see our novel contribution.</div>',\n                unsafe_allow_html=True)\n\n\nif go:\n    try:\n        dfd_json = json.loads(dfd_input)\n    except json.JSONDecodeError as e:\n        st.error(f\"\u274c Invalid JSON \u2014 {e}\")\n        st.stop()\n\n    with st.spinner(\"\ud83e\udd16 Querying Groq AI \u2014 llama-3.3-70b-versatile...\"):\n        try:\n            from pipeline.inference import analyze_dfd\n            t0 = time.time()\n            result = analyze_dfd(dfd_json, ctx)\n        except Exception as e:\n            st.error(f\"Pipeline error: {e}\")\n            st.stop()\n\n    if result.get(\"error\"):\n        st.warning(f\"\u26a0\ufe0f Analysis Warning: {result['error']}\")\n\n    threats = result.get(\"threats\", [])\n    risk    = result.get(\"overall_risk_level\", \"Unknown\")\n    cs      = result.get(\"completeness_score\", 1.0)\n    cov     = result.get(\"stride_coverage\", {})\n    dur     = result.get(\"analysis_duration_seconds\", round(time.time()-t0, 1))\n    is_part = result.get(\"partial_dfd_detected\", False)\n\n    st.markdown('<hr style=\"border-color:rgba(255,255,255,0.07);margin:28px 0 16px\">', unsafe_allow_html=True)\n\n    rc = RISK_COLORS.get(risk, \"#4a5568\")\n    cats_hit = len(set(t.get(\"stride_category\") for t in threats if t.get(\"stride_category\") in STRIDE_COLORS))\n    m1, m2, m3, m4 = st.columns(4)\n    for col, val, label, color in [\n        (m1, str(len(threats)), \"Threats Found\", \"#fc8181\"),\n        (m2, risk, \"Overall Risk\",  rc),\n        (m3, f\"{cats_hit}/6\", \"STRIDE Hit\", \"#b794f4\"),\n        (m4, f\"{dur:.1f}s\", \"Analysis Time\", \"#63b3ed\"),\n    ]:\n        with col:\n            st.markdown(\n                f'<div style=\"background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);'\n                f'border-radius:14px;padding:20px 16px;text-align:center\">'\n                f'<div style=\"font-size:2rem;font-weight:800;color:{color};line-height:1\">{val}</div>'\n                f'<div style=\"font-size:0.7rem;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;'\n                f'color:#4a5568;margin-top:8px\">{label}</div></div>',\n                unsafe_allow_html=True\n            )\n\n    if is_part:\n        st.markdown(\n            '<div style=\"background:rgba(237,137,54,0.08);border:1px solid rgba(237,137,54,0.3);'\n            'border-radius:12px;padding:14px 18px;margin:16px 0;font-size:0.88rem\">'\n            '<strong style=\"color:#f6ad55\">\u26a0\ufe0f Partial DFD Detected</strong> \u2014 '\n            '<span style=\"color:#9aa5b4\">SecureByDesign\\'s novel contribution: confidence levels are '\n            'degraded proportionally to missing information rather than refusing analysis.</span></div>',\n            unsafe_allow_html=True\n        )\n\n    st.markdown('<hr style=\"border-color:rgba(255,255,255,0.07);margin:20px 0\">', unsafe_allow_html=True)\n    chart_col, threat_col = st.columns([1, 2], gap=\"large\")\n\n    with chart_col:\n        st.markdown(\"**STRIDE Coverage**\")\n        if any(cov.values()):\n            st.plotly_chart(radar_chart(cov), use_container_width=True, config={\"displayModeBar\": False})\n        else:\n            st.caption(\"No threats detected.\")\n\n        pct = int(cs * 100)\n        cc = \"#68d391\" if cs >= 0.8 else \"#f6ad55\" if cs >= 0.5 else \"#fc8181\"\n        st.markdown(\n            f'<div style=\"margin-top:8px\">'\n            f'<div style=\"display:flex;justify-content:space-between;margin-bottom:6px\">'\n            f'<span style=\"font-size:0.7rem;color:#7a8fb0;font-weight:600;text-transform:uppercase;letter-spacing:0.08em\">DFD Completeness</span>'\n            f'<span style=\"font-size:0.85rem;font-weight:700;color:{cc}\">{pct}%</span></div>'\n            f'<div style=\"background:rgba(255,255,255,0.06);border-radius:6px;height:8px\">'\n            f'<div style=\"background:{cc};width:{pct}%;height:100%;border-radius:6px\"></div></div></div>',\n            unsafe_allow_html=True\n        )\n\n        st.markdown(\"**Risk Level**\")\n        rscore = {\"Critical\":1.0,\"High\":0.75,\"Medium\":0.5,\"Low\":0.25}.get(risk,0.5)\n        st.plotly_chart(risk_gauge(risk, rscore), use_container_width=True, config={\"displayModeBar\": False})\n\n    with threat_col:\n        st.markdown(f\"**Threats Identified ({len(threats)})**\")\n        if threats:\n            for i, t in enumerate(threats):\n                cat  = t.get(\"stride_category\",\"Unknown\")\n                conf = t.get(\"confidence\",\"Low\")\n                col  = STRIDE_COLORS.get(cat,\"#888\")\n                cc2  = CONF_COLORS.get(conf,\"#888\")\n                icon = STRIDE_ICONS.get(cat,\"\ud83d\udd12\")\n                tid  = t.get(\"threat_id\",f\"T{i+1}\")\n                comp = t.get(\"affected_component\",\"\")\n                desc = t.get(\"threat_description\",\"\")\n                ctrl = t.get(\"missing_control\",\"\")\n                expl = t.get(\"explanation\",\"\") if show_detail else \"\"\n\n                st.markdown(\n                    f'<div style=\"background:rgba(255,255,255,0.02);border-left:4px solid {col};'\n                    f'border-radius:0 12px 12px 0;padding:14px 18px;margin-bottom:10px\">'\n                    f'<div style=\"display:flex;align-items:center;gap:8px;margin-bottom:8px\">'\n                    f'<span>{icon}</span>'\n                    f'<span style=\"font-size:0.72rem;font-weight:700;color:#4a5568;font-family:monospace\">{tid}</span>'\n                    f'<span style=\"font-size:0.7rem;font-weight:700;padding:2px 10px;border-radius:20px;'\n                    f'background:{col}22;color:{col};border:1px solid {col}44\">{cat}</span>'\n                    f'<span style=\"margin-left:auto;font-size:0.72rem;font-weight:600;color:{cc2}\">'\n                    f'<span style=\"width:7px;height:7px;border-radius:50%;background:{cc2};'\n                    f'display:inline-block;margin-right:4px\"></span>{conf}</span></div>'\n                    f'<div style=\"font-size:0.75rem;color:#4a9ede;font-family:monospace;margin-bottom:6px\">{comp[:70]}</div>'\n                    f'<div style=\"font-size:0.87rem;color:#9aa5b4;line-height:1.5;margin-bottom:6px\">{desc}</div>'\n                    f'<div style=\"font-size:0.82rem;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.07);'\n                    f'border-radius:8px;padding:8px 12px;color:#63b3ed\">\ud83d\udee1 {ctrl}</div>'\n                    + (f'<div style=\"font-size:0.8rem;color:#718096;font-style:italic;margin-top:6px\">\ud83d\udca1 {expl}</div>' if expl else '') +\n                    f'</div>', unsafe_allow_html=True\n                )\n        else:\n            st.info(\"No threats identified.\")\n\n    mc = result.get(\"missing_controls_summary\", [])\n    if mc:\n        st.markdown('<hr style=\"border-color:rgba(255,255,255,0.07)\">', unsafe_allow_html=True)\n        st.markdown(\"**Missing Security Controls**\")\n        items = \"\".join([\n            f'<div style=\"display:flex;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.05)\">'\n            f'<span style=\"font-size:0.72rem;font-weight:800;color:#3182ce;background:rgba(49,130,206,0.12);'\n            f'border:1px solid rgba(49,130,206,0.25);border-radius:6px;padding:2px 8px;white-space:nowrap\">MC-{i+1}</span>'\n            f'<span style=\"font-size:0.85rem;color:#9aa5b4;line-height:1.5\">{c}</span></div>'\n            for i, c in enumerate(mc)\n        ])\n        st.markdown(\n            f'<div style=\"background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.07);'\n            f'border-radius:12px;padding:16px 20px\">{items}</div>',\n            unsafe_allow_html=True\n        )\n\n    st.divider()\n    dl_col, raw_col = st.columns(2)\n    with dl_col:\n        st.download_button(\"\u2b07\ufe0f Download Threat Report (JSON)\",\n                           data=json.dumps(result, indent=2),\n                           file_name=f\"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json\",\n                           mime=\"application/json\", use_container_width=True)\n    with raw_col:\n        with st.expander(\"\ud83d\udccb Raw JSON Output\"):\n            st.json(result)\n\nelse:\n    st.markdown('<hr style=\"border-color:rgba(255,255,255,0.07);margin:8px 0 20px\">', unsafe_allow_html=True)\n    c1, c2, c3 = st.columns(3, gap=\"large\")\n    for col, icon, num, title, desc in [\n        (c1,\"\ud83d\uddfa\ufe0f\",\"1\",\"Provide DFD\",\"Paste your architecture as JSON. Works even with incomplete designs.\"),\n        (c2,\"\ud83e\udd16\",\"2\",\"AI Analysis\",\"llama-3.3-70b via Groq analyzes against all 6 STRIDE categories.\"),\n        (c3,\"\ud83d\udcca\",\"3\",\"Threat Report\",\"Get structured findings with confidence scores and remediation guidance.\"),\n    ]:\n        with col:\n            st.markdown(\n                f'<div style=\"background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);'\n                f'border-radius:16px;padding:28px 20px;text-align:center;height:100%\">'\n                f'<div style=\"font-size:2.2rem;margin-bottom:12px\">{icon}</div>'\n                f'<div style=\"font-size:0.62rem;font-weight:800;letter-spacing:0.15em;text-transform:uppercase;'\n                f'color:#3182ce;margin-bottom:8px\">Step {num}</div>'\n                f'<div style=\"font-size:0.95rem;font-weight:700;color:#e2e8f0;margin-bottom:10px\">{title}</div>'\n                f'<div style=\"font-size:0.8rem;color:#4a5568;line-height:1.6\">{desc}</div></div>',\n                unsafe_allow_html=True\n            )\n\n    st.markdown('<div style=\"margin-top:24px\"></div>', unsafe_allow_html=True)\n    st.markdown(\n        '<div style=\"background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.07);'\n        'border-left:4px solid #f6ad55;border-radius:0 12px 12px 0;padding:20px 24px\">'\n        '<div style=\"font-size:1rem;font-weight:700;color:#f6ad55;margin-bottom:8px\">\u26a0\ufe0f Novel Contribution: Graceful Partial DFD Analysis</div>'\n        '<div style=\"font-size:0.85rem;color:#718096;line-height:1.7\">'\n        'Standard threat modeling tools <strong style=\"color:#fc8181\">refuse to analyze</strong> incomplete DFDs. '\n        'SecureByDesign instead <strong style=\"color:#68d391\">degrades confidence levels proportionally</strong> \u2014 '\n        'reporting Low or Medium confidence findings rather than producing no output at all.<br><br>'\n        'Try <strong style=\"color:#f6ad55\">\u26a0\ufe0f Partial DFD</strong> in the sidebar to see this live.'\n        '</div></div>',\n        unsafe_allow_html=True\n    )\n"
cells.append(writefile_cell("/kaggle/working/SecureByDesign/app/streamlit_app.py", _app_content))
cells.append(code('print("\u2705 Premium Streamlit app written.")'))

# ---------- PHASE 5: LAUNCH ----------
cells.append(md("""## Phase 5 — Launch Demo via ngrok
> **Requires:** `NGROK_TOKEN` in Kaggle Secrets — get free token at [ngrok.com](https://ngrok.com).
"""))
cells.append(code("""\
!pip install pyngrok plotly --quiet

from pyngrok import ngrok
from kaggle_secrets import UserSecretsClient
import subprocess, time, os, signal

# Kill any running Streamlit on 8501
try:
    subprocess.run(["pkill", "-f", "streamlit"], capture_output=True)
    time.sleep(2)
    print("✅ Cleared previous Streamlit processes")
except Exception:
    pass

try:
    ngrok_token = UserSecretsClient().get_secret("NGROK_TOKEN")
    ngrok.set_auth_token(ngrok_token)
    print("✅ Ngrok token set from Kaggle Secrets")
except Exception as e:
    print(f"⚠️  Could not get NGROK_TOKEN: {e}")
    print("   Add it via Add-ons → Secrets → NGROK_TOKEN")

ngrok.kill()

proc = subprocess.Popen([
    "streamlit", "run", "/kaggle/working/SecureByDesign/app/streamlit_app.py",
    "--server.port", "8501",
    "--server.headless", "true",
    "--browser.gatherUsageStats", "false"
])
time.sleep(8)

try:
    url = ngrok.connect(8501)
    print("\\n" + "="*60)
    print(f"🔐 SecureByDesign Public Demo URL: {url}")
    print("="*60)
    print("Share this URL with your supervisor. Keep this cell running!")
except Exception as e:
    print(f"❌ Failed to create tunnel: {e}")
"""))

# ── ASSEMBLE & WRITE ────────────────────────────────────────────────────────

notebook = {
    "nbformat": 4,
    "nbformat_minor": 5,
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.10.12"}
    },
    "cells": cells
}

with open(OUT_NB, "w", encoding="utf-8") as f:
    json.dump(notebook, f, indent=1, ensure_ascii=True)

print(f"\n✅ Notebook written → {OUT_NB}")
print(f"   Total cells: {len(cells)}")
print(f"   File size:   {OUT_NB.stat().st_size / 1024:.1f} KB")
print("\nNext step: Upload SecureByDesign_COMPLETE.ipynb to Kaggle and run top-to-bottom.")
