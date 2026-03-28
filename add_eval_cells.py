"""
Patch SecureByDesign_COMPLETE.ipynb to add Phase 3 evaluation cells.
Run once: python add_eval_cells.py
"""
import json
import os

NOTEBOOK_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "SecureByDesign_COMPLETE.ipynb"
)

# Phase 3 cells to insert
EVAL_CELLS = [
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## Phase 3 \u2014 Evaluation Harness\n",
            "Run the AI pipeline on 17 real microservice DFDs from the **microSecEnD** dataset and compute Precision, Recall, and F1-Score against STRIDE ground truth.\n",
            "\n",
            "> **Requires:** `GROQ_API_KEY` in Kaggle Secrets \u2014 get free key at [console.groq.com/keys](https://console.groq.com/keys).\n",
            "\n",
            "**Ground truth derivation:** STRIDE categories are derived from security stereotypes in microSecEnD:\n",
            "- `plaintext_credentials` \u2192 Information Disclosure + Tampering\n",
            "- `csrf_disabled` \u2192 Tampering\n",
            "- Missing `authentication` on flows \u2192 Spoofing\n",
            "- Missing `local_logging` \u2192 Repudiation\n",
            "- `entrypoint`/`gateway` without rate limiting \u2192 Denial of Service\n",
            "- Missing `authorization` on business services \u2192 Elevation of Privilege"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# \u2500\u2500 Step 3.1: Build Test Suite from microSecEnD \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n",
            "import json, os, sys\n",
            "\n",
            "WORK = '/kaggle/working/SecureByDesign'\n",
            "EVAL_DIR = f'{WORK}/evaluation'\n",
            "TEST_DFD_DIR = f'{EVAL_DIR}/test_dfds'\n",
            "MICROSECEND = f'{WORK}/data/microSecEnD/dataset'\n",
            "os.makedirs(TEST_DFD_DIR, exist_ok=True)\n",
            "\n",
            "STRIDE_CATS = ['Spoofing','Tampering','Repudiation','Information Disclosure','Denial of Service','Elevation of Privilege']\n",
            "\n",
            "SVC_ST = {'plaintext_credentials': ['Information Disclosure','Tampering'], 'csrf_disabled': ['Tampering']}\n",
            "FLOW_ST = {'plaintext_credentials_link': ['Information Disclosure','Tampering'],\n",
            "           'authentication_with_plaintext_credentials': ['Information Disclosure','Spoofing']}\n",
            "\n",
            "def derive_gt(services, flows, ext):\n",
            "    s = set()\n",
            "    for svc in services:\n",
            "        for st in svc.get('stereotypes', []):\n",
            "            for c in SVC_ST.get(st, []): s.add(c)\n",
            "    for fl in flows:\n",
            "        for st in fl.get('stereotypes', []):\n",
            "            for c in FLOW_ST.get(st, []): s.add(c)\n",
            "        if 'authenticated' not in fl.get('stereotypes', []): s.add('Spoofing')\n",
            "    biz = [sv for sv in services if 'infrastructural' not in sv.get('stereotypes',[]) and 'database' not in sv.get('stereotypes',[])]\n",
            "    for sv in biz:\n",
            "        if 'local_logging' not in sv.get('stereotypes',[]): s.add('Repudiation'); break\n",
            "    for sv in services:\n",
            "        if 'entrypoint' in sv.get('stereotypes',[]) or 'gateway' in sv.get('stereotypes',[]): s.add('Denial of Service'); break\n",
            "    for sv in biz:\n",
            "        if 'authorization' not in sv.get('stereotypes',[]): s.add('Elevation of Privilege'); break\n",
            "    return sorted(s)\n",
            "\n",
            "def convert(name, data):\n",
            "    svcs = data.get('services',[]); flows = data.get('information_flows',[]); exts = data.get('external_entities',[])\n",
            "    nodes, nmap = [], {}\n",
            "    for i, sv in enumerate(svcs):\n",
            "        nid = f'S{i+1}'; nmap[sv['name']] = nid\n",
            "        nodes.append({'id':nid, 'type':'datastore' if 'database' in sv.get('stereotypes',[]) else 'process', 'name':sv['name']})\n",
            "    for i, e in enumerate(exts):\n",
            "        nid = f'EXT{i+1}'; nmap[e['name']] = nid\n",
            "        nodes.append({'id':nid, 'type':'external_entity', 'name':e['name']})\n",
            "    edges = []\n",
            "    for i, fl in enumerate(flows):\n",
            "        if fl['sender'] not in nmap or fl['receiver'] not in nmap: continue\n",
            "        st = fl.get('stereotypes',[])\n",
            "        edges.append({'id':f'F{i+1}','from':nmap[fl['sender']],'to':nmap[fl['receiver']],\n",
            "            'data_description':f\"{fl['sender']} -> {fl['receiver']}\",\n",
            "            'protocol':'JDBC' if 'jdbc' in st else 'HTTP/REST' if 'restful_http' in st else None,\n",
            "            'authenticated': True if 'authenticated' in st else None,\n",
            "            'encrypted': False if 'plaintext_credentials_link' in st else None})\n",
            "    tb = []\n",
            "    gw = [n for n in nodes if any(s in next((sv.get('stereotypes',[]) for sv in svcs if sv['name']==n['name']),[]) for s in ['gateway','entrypoint'])]\n",
            "    en = [n for n in nodes if n['type']=='external_entity']\n",
            "    if gw and en: tb.append({'id':'TB1','name':'Internet Boundary','separates':[en[0]['id'],gw[0]['id']]})\n",
            "    return {'dfd_id':name,'system_name':name.replace('_',' ').title(),'nodes':nodes,'edges':edges,'trust_boundaries':tb,\n",
            "            'partial_info_flags':{'missing_trust_boundaries':len(tb)==0,'unknown_protocols':any(e['protocol'] is None for e in edges),\n",
            "                                  'unspecified_auth':any(e['authenticated'] is None for e in edges),'incomplete_nodes':False}}\n",
            "\n",
            "ground_truth = {}\n",
            "count = 0\n",
            "for pdir in sorted(os.listdir(MICROSECEND)):\n",
            "    ppath = os.path.join(MICROSECEND, pdir)\n",
            "    if not os.path.isdir(ppath): continue\n",
            "    jsons = [f for f in os.listdir(ppath) if f.endswith('.json') and 'traceability' not in f and 'rules' not in f]\n",
            "    if not jsons: continue\n",
            "    with open(os.path.join(ppath, jsons[0]), 'r') as f:\n",
            "        try: data = json.load(f)\n",
            "        except: continue\n",
            "    if 'services' not in data: continue\n",
            "    dfd = convert(pdir, data)\n",
            "    with open(f'{TEST_DFD_DIR}/{pdir}.json','w') as f: json.dump(dfd, f, indent=2)\n",
            "    svcs = data.get('services',[]); flows = data.get('information_flows',[]); exts = data.get('external_entities',[])\n",
            "    gt = derive_gt(svcs, flows, exts)\n",
            "    ground_truth[pdir] = {'system_name':dfd['system_name'],'expected_stride_categories':gt,\n",
            "                          'num_nodes':len(dfd['nodes']),'num_edges':len(dfd['edges'])}\n",
            "    count += 1\n",
            "    print(f'  [{count}] {pdir}: {len(dfd[\"nodes\"])} nodes, {len(dfd[\"edges\"])} edges, STRIDE={gt}')\n",
            "\n",
            "with open(f'{EVAL_DIR}/ground_truth.json','w') as f: json.dump(ground_truth, f, indent=2)\n",
            "print(f'\\n\\u2705 Test suite built: {count} DFDs with ground truth')"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# \u2500\u2500 Step 3.2: Run Full Evaluation \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n",
            "# This calls analyze_dfd() for each of the 17 test DFDs and computes metrics.\n",
            "# NOTE: Takes ~2-5 min depending on Groq rate limits.\n",
            "\n",
            "import time\n",
            "from datetime import datetime\n",
            "sys.path.insert(0, WORK)\n",
            "from pipeline.inference import analyze_dfd\n",
            "\n",
            "with open(f'{EVAL_DIR}/ground_truth.json') as f:\n",
            "    ground_truth = json.load(f)\n",
            "\n",
            "results = []\n",
            "print(f'\\n{\"=\"*60}')\n",
            "print('SECUREBYDESIGN EVALUATION RUN')\n",
            "print(f'Timestamp: {datetime.now().isoformat()}')\n",
            "print(f'{\"=\"*60}\\n')\n",
            "\n",
            "test_files = sorted([f for f in os.listdir(TEST_DFD_DIR) if f.endswith('.json')])\n",
            "for i, fname in enumerate(test_files):\n",
            "    dfd_id = fname.replace('.json','')\n",
            "    if dfd_id not in ground_truth: continue\n",
            "    with open(f'{TEST_DFD_DIR}/{fname}') as f: dfd_json = json.load(f)\n",
            "    gt = ground_truth[dfd_id]\n",
            "    t0 = time.time()\n",
            "    try:\n",
            "        result = analyze_dfd(dfd_json, '')\n",
            "        dur = time.time() - t0\n",
            "        err = result.get('error')\n",
            "    except Exception as e:\n",
            "        dur = time.time() - t0\n",
            "        results.append({'dfd_id':dfd_id,'precision':0,'recall':0,'f1':0,'threats':0,'error':str(e)})\n",
            "        print(f'  [{i+1}/{len(test_files)}] {dfd_id}: ERROR - {e}')\n",
            "        time.sleep(2); continue\n",
            "    pred = list(set(t.get('stride_category') for t in result.get('threats',[]) if t.get('stride_category') in STRIDE_CATS))\n",
            "    exp = gt.get('expected_stride_categories',[])\n",
            "    ev, pv = [1 if c in exp else 0 for c in STRIDE_CATS], [1 if c in pred else 0 for c in STRIDE_CATS]\n",
            "    tp = sum(e==1 and p==1 for e,p in zip(ev,pv))\n",
            "    fp = sum(e==0 and p==1 for e,p in zip(ev,pv))\n",
            "    fn = sum(e==1 and p==0 for e,p in zip(ev,pv))\n",
            "    prec = tp/(tp+fp) if tp+fp else 0; rec = tp/(tp+fn) if tp+fn else 0\n",
            "    f1 = 2*prec*rec/(prec+rec) if prec+rec else 0\n",
            "    results.append({'dfd_id':dfd_id,'precision':round(prec,3),'recall':round(rec,3),'f1':round(f1,3),\n",
            "                    'threats':len(result.get('threats',[])), 'risk':result.get('overall_risk_level','?'),\n",
            "                    'duration':round(dur,1),'error':err,'predicted':pred,'expected':exp})\n",
            "    print(f'  [{i+1}/{len(test_files)}] {dfd_id}: P={prec:.3f} R={rec:.3f} F1={f1:.3f} threats={len(result.get(\"threats\",[]))}')\n",
            "    time.sleep(2)  # rate limit\n",
            "\n",
            "# \u2500\u2500 Aggregate Results \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n",
            "valid = [r for r in results if r.get('error') is None]\n",
            "if valid:\n",
            "    avg_p = sum(r['precision'] for r in valid)/len(valid)\n",
            "    avg_r = sum(r['recall'] for r in valid)/len(valid)\n",
            "    avg_f1 = sum(r['f1'] for r in valid)/len(valid)\n",
            "else:\n",
            "    avg_p = avg_r = avg_f1 = 0\n",
            "\n",
            "print(f'\\n{\"=\"*60}')\n",
            "print(f'AGGREGATE RESULTS ({len(valid)}/{len(results)} successful)')\n",
            "print(f'{\"-\"*60}')\n",
            "print(f'  Macro Precision : {avg_p:.3f}')\n",
            "print(f'  Macro Recall    : {avg_r:.3f}')\n",
            "print(f'  Macro F1-Score  : {avg_f1:.3f}')\n",
            "print(f'{\"=\"*60}')\n",
            "\n",
            "# Save results\n",
            "os.makedirs(f'{EVAL_DIR}/results', exist_ok=True)\n",
            "ts = datetime.now().strftime('%Y%m%d_%H%M%S')\n",
            "rpath = f'{EVAL_DIR}/results/evaluation_{ts}.json'\n",
            "with open(rpath, 'w') as f:\n",
            "    json.dump({'aggregate':{'precision':round(avg_p,3),'recall':round(avg_r,3),'f1':round(avg_f1,3)},\n",
            "               'per_dfd':results}, f, indent=2, default=str)\n",
            "print(f'\\nResults saved: {rpath}')"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# \u2500\u2500 Step 3.3: Display Results Table \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n",
            "import pandas as pd\n",
            "\n",
            "df = pd.DataFrame(results)[['dfd_id','precision','recall','f1','threats','error']]\n",
            "df = df.rename(columns={'dfd_id':'DFD','precision':'Precision','recall':'Recall','f1':'F1','threats':'Threats'})\n",
            "display(df.style.format({'Precision':'{:.3f}','Recall':'{:.3f}','F1':'{:.3f}'}).background_gradient(subset=['F1'], cmap='RdYlGn'))\n",
            "\n",
            "print(f'\\nMacro Average \\u2014 Precision: {avg_p:.3f} | Recall: {avg_r:.3f} | F1: {avg_f1:.3f}')"
        ]
    }
]


def patch_notebook():
    """Insert Phase 3 evaluation cells into the notebook."""
    with open(NOTEBOOK_PATH, "r", encoding="utf-8") as f:
        nb = json.load(f)

    cells = nb["cells"]

    # Find insertion point: after the "Streamlit app written" print cell,
    # before Phase 5 ngrok cell
    insert_idx = None
    for i, cell in enumerate(cells):
        src = "".join(cell.get("source", []))
        if "Streamlit app written" in src:
            insert_idx = i + 1
            break

    if insert_idx is None:
        # Fallback: insert before the last 2 cells (Phase 5)
        for i, cell in enumerate(cells):
            src = "".join(cell.get("source", []))
            if "Phase 5" in src or "ngrok" in src.lower():
                insert_idx = i
                break

    if insert_idx is None:
        # Last resort: append before metadata
        insert_idx = len(cells)

    # Check if already patched (look for our specific evaluation runner code)
    for cell in cells:
        src = "".join(cell.get("source", []))
        if "Step 3.2: Run Full Evaluation" in src:
            print("Phase 3 evaluation cells already present in notebook. Skipping.")
            return

    # Insert cells
    for j, cell in enumerate(EVAL_CELLS):
        cells.insert(insert_idx + j, cell)

    nb["cells"] = cells

    with open(NOTEBOOK_PATH, "w", encoding="utf-8") as f:
        json.dump(nb, f, indent=1, ensure_ascii=False)

    print(f"[OK] Inserted {len(EVAL_CELLS)} Phase 3 evaluation cells at position {insert_idx}")
    print(f"     Notebook saved: {NOTEBOOK_PATH}")


if __name__ == "__main__":
    patch_notebook()
