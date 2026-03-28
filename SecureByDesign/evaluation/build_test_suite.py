"""
Build Test Suite for SecureByDesign Evaluation
Converts microSecEnD dataset JSONs into SecureByDesign DFD format + ground truth.

Usage (from SecureByDesign/ directory):
    python -m evaluation.build_test_suite

Or on Kaggle:
    %run /kaggle/working/SecureByDesign/evaluation/build_test_suite.py
"""

import json
import os
import sys

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

MICROSECEND_DIR = os.path.join(PROJECT_ROOT, "data", "microSecEnD", "dataset")
OUTPUT_DFD_DIR = os.path.join(SCRIPT_DIR, "test_dfds")
GROUND_TRUTH_PATH = os.path.join(SCRIPT_DIR, "ground_truth.json")

# ── STRIDE ground truth derivation from microSecEnD stereotypes ───────────────

# Service-level stereotype → STRIDE mapping
SERVICE_STEREOTYPE_TO_STRIDE = {
    "plaintext_credentials":    ["Information Disclosure", "Tampering"],
    "csrf_disabled":            ["Tampering"],
    "basic_authentication":     [],                   # auth IS present, not a threat by itself
    "authentication":           [],                   # positive indicator
    "authorization":            [],                   # positive indicator
    "local_logging":            [],                   # positive indicator (reduces Repudiation risk)
    "token_server":             [],
    "encryption":               [],
}

# Flow-level stereotype → STRIDE mapping
FLOW_STEREOTYPE_TO_STRIDE = {
    "plaintext_credentials_link":                   ["Information Disclosure", "Tampering"],
    "authentication_with_plaintext_credentials":    ["Information Disclosure", "Spoofing"],
}

# Structural gap detectors (absence-based threats)
def _detect_structural_threats(services, flows, external_entities):
    """Detect STRIDE threats from missing security controls."""
    threats = set()

    # ── Spoofing: any flow without authentication ──────────────────────────
    for flow in flows:
        stereotypes = flow.get("stereotypes", [])
        if "authenticated" not in stereotypes:
            threats.add("Spoofing")
            break

    # ── Repudiation: any service without local_logging ─────────────────────
    business_services = [s for s in services
                         if "infrastructural" not in s.get("stereotypes", [])
                         and "database" not in s.get("stereotypes", [])]
    for svc in business_services:
        if "local_logging" not in svc.get("stereotypes", []):
            threats.add("Repudiation")
            break

    # ── Denial of Service: entrypoint/gateway exists (always a risk) ───────
    for svc in services:
        st = svc.get("stereotypes", [])
        if "entrypoint" in st or "gateway" in st:
            threats.add("Denial of Service")
            break

    # ── Elevation of Privilege: any service without authorization ──────────
    for svc in business_services:
        if "authorization" not in svc.get("stereotypes", []):
            threats.add("Elevation of Privilege")
            break

    return threats


def derive_ground_truth(services, flows, external_entities):
    """Derive expected STRIDE categories from microSecEnD security stereotypes."""
    stride_set = set()

    # 1) Service-level stereotypes
    for svc in services:
        for st in svc.get("stereotypes", []):
            for cat in SERVICE_STEREOTYPE_TO_STRIDE.get(st, []):
                stride_set.add(cat)

    # 2) Flow-level stereotypes
    for flow in flows:
        for st in flow.get("stereotypes", []):
            for cat in FLOW_STEREOTYPE_TO_STRIDE.get(st, []):
                stride_set.add(cat)

    # 3) Structural (absence-based) threats
    stride_set |= _detect_structural_threats(services, flows, external_entities)

    return sorted(stride_set)


# ── DFD conversion ────────────────────────────────────────────────────────────

def _classify_node_type(svc):
    """Classify a microSecEnD service into DFD node type."""
    st = svc.get("stereotypes", [])
    if "database" in st:
        return "datastore"
    return "process"


def _classify_ext_entity_type(ent):
    return "external_entity"


def _flow_protocol(flow):
    st = flow.get("stereotypes", [])
    if "jdbc" in st:
        return "JDBC"
    if "restful_http" in st:
        return "HTTP/REST"
    return None


def _flow_authenticated(flow):
    st = flow.get("stereotypes", [])
    if "authenticated" in st:
        return True
    return None


def _flow_encrypted(flow):
    st = flow.get("stereotypes", [])
    if "plaintext_credentials_link" in st:
        return False
    if "encryption" in st:
        return True
    return None


def convert_microsecend_to_dfd(project_name, data):
    """Convert one microSecEnD JSON into SecureByDesign DFD format."""
    services = data.get("services", [])
    flows = data.get("information_flows", [])
    external_entities = data.get("external_entities", [])

    # Build nodes
    nodes = []
    node_names = set()

    for i, svc in enumerate(services):
        name = svc["name"]
        node_names.add(name)
        nodes.append({
            "id": f"S{i+1}",
            "type": _classify_node_type(svc),
            "name": name,
            "description": ", ".join(svc.get("stereotypes", [])[:3]) or None,
        })

    for i, ent in enumerate(external_entities):
        name = ent["name"]
        node_names.add(name)
        nodes.append({
            "id": f"EXT{i+1}",
            "type": "external_entity",
            "name": name,
            "description": ", ".join(ent.get("stereotypes", [])[:3]) or None,
        })

    # Build name→id lookup
    name_to_id = {n["name"]: n["id"] for n in nodes}

    # Build edges
    edges = []
    for i, flow in enumerate(flows):
        sender = flow.get("sender", "")
        receiver = flow.get("receiver", "")

        # Skip flows with unknown endpoints
        if sender not in name_to_id or receiver not in name_to_id:
            continue

        edges.append({
            "id": f"F{i+1}",
            "from": name_to_id[sender],
            "to": name_to_id[receiver],
            "data_description": f"{sender} → {receiver} data flow",
            "protocol": _flow_protocol(flow),
            "authenticated": _flow_authenticated(flow),
            "encrypted": _flow_encrypted(flow),
        })

    # Trust boundaries: group gateway/entrypoint as boundary
    trust_boundaries = []
    gateway_nodes = [n for n in nodes if any(
        s in (next((svc.get("stereotypes", []) for svc in services if svc["name"] == n["name"]), []))
        for s in ["gateway", "entrypoint"]
    )]
    ext_nodes = [n for n in nodes if n["type"] == "external_entity"]

    if gateway_nodes and ext_nodes:
        trust_boundaries.append({
            "id": "TB1",
            "name": "Internet Boundary",
            "separates": [ext_nodes[0]["id"], gateway_nodes[0]["id"]]
        })

    internal_svcs = [n for n in nodes if n["type"] == "process"
                     and n["id"] not in [g["id"] for g in gateway_nodes]]
    datastores = [n for n in nodes if n["type"] == "datastore"]
    if internal_svcs and datastores:
        trust_boundaries.append({
            "id": "TB2",
            "name": "Data Layer Boundary",
            "separates": [internal_svcs[0]["id"], datastores[0]["id"]]
        })

    # Partial info flags
    has_unknown_protocols = any(e["protocol"] is None for e in edges)
    has_unspecified_auth = any(e["authenticated"] is None for e in edges)

    dfd = {
        "dfd_id": project_name,
        "system_name": project_name.replace("_", " ").title(),
        "nodes": nodes,
        "edges": edges,
        "trust_boundaries": trust_boundaries,
        "partial_info_flags": {
            "missing_trust_boundaries": len(trust_boundaries) == 0,
            "unknown_protocols": has_unknown_protocols,
            "unspecified_auth": has_unspecified_auth,
            "incomplete_nodes": False,
        }
    }

    return dfd


# ── Main ──────────────────────────────────────────────────────────────────────

def build_test_suite():
    """Build the complete test suite from microSecEnD dataset."""
    os.makedirs(OUTPUT_DFD_DIR, exist_ok=True)

    # Find all project directories with JSON files
    ground_truth = {}
    count = 0

    for project_dir in sorted(os.listdir(MICROSECEND_DIR)):
        project_path = os.path.join(MICROSECEND_DIR, project_dir)
        if not os.path.isdir(project_path):
            continue

        # Find the main project JSON (not traceability/rules files)
        json_files = [f for f in os.listdir(project_path)
                      if f.endswith(".json")
                      and "traceability" not in f
                      and "rules" not in f]

        if not json_files:
            continue

        main_json = os.path.join(project_path, json_files[0])
        try:
            with open(main_json, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            print(f"  [SKIP] {project_dir}: JSON decode error")
            continue

        if "services" not in data:
            print(f"  [SKIP] {project_dir}: no 'services' key")
            continue

        # Convert to DFD
        dfd = convert_microsecend_to_dfd(project_dir, data)

        # Save DFD
        dfd_path = os.path.join(OUTPUT_DFD_DIR, f"{project_dir}.json")
        with open(dfd_path, "w", encoding="utf-8") as f:
            json.dump(dfd, f, indent=2)

        # Derive ground truth
        services = data.get("services", [])
        flows = data.get("information_flows", [])
        ext_entities = data.get("external_entities", [])

        expected_stride = derive_ground_truth(services, flows, ext_entities)

        ground_truth[project_dir] = {
            "system_name": dfd["system_name"],
            "expected_stride_categories": expected_stride,
            "num_nodes": len(dfd["nodes"]),
            "num_edges": len(dfd["edges"]),
            "num_expected_threats": len(expected_stride),
            "source": f"microSecEnD/{project_dir}",
        }

        count += 1
        print(f"  [OK] {project_dir}: {len(dfd['nodes'])} nodes, "
              f"{len(dfd['edges'])} edges, STRIDE={expected_stride}")

    # Save ground truth
    with open(GROUND_TRUTH_PATH, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)

    print(f"\n{'='*60}")
    print(f"TEST SUITE BUILT SUCCESSFULLY")
    print(f"  Test DFDs : {count} files in {OUTPUT_DFD_DIR}")
    print(f"  Ground Truth: {GROUND_TRUTH_PATH}")
    print(f"{'='*60}")

    return count, ground_truth


if __name__ == "__main__":
    build_test_suite()
