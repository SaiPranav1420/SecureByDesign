"""
DFD Parser for SecureByDesign
Parses DFD JSON into structured context objects for the LLM inference pipeline.

Supports ANY DFD JSON format by dynamically normalizing keys before processing.
Users can submit DFDs with 'name' or 'label', 'from'/'source'/'src',
'datastore'/'data_store'/'database', etc. — all handled automatically.

Author: Person A
Project: SecureByDesign — Explainable LLM-Based STRIDE Threat Inference
"""

import json
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime


# ============================================================
# DYNAMIC KEY ALIAS MAPS
# ============================================================
# Each canonical key → list of alternative keys that should map to it.
# The normalizer walks these in order and uses the first match found.

# Top-level DFD fields
_TOP_LEVEL_ALIASES = {
    'dfd_id':            ['dfd_id', 'id', 'diagram_id', 'dfdId', 'dfd_identifier', 'diagramId'],
    'system_name':       ['system_name', 'name', 'systemName', 'title', 'system', 'project_name',
                          'project', 'application_name', 'app_name', 'service_name'],
    'nodes':             ['nodes', 'elements', 'components', 'entities', 'objects', 'items'],
    'edges':             ['edges', 'flows', 'data_flows', 'dataFlows', 'connections', 'links',
                          'arrows', 'transitions', 'communications', 'interactions'],
    'trust_boundaries':  ['trust_boundaries', 'trustBoundaries', 'boundaries', 'trust_zones',
                          'trustZones', 'zones', 'security_boundaries'],
    'partial_info_flags':['partial_info_flags', 'partialInfoFlags', 'partial_flags', 'flags',
                          'metadata', 'meta'],
}

# Node-level fields
_NODE_ALIASES = {
    'id':              ['id', 'node_id', 'nodeId', 'identifier', 'key', 'uid', 'element_id'],
    'name':            ['name', 'label', 'title', 'display_name', 'displayName', 'node_name',
                        'nodeName', 'text', 'caption', 'description_short'],
    'type':            ['type', 'node_type', 'nodeType', 'kind', 'category', 'element_type',
                        'elementType', 'class', 'role'],
    'description':     ['description', 'desc', 'details', 'notes', 'info', 'summary', 'tooltip'],
    'vulnerabilities': ['vulnerabilities', 'vulns', 'weaknesses', 'issues', 'risks',
                        'security_issues', 'threats', 'findings', 'problems', 'concerns'],
}

# Edge-level fields
_EDGE_ALIASES = {
    'id':               ['id', 'edge_id', 'edgeId', 'flow_id', 'flowId', 'identifier', 'key'],
    'from':             ['from', 'source', 'src', 'from_node', 'fromNode', 'source_id',
                         'sourceId', 'from_id', 'fromId', 'origin', 'start', 'sender'],
    'to':               ['to', 'target', 'dst', 'dest', 'destination', 'to_node', 'toNode',
                         'target_id', 'targetId', 'to_id', 'toId', 'end', 'receiver', 'sink'],
    'label':            ['label', 'name', 'title', 'flow_name', 'flowName', 'display_name',
                         'text', 'caption'],
    'data_description': ['data_description', 'dataDescription', 'data', 'description',
                         'desc', 'details', 'payload', 'content', 'message'],
    'protocol':         ['protocol', 'transport', 'communication_type', 'channel', 'method',
                         'transport_protocol'],
    'authenticated':    ['authenticated', 'auth', 'is_authenticated', 'isAuthenticated',
                         'requires_auth', 'authentication'],
    'encrypted':        ['encrypted', 'is_encrypted', 'isEncrypted', 'encryption', 'tls',
                         'ssl', 'https'],
    'vulnerabilities':  ['vulnerabilities', 'vulns', 'weaknesses', 'issues', 'risks',
                         'security_issues', 'findings'],
}

# Node type normalization: maps various type strings → canonical types
_NODE_TYPE_ALIASES = {
    'external_entity': [
        'external_entity', 'external entity', 'externalentity', 'entity', 'actor',
        'user', 'client', 'external', 'ext_entity', 'external_actor', 'consumer',
        'producer', 'third_party', 'third party', 'api_consumer', 'terminal',
        'interactor', 'external system', 'external_system',
    ],
    'process': [
        'process', 'service', 'function', 'module', 'handler', 'controller',
        'processor', 'logic', 'computation', 'transform', 'microservice',
        'api', 'endpoint', 'server', 'application', 'component', 'task',
        'action', 'operation', 'workflow', 'step', 'activity',
    ],
    'datastore': [
        'datastore', 'data_store', 'data store', 'database', 'db', 'storage',
        'repository', 'cache', 'file', 'filesystem', 'file_system', 'queue',
        'message_queue', 'data', 'table', 'collection', 'bucket', 'store',
        'persistence', 'log', 'log_store', 'data_lake', 'warehouse',
    ],
}


# ============================================================
# NORMALIZER
# ============================================================

def _resolve_key(source: dict, aliases: List[str], default=None):
    """Return the value of the first matching alias key found in source."""
    for alias in aliases:
        if alias in source:
            return source[alias]
    # Try case-insensitive match as last resort
    lower_map = {k.lower().replace('-', '_').replace(' ', '_'): k for k in source}
    for alias in aliases:
        normalized = alias.lower().replace('-', '_').replace(' ', '_')
        if normalized in lower_map:
            return source[lower_map[normalized]]
    return default


def _normalize_node_type(raw_type: str) -> str:
    """Map any node type string to one of the three canonical types."""
    cleaned = raw_type.lower().strip().replace('-', '_').replace(' ', '_')
    for canonical, variants in _NODE_TYPE_ALIASES.items():
        if cleaned in [v.replace(' ', '_') for v in variants]:
            return canonical
    # Fallback: check if the type string *contains* a known keyword
    for canonical, variants in _NODE_TYPE_ALIASES.items():
        for v in variants:
            if v.replace(' ', '_') in cleaned or cleaned in v.replace(' ', '_'):
                return canonical
    return raw_type  # Return as-is; parser will treat as process


def _normalize_node(raw_node: dict) -> dict:
    """Normalize a single node dict to canonical keys."""
    normalized = {}

    # Preserve ALL original keys (so extra data like vulnerabilities are kept)
    for k, v in raw_node.items():
        normalized[k] = v

    # Override with canonical keys
    for canonical_key, aliases in _NODE_ALIASES.items():
        val = _resolve_key(raw_node, aliases)
        if val is not None:
            normalized[canonical_key] = val

    # Normalize the type field
    if 'type' in normalized:
        normalized['type'] = _normalize_node_type(str(normalized['type']))

    # Ensure 'name' field exists (fallback chain: name → label → id → 'Unknown')
    if 'name' not in normalized or not normalized['name']:
        normalized['name'] = normalized.get('label', normalized.get('id', 'Unknown'))

    return normalized


def _normalize_edge(raw_edge: dict) -> dict:
    """Normalize a single edge dict to canonical keys."""
    normalized = {}

    # Preserve ALL original keys
    for k, v in raw_edge.items():
        normalized[k] = v

    # Override with canonical keys
    for canonical_key, aliases in _EDGE_ALIASES.items():
        val = _resolve_key(raw_edge, aliases)
        if val is not None:
            normalized[canonical_key] = val

    # If no data_description but a label exists, use label as data description
    if 'data_description' not in normalized and 'label' in normalized:
        normalized['data_description'] = normalized['label']

    return normalized


def normalize_dfd_json(dfd_json: dict) -> dict:
    """
    DYNAMIC DFD NORMALIZER
    ======================
    Accepts ANY DFD JSON format and normalizes it to the canonical schema
    expected by the parser.

    Handles:
    - Alternative key names (label/name, source/from, target/to, etc.)
    - Alternative node type values (entity/actor/user → external_entity, etc.)
    - CamelCase / snake_case / mixed-case keys
    - Alternative top-level field names (components/elements → nodes, etc.)
    - Missing fields (provides safe defaults)
    - Preserves all extra/unknown fields for downstream use

    This function should be called BEFORE parse_dfd() to guarantee
    format-agnostic parsing.
    """
    normalized = {}

    # ── Resolve top-level fields ──────────────────────────────────────────────
    for canonical_key, aliases in _TOP_LEVEL_ALIASES.items():
        val = _resolve_key(dfd_json, aliases)
        if val is not None:
            normalized[canonical_key] = val

    # ── Defaults for required top-level fields ────────────────────────────────
    if 'dfd_id' not in normalized:
        # Auto-generate a DFD ID if missing
        normalized['dfd_id'] = f"auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    if 'system_name' not in normalized:
        normalized['system_name'] = 'Unknown System'

    if 'nodes' not in normalized:
        normalized['nodes'] = []

    if 'edges' not in normalized:
        normalized['edges'] = []

    # ── Normalize each node ───────────────────────────────────────────────────
    raw_nodes = normalized.get('nodes', [])
    normalized_nodes = []
    for i, node in enumerate(raw_nodes):
        if isinstance(node, dict):
            n = _normalize_node(node)
            # Ensure every node has an id
            if 'id' not in n:
                n['id'] = f"node_{i}"
            normalized_nodes.append(n)
        elif isinstance(node, str):
            # Handle case where nodes are just strings (names)
            normalized_nodes.append({
                'id': f"node_{i}",
                'name': node,
                'type': 'process',
            })
    normalized['nodes'] = normalized_nodes

    # ── Normalize each edge ───────────────────────────────────────────────────
    raw_edges = normalized.get('edges', [])
    normalized_edges = []
    for i, edge in enumerate(raw_edges):
        if isinstance(edge, dict):
            e = _normalize_edge(edge)
            # Ensure every edge has an id
            if 'id' not in e:
                e['id'] = f"edge_{i}"
            normalized_edges.append(e)
    normalized['edges'] = normalized_edges

    # ── Normalize trust boundaries (if present) ───────────────────────────────
    raw_tb = normalized.get('trust_boundaries', [])
    normalized_tb = []
    for tb in raw_tb:
        if isinstance(tb, dict):
            norm_tb = dict(tb)
            # Resolve name
            if 'name' not in norm_tb:
                norm_tb['name'] = norm_tb.get('label', norm_tb.get('title',
                                  norm_tb.get('id', 'Unnamed Boundary')))
            # Resolve separates
            if 'separates' not in norm_tb:
                norm_tb['separates'] = norm_tb.get('contains', norm_tb.get(
                    'members', norm_tb.get('nodes', [])))
            normalized_tb.append(norm_tb)
    normalized['trust_boundaries'] = normalized_tb

    # ── Preserve any extra top-level keys not in alias map ────────────────────
    known_keys = set()
    for aliases in _TOP_LEVEL_ALIASES.values():
        known_keys.update(aliases)
    for k, v in dfd_json.items():
        if k not in normalized and k not in known_keys:
            normalized[k] = v

    return normalized


# ============================================================
# DATA STRUCTURES
# ============================================================

@dataclass
class ParsedDFD:
    """
    Structured representation of a parsed DFD, ready for prompt construction.
    All fields are populated by parse_dfd() — never construct directly.
    """
    dfd_id: str
    system_name: str

    # Node groups (categorized by type)
    external_entities: List[Dict] = field(default_factory=list)
    processes: List[Dict] = field(default_factory=list)
    datastores: List[Dict] = field(default_factory=list)

    # Edges and boundaries
    edges: List[Dict] = field(default_factory=list)
    trust_boundaries: List[Dict] = field(default_factory=list)

    # Security-relevant analysis flags
    boundary_crossing_edges: List[Dict] = field(default_factory=list)  # Edges crossing trust boundaries
    missing_auth_edges: List[str] = field(default_factory=list)        # Edge IDs with null/unspecified auth
    missing_encryption_edges: List[str] = field(default_factory=list)  # Edge IDs with null/unspecified encryption
    unknown_protocol_edges: List[str] = field(default_factory=list)    # Edge IDs with null/unknown protocol

    # Partial DFD detection
    is_partial: bool = False
    completeness_score: float = 1.0  # 0.0 = almost no info, 1.0 = fully specified
    missing_elements: List[str] = field(default_factory=list)

    # LLM-ready text summary (built by _build_text_summary)
    text_summary: str = ""


# Convenience property — all nodes regardless of type
ParsedDFD.nodes_all = property(
    lambda self: self.external_entities + self.processes + self.datastores
)


# ============================================================
# MAIN PARSING FUNCTION
# ============================================================

def parse_dfd(dfd_json: dict) -> ParsedDFD:
    """
    Main entry point. Parse a DFD JSON dict into a ParsedDFD object.

    THIS FUNCTION IS FORMAT-AGNOSTIC. It accepts any DFD JSON structure
    and automatically normalizes it before parsing.

    Performs:
      - Dynamic key normalization (handles name/label, from/source, etc.)
      - Schema validation (required fields)
      - Node categorization by type (with fuzzy type matching)
      - Edge security property analysis
      - Trust boundary crossing detection
      - Completeness scoring and partial DFD detection
      - LLM-ready text summary generation

    Args:
        dfd_json: Raw DFD dictionary in ANY common format.
                  Will be auto-normalized to canonical schema.

    Returns:
        ParsedDFD object with all fields populated.

    Raises:
        ValueError: If the DFD JSON is completely unparseable (no nodes at all).
    """

    # ── STEP 0: Normalize to canonical format ─────────────────────────────────
    dfd_json = normalize_dfd_json(dfd_json)

    # ── Validate required fields (now guaranteed by normalizer) ───────────────
    required_fields = ['dfd_id', 'system_name', 'nodes', 'edges']
    for f in required_fields:
        if f not in dfd_json:
            raise ValueError(
                f"Missing required field in DFD JSON: '{f}'. "
                f"Required fields: {required_fields}"
            )

    parsed = ParsedDFD(
        dfd_id=dfd_json['dfd_id'],
        system_name=dfd_json['system_name']
    )

    # Build node lookup dict for name resolution in edges/boundaries
    node_lookup: Dict[str, Dict] = {
        node['id']: node for node in dfd_json.get('nodes', [])
        if 'id' in node
    }

    # ── STEP 1: Categorize nodes by type ─────────────────────────────────────
    for node in dfd_json.get('nodes', []):
        node_type = node.get('type', '').lower().strip()

        if node_type == 'external_entity':
            parsed.external_entities.append(node)
        elif node_type == 'process':
            parsed.processes.append(node)
        elif node_type == 'datastore':
            parsed.datastores.append(node)
        else:
            # Unknown node type — treat as process for analysis purposes
            # Do not drop; unknown types in real-world DFDs are common
            node_copy = dict(node)
            node_copy['_type_note'] = f"Unknown type '{node_type}' — treated as process"
            parsed.processes.append(node_copy)

    # ── STEP 2: Process edges — detect missing security properties ─────────────
    parsed.edges = dfd_json.get('edges', [])

    for edge in parsed.edges:
        edge_id = edge.get('id', 'unknown')

        # null = unspecified (our schema uses None for unknowns)
        if edge.get('authenticated') is None:
            parsed.missing_auth_edges.append(edge_id)

        if edge.get('encrypted') is None:
            parsed.missing_encryption_edges.append(edge_id)

        if edge.get('protocol') is None:
            parsed.unknown_protocol_edges.append(edge_id)

    # ── STEP 3: Load trust boundaries ────────────────────────────────────────
    parsed.trust_boundaries = dfd_json.get('trust_boundaries', [])

    # ── STEP 4: Detect trust boundary crossings ───────────────────────────────
    # An edge crosses a boundary if exactly one of its endpoints appears in
    # the boundary's 'separates' list. This is the key attack surface signal.
    for edge in parsed.edges:
        from_node = edge.get('from')
        to_node = edge.get('to')

        for boundary in parsed.trust_boundaries:
            separated = set(boundary.get('separates', []))

            # XOR: one endpoint inside, one outside
            from_inside = from_node in separated
            to_inside = to_node in separated

            if from_inside != to_inside:
                crossing_info = {
                    **edge,
                    'crossing_boundary': boundary.get('id', 'unknown'),
                    'boundary_name': boundary.get('name', 'Unknown Boundary'),
                    'from_name': node_lookup.get(from_node, {}).get('name', from_node),
                    'to_name': node_lookup.get(to_node, {}).get('name', to_node),
                }
                parsed.boundary_crossing_edges.append(crossing_info)
                break  # Each edge crosses at most one boundary in simplified model

    # ── STEP 5: Compute completeness score & detect partial DFD ──────────────
    partial_flags = dfd_json.get('partial_info_flags', {})
    if not isinstance(partial_flags, dict):
        partial_flags = {}

    missing_elements: List[str] = []
    completeness_factors: List[float] = []

    # Factor 1: Trust boundaries present?
    has_tb = bool(parsed.trust_boundaries)
    tb_flagged_missing = partial_flags.get('missing_trust_boundaries', False)
    if not has_tb or tb_flagged_missing:
        missing_elements.append(
            "Trust boundaries not defined — cannot determine attack surface perimeter"
        )
        completeness_factors.append(0.0)
    else:
        completeness_factors.append(1.0)

    # Factor 2: Authentication specified on edges
    total_edges = max(len(parsed.edges), 1)
    auth_ratio = 1.0 - (len(parsed.missing_auth_edges) / total_edges)
    completeness_factors.append(auth_ratio)
    if parsed.missing_auth_edges:
        missing_elements.append(
            f"Authentication unspecified on edges: {', '.join(parsed.missing_auth_edges)}"
        )

    # Factor 3: Encryption specified on edges
    enc_ratio = 1.0 - (len(parsed.missing_encryption_edges) / total_edges)
    completeness_factors.append(enc_ratio)
    if parsed.missing_encryption_edges:
        missing_elements.append(
            f"Encryption unspecified on edges: {', '.join(parsed.missing_encryption_edges)}"
        )

    # Factor 4: Protocols specified on edges
    proto_flagged = partial_flags.get('unknown_protocols', False)
    if proto_flagged or parsed.unknown_protocol_edges:
        missing_elements.append(
            f"Protocol unknown on edges: {', '.join(parsed.unknown_protocol_edges) or 'flagged in partial_info_flags'}"
        )
        completeness_factors.append(0.5)
    else:
        completeness_factors.append(1.0)

    # Guard: empty DFD
    if len(parsed.nodes_all) == 0:
        missing_elements.append("No nodes defined — DFD is empty")
        completeness_factors.append(0.0)

    if len(parsed.edges) == 0:
        missing_elements.append("No data flows defined — cannot analyze data movement")
        completeness_factors.append(0.0)

    parsed.completeness_score = sum(completeness_factors) / max(len(completeness_factors), 1)
    parsed.is_partial = parsed.completeness_score < 0.8 or bool(missing_elements)
    parsed.missing_elements = missing_elements

    # ── STEP 6: Build LLM-ready text summary ─────────────────────────────────
    parsed.text_summary = _build_text_summary(parsed, node_lookup)

    return parsed


# ============================================================
# TEXT SUMMARY BUILDER
# ============================================================

def _build_text_summary(parsed: ParsedDFD, node_lookup: Dict[str, Dict]) -> str:
    """
    Build a structured natural language summary of the DFD for use in LLM prompts.
    Designed to be maximally informative for STRIDE threat reasoning.
    Highlights trust boundary crossings and missing security properties prominently.

    Returns:
        Multi-line string ready for inclusion in an LLM prompt.
    """
    lines = []

    # Header
    lines.append(f"SYSTEM: {parsed.system_name}")
    lines.append(f"DFD ID: {parsed.dfd_id}")
    lines.append(f"COMPLETENESS: {parsed.completeness_score:.0%}")
    lines.append("")

    # Components
    lines.append("=== COMPONENTS ===")
    if parsed.external_entities:
        names = ', '.join(n.get('name', n.get('id', 'Unknown')) for n in parsed.external_entities)
        lines.append(f"External Entities (untrusted/outside system boundary): {names}")

        # Include vulnerabilities if present
        for n in parsed.external_entities:
            vulns = n.get('vulnerabilities', [])
            if vulns:
                lines.append(f"  ⚠ {n.get('name', n.get('id'))}: {'; '.join(vulns)}")

    if parsed.processes:
        names = ', '.join(n.get('name', n.get('id', 'Unknown')) for n in parsed.processes)
        lines.append(f"Processes (application logic): {names}")

        for n in parsed.processes:
            vulns = n.get('vulnerabilities', [])
            if vulns:
                lines.append(f"  ⚠ {n.get('name', n.get('id'))}: {'; '.join(vulns)}")

    if parsed.datastores:
        names = ', '.join(n.get('name', n.get('id', 'Unknown')) for n in parsed.datastores)
        lines.append(f"Datastores (data at rest): {names}")

        for n in parsed.datastores:
            vulns = n.get('vulnerabilities', [])
            if vulns:
                lines.append(f"  ⚠ {n.get('name', n.get('id'))}: {'; '.join(vulns)}")

    if not parsed.nodes_all:
        lines.append("  WARNING: No components defined. DFD is empty.")
    lines.append("")

    # Trust boundaries
    lines.append("=== TRUST BOUNDARIES ===")
    if parsed.trust_boundaries:
        for tb in parsed.trust_boundaries:
            separated_ids = tb.get('separates', [])
            separated_names = [node_lookup.get(n, {}).get('name', n) for n in separated_ids]
            lines.append(f"  [{tb.get('id', '?')}] {tb.get('name', 'Unnamed Boundary')}: "
                         f"separates {' | '.join(separated_names)}")
    else:
        lines.append("  WARNING: No trust boundaries defined. Attack surface cannot be determined.")
    lines.append("")

    # Data flows (all edges)
    lines.append("=== DATA FLOWS ===")
    if parsed.edges:
        for edge in parsed.edges:
            from_name = node_lookup.get(edge.get('from'), {}).get('name', edge.get('from', '?'))
            to_name = node_lookup.get(edge.get('to'), {}).get('name', edge.get('to', '?'))

            # Edge label (if present)
            edge_label = edge.get('label', edge.get('data_description', ''))

            # Authentication status
            auth_val = edge.get('authenticated')
            if auth_val is True:
                auth_str = "authenticated"
            elif auth_val is False:
                auth_str = "NOT authenticated"
            else:
                auth_str = "AUTHENTICATION UNSPECIFIED"

            # Encryption status
            enc_val = edge.get('encrypted')
            if enc_val is True:
                enc_str = "encrypted"
            elif enc_val is False:
                enc_str = "NOT encrypted"
            else:
                enc_str = "ENCRYPTION UNSPECIFIED"

            proto = edge.get('protocol') or "UNKNOWN PROTOCOL"
            data = edge.get('data_description') or edge_label or "unspecified data"

            lines.append(f"  [{edge.get('id', '?')}] {from_name} → {to_name}")
            lines.append(f"       Data: {data} | Protocol: {proto} | {auth_str} | {enc_str}")

            # Include edge vulnerabilities if present
            vulns = edge.get('vulnerabilities', [])
            if vulns:
                lines.append(f"       ⚠ Vulnerabilities: {'; '.join(vulns)}")
    else:
        lines.append("  WARNING: No data flows defined.")
    lines.append("")

    # Trust boundary crossings — highest-priority section for STRIDE analysis
    if parsed.boundary_crossing_edges:
        lines.append("=== TRUST BOUNDARY CROSSINGS (HIGH SECURITY RELEVANCE) ===")
        for crossing in parsed.boundary_crossing_edges:
            lines.append(f"  [{crossing.get('id', '?')}] {crossing.get('from_name', '?')} → {crossing.get('to_name', '?')}")
            lines.append(f"       Crosses: {crossing.get('boundary_name', 'Unknown Boundary')}")
            auth_val = crossing.get('authenticated')
            auth = "UNSPECIFIED" if auth_val is None else ("YES" if auth_val else "NO")
            enc_val = crossing.get('encrypted')
            enc = "UNSPECIFIED" if enc_val is None else ("YES" if enc_val else "NO")
            lines.append(f"       Auth: {auth} | Encrypted: {enc}")
        lines.append("")

    # Partial DFD warnings — give the LLM clear signals about uncertainty
    if parsed.is_partial:
        lines.append("=== PARTIAL DFD WARNINGS — REASON FOR LOWER CONFIDENCE ===")
        for warning in parsed.missing_elements:
            lines.append(f"  ⚠  {warning}")
        lines.append("")

    return "\n".join(lines)


# ============================================================
# SELF-TEST (run directly to verify)
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("DFD PARSER SELF-TEST")
    print("=" * 60)

    # TEST 1: Standard format with 'name' key
    print("\n--- Test 1: Standard 'name' format ---")
    sample_dfd = {
        "dfd_id": "test_001",
        "system_name": "Test Payment Service",
        "nodes": [
            {"id": "N1", "type": "external_entity", "name": "Mobile Client", "description": "User app"},
            {"id": "N2", "type": "process", "name": "API Gateway", "description": "Entry point"},
            {"id": "N3", "type": "datastore", "name": "User DB", "description": "User data"}
        ],
        "edges": [
            {"id": "E1", "from": "N1", "to": "N2", "data_description": "Login request",
             "protocol": "HTTPS", "authenticated": None, "encrypted": True},
            {"id": "E2", "from": "N2", "to": "N3", "data_description": "DB query",
             "protocol": None, "authenticated": None, "encrypted": None}
        ],
        "trust_boundaries": [
            {"id": "TB1", "name": "Internet Boundary", "separates": ["N1", "N2"]}
        ],
        "partial_info_flags": {
            "missing_trust_boundaries": False,
            "unknown_protocols": True,
            "unspecified_auth": True,
            "incomplete_nodes": False
        }
    }

    result = parse_dfd(sample_dfd)
    print(f"✅ System: {result.system_name}")
    print(f"✅ Completeness: {result.completeness_score:.0%}")
    print(f"✅ Total Nodes: {len(result.nodes_all)}")
    assert len(result.nodes_all) == 3, "Expected 3 nodes"

    # TEST 2: 'label' format (like the user's DFD)
    print("\n--- Test 2: 'label' format ---")
    label_dfd = {
        "dfd_id": "DFD-001",
        "system_name": "Online Banking Web Application",
        "nodes": [
            {"id": "E1", "type": "external_entity", "label": "Customer"},
            {"id": "P1", "type": "process", "label": "Login Process",
             "vulnerabilities": ["No rate limiting", "No MFA"]},
            {"id": "D1", "type": "data_store", "label": "User Database",
             "vulnerabilities": ["Passwords in plaintext"]},
        ],
        "edges": [
            {"from": "E1", "to": "P1", "label": "Submit Credentials (HTTP)",
             "vulnerabilities": ["Unencrypted transmission"]},
            {"from": "P1", "to": "D1", "label": "Validate Credentials"},
        ]
    }

    result2 = parse_dfd(label_dfd)
    print(f"✅ System: {result2.system_name}")
    print(f"✅ External Entities: {[n['name'] for n in result2.external_entities]}")
    print(f"✅ Processes: {[n['name'] for n in result2.processes]}")
    print(f"✅ Datastores: {[n['name'] for n in result2.datastores]}")
    assert result2.external_entities[0]['name'] == "Customer"
    assert result2.datastores[0]['name'] == "User Database"

    # TEST 3: source/target + alternative type names
    print("\n--- Test 3: Alternative keys (source/target, actor/database) ---")
    alt_dfd = {
        "id": "ALT-001",
        "title": "E-Commerce Platform",
        "elements": [
            {"id": "A1", "type": "actor", "label": "Buyer"},
            {"id": "S1", "type": "service", "name": "Order Service"},
            {"id": "DB1", "type": "database", "label": "Orders DB"},
        ],
        "flows": [
            {"source": "A1", "target": "S1", "label": "Place Order"},
            {"source": "S1", "target": "DB1", "label": "Save Order"},
        ]
    }

    result3 = parse_dfd(alt_dfd)
    print(f"✅ System: {result3.system_name}")
    print(f"✅ DFD ID: {result3.dfd_id}")
    print(f"✅ External Entities: {[n['name'] for n in result3.external_entities]}")
    print(f"✅ Processes: {[n['name'] for n in result3.processes]}")
    print(f"✅ Datastores: {[n['name'] for n in result3.datastores]}")
    print(f"✅ Edges: {len(result3.edges)}")
    assert result3.system_name == "E-Commerce Platform"
    assert result3.dfd_id == "ALT-001"
    assert len(result3.external_entities) == 1  # actor → external_entity
    assert len(result3.datastores) == 1          # database → datastore
    assert len(result3.edges) == 2               # flows → edges

    # TEST 4: Minimal / edge case
    print("\n--- Test 4: Minimal DFD ---")
    minimal = {
        "dfd_id": "minimal_001",
        "system_name": "Minimal System",
        "nodes": [{"id": "N1", "type": "process", "name": "Service"}],
        "edges": []
    }
    result4 = parse_dfd(minimal)
    print(f"✅ Completeness: {result4.completeness_score:.0%}")
    print(f"✅ Is Partial: {result4.is_partial}")

    print("\n" + "=" * 60)
    print("✅ ALL DFD PARSER TESTS PASSED")
    print("=" * 60)
