"""
Evaluation Harness for SecureByDesign
Runs test DFDs through the AI pipeline and computes Precision/Recall/F1.

Usage (from SecureByDesign/ directory):
    python -m evaluation.evaluate

Or on Kaggle:
    %run /kaggle/working/SecureByDesign/evaluation/evaluate.py
"""

import json
import os
import sys
import time
import traceback
from datetime import datetime

# Ensure project root is on sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ── Paths ─────────────────────────────────────────────────────────────────────
TEST_DFDS_DIR = os.path.join(SCRIPT_DIR, "test_dfds")
GROUND_TRUTH_PATH = os.path.join(SCRIPT_DIR, "ground_truth.json")
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")

STRIDE_CATEGORIES = [
    "Spoofing", "Tampering", "Repudiation",
    "Information Disclosure", "Denial of Service", "Elevation of Privilege"
]

# Rate limit delay between API calls (seconds)
RATE_LIMIT_DELAY = 2


# ── Metric Computation ───────────────────────────────────────────────────────

def compute_binary_metrics(expected_cats, predicted_cats):
    """Compute Precision, Recall, F1 from two lists of STRIDE categories."""
    expected_vec = [1 if cat in expected_cats else 0 for cat in STRIDE_CATEGORIES]
    predicted_vec = [1 if cat in predicted_cats else 0 for cat in STRIDE_CATEGORIES]

    tp = sum(e == 1 and p == 1 for e, p in zip(expected_vec, predicted_vec))
    fp = sum(e == 0 and p == 1 for e, p in zip(expected_vec, predicted_vec))
    fn = sum(e == 1 and p == 0 for e, p in zip(expected_vec, predicted_vec))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return round(precision, 3), round(recall, 3), round(f1, 3)


# ── Load Test Cases ──────────────────────────────────────────────────────────

def load_test_cases():
    """Load test DFDs and ground truth."""
    with open(GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    test_cases = []
    for filename in sorted(os.listdir(TEST_DFDS_DIR)):
        if not filename.endswith(".json"):
            continue

        dfd_id = filename.replace(".json", "")
        if dfd_id not in ground_truth:
            print(f"  ⚠ No ground truth for {dfd_id} — skipping")
            continue

        filepath = os.path.join(TEST_DFDS_DIR, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            dfd_json = json.load(f)

        test_cases.append({
            "dfd_id": dfd_id,
            "dfd_json": dfd_json,
            "ground_truth": ground_truth[dfd_id],
        })

    print(f"✅ Loaded {len(test_cases)} test cases")
    return test_cases


# ── Single Evaluation ────────────────────────────────────────────────────────

def run_single_evaluation(test_case, analyze_fn):
    """Run one test case through the pipeline and compare to ground truth."""
    dfd_json = test_case["dfd_json"]
    gt = test_case["ground_truth"]
    dfd_id = test_case["dfd_id"]

    start = time.time()
    try:
        result = analyze_fn(dfd_json, "")
        duration = time.time() - start
        error = result.get("error", None)
    except Exception as e:
        traceback.print_exc()
        return {
            "dfd_id": dfd_id,
            "system_name": gt.get("system_name", ""),
            "error": str(e),
            "predicted_categories": [],
            "expected_categories": gt.get("expected_stride_categories", []),
            "precision": 0.0, "recall": 0.0, "f1": 0.0,
            "threats_predicted": 0,
            "duration_seconds": round(time.time() - start, 2),
        }

    # Extract predicted STRIDE categories (deduplicated)
    predicted_categories = list(set(
        t.get("stride_category") for t in result.get("threats", [])
        if t.get("stride_category") in STRIDE_CATEGORIES
    ))

    expected_categories = gt.get("expected_stride_categories", [])

    precision, recall, f1 = compute_binary_metrics(expected_categories, predicted_categories)

    # Confidence distribution
    conf_dist = {"High": 0, "Medium": 0, "Low": 0}
    for threat in result.get("threats", []):
        conf = threat.get("confidence", "Low")
        conf_dist[conf] = conf_dist.get(conf, 0) + 1

    return {
        "dfd_id": dfd_id,
        "system_name": gt.get("system_name", ""),
        "predicted_categories": predicted_categories,
        "expected_categories": expected_categories,
        "threats_predicted": len(result.get("threats", [])),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "overall_risk_level": result.get("overall_risk_level", "Unknown"),
        "completeness_score": result.get("completeness_score", 1.0),
        "confidence_high": conf_dist["High"],
        "confidence_medium": conf_dist["Medium"],
        "confidence_low": conf_dist["Low"],
        "duration_seconds": round(duration, 2),
        "error": error,
    }


# ── Full Evaluation ──────────────────────────────────────────────────────────

def run_full_evaluation(analyze_fn=None):
    """Run complete evaluation across all test cases."""
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Import analyze_dfd if not provided
    if analyze_fn is None:
        from pipeline.inference import analyze_dfd
        analyze_fn = analyze_dfd

    test_cases = load_test_cases()

    print(f"\n{'='*60}")
    print(f"SECUREBYDESIGN EVALUATION RUN")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Test Cases: {len(test_cases)}")
    print(f"{'-'*60}\n")

    results = []
    for i, test_case in enumerate(test_cases):
        print(f"[{i+1}/{len(test_cases)}] Evaluating {test_case['dfd_id']}...")
        result = run_single_evaluation(test_case, analyze_fn)
        results.append(result)

        status = "✅" if not result.get("error") else "⚠"
        print(f"  {status} P={result['precision']:.3f} | R={result['recall']:.3f} | "
              f"F1={result['f1']:.3f} | threats={result['threats_predicted']} | "
              f"{result['duration_seconds']}s")

        # Rate limit between API calls
        if i < len(test_cases) - 1:
            time.sleep(RATE_LIMIT_DELAY)

    # ── Aggregate Results ─────────────────────────────────────────────────
    valid = [r for r in results if r.get("error") is None]
    errors = [r for r in results if r.get("error") is not None]

    if valid:
        avg_precision = sum(r["precision"] for r in valid) / len(valid)
        avg_recall    = sum(r["recall"] for r in valid) / len(valid)
        avg_f1        = sum(r["f1"] for r in valid) / len(valid)
        avg_threats   = sum(r["threats_predicted"] for r in valid) / len(valid)
        avg_duration  = sum(r["duration_seconds"] for r in valid) / len(valid)
    else:
        avg_precision = avg_recall = avg_f1 = avg_threats = avg_duration = 0.0

    print(f"\n{'='*60}")
    print("AGGREGATE RESULTS")
    print(f"{'-'*60}")
    print(f"  Total test cases    : {len(results)}")
    print(f"  Successful          : {len(valid)}")
    print(f"  Errors              : {len(errors)}")
    print(f"{'-'*60}")
    print(f"  Macro Precision     : {avg_precision:.3f}")
    print(f"  Macro Recall        : {avg_recall:.3f}")
    print(f"  Macro F1-Score      : {avg_f1:.3f}")
    print(f"{'-'*60}")
    print(f"  Avg Threats/DFD     : {avg_threats:.1f}")
    print(f"  Avg Duration        : {avg_duration:.1f}s")
    print(f"{'='*60}")

    # Save results JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_path = os.path.join(RESULTS_DIR, f"evaluation_results_{timestamp}.json")

    save_data = {
        "timestamp": datetime.now().isoformat(),
        "num_test_cases": len(results),
        "num_successful": len(valid),
        "num_errors": len(errors),
        "aggregate": {
            "precision": round(avg_precision, 3),
            "recall": round(avg_recall, 3),
            "f1": round(avg_f1, 3),
            "avg_threats_per_dfd": round(avg_threats, 1),
            "avg_duration_seconds": round(avg_duration, 1),
        },
        "per_dfd_results": results,
    }

    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(save_data, f, indent=2, default=str)

    print(f"\n✅ Results saved: {results_path}")

    return save_data


if __name__ == "__main__":
    run_full_evaluation()
