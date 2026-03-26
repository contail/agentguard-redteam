"""Run E2E evaluation through AgentGuard proxy for paper results.

Sends test cases from trust-agent-guard-model test_cases_v5.json (70 cases)
through the full AgentGuard pipeline:
  Stage 1 (rule engine) → Stage 2 (detect-route-judge via trust-layer)

Usage:
    python eval/run_e2e_eval.py
    python eval/run_e2e_eval.py --test-file ~/trust-agent-guard-model/prompts/test_cases_v3.json
    python eval/run_e2e_eval.py --proxy-url http://localhost:10180
    python eval/run_e2e_eval.py --output results/e2e_v5_rank128.json
"""

import argparse
import json
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"
DEFAULT_TEST_FILE = Path.home() / "trust-agent-guard-model" / "prompts" / "test_cases_v5.json"
DEFAULT_PROXY = "http://localhost:10180"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def load_test_cases(path):
    data = json.loads(path.read_text())
    if isinstance(data, list):
        return data
    return data.get("test_cases", data.get("cases", []))


def send_through_proxy(proxy_url, query, context=""):
    """Send a query through AgentGuard proxy and check if blocked."""
    body = json.dumps({"query": query, "context": context})
    curl_cmd = [
        "curl", "-s", "-w", "\n%{http_code}",
        "-X", "POST", f"{proxy_url}/api/query",
        "-H", "Content-Type: application/json",
        "-d", body,
    ]
    try:
        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=30)
        lines = result.stdout.strip().rsplit("\n", 1)
        response_body = lines[0] if len(lines) > 1 else ""
        status_code = int(lines[-1]) if lines else 0
        blocked = status_code == 403
        return {
            "blocked": blocked,
            "status_code": status_code,
            "response": response_body[:200],
        }
    except subprocess.TimeoutExpired:
        return {"blocked": False, "status_code": 0, "response": "timeout"}
    except Exception as e:
        return {"blocked": False, "status_code": -1, "response": str(e)}


def run_eval(test_cases, proxy_url):
    results = []
    by_category = defaultdict(lambda: {"total": 0, "correct": 0, "cases": []})

    print(f"\n{BOLD}E2E Evaluation: {len(test_cases)} cases via {proxy_url}{RESET}")
    print(f"{'='*70}\n")

    for tc in test_cases:
        tc_id = tc["id"]
        category = tc["category"]
        context = tc.get("context", "")
        expected = tc["expected_verdict"]  # PASS or BLOCK
        expect_blocked = expected == "BLOCK"

        # Config cases use "config" field instead of "query"
        if "query" in tc:
            query = tc["query"]
        elif "config" in tc:
            query = json.dumps(tc["config"], ensure_ascii=False)[:500]
        else:
            print(f"  {YELLOW}[SKIP]{RESET} {tc_id}: no query or config field")
            continue

        start = time.time()
        resp = send_through_proxy(proxy_url, query, context)
        latency_ms = round((time.time() - start) * 1000)

        actual_blocked = resp["blocked"]
        correct = actual_blocked == expect_blocked

        result = {
            "id": tc_id,
            "category": category,
            "query": query[:100],
            "expected": expected,
            "actual": "BLOCK" if actual_blocked else "PASS",
            "correct": correct,
            "status_code": resp["status_code"],
            "latency_ms": latency_ms,
            "response": resp["response"][:100],
        }
        results.append(result)

        by_category[category]["total"] += 1
        if correct:
            by_category[category]["correct"] += 1
        by_category[category]["cases"].append(result)

        icon = f"{GREEN}OK{RESET}" if correct else f"{RED}FAIL{RESET}"
        actual_str = "BLOCK" if actual_blocked else "PASS"
        print(f"  [{icon}] {tc_id:25s} {category:25s} expected={expected:5s} actual={actual_str:5s} {latency_ms:5d}ms")

        time.sleep(0.5)

    return results, dict(by_category)


def print_summary(results, by_category):
    total = len(results)
    correct = sum(1 for r in results if r["correct"])
    accuracy = correct / total * 100 if total else 0

    # FP/FN analysis
    false_positives = [r for r in results if r["expected"] == "PASS" and r["actual"] == "BLOCK"]
    false_negatives = [r for r in results if r["expected"] == "BLOCK" and r["actual"] == "PASS"]

    benign_total = sum(1 for r in results if r["expected"] == "PASS")
    attack_total = sum(1 for r in results if r["expected"] == "BLOCK")
    fpr = len(false_positives) / benign_total * 100 if benign_total else 0
    fnr = len(false_negatives) / attack_total * 100 if attack_total else 0

    latencies = [r["latency_ms"] for r in results]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    print(f"\n{'='*70}")
    print(f"{BOLD}Summary{RESET}")
    print(f"{'='*70}")
    print(f"  Total: {correct}/{total} ({accuracy:.1f}%)")
    print(f"  FP: {len(false_positives)}/{benign_total} ({fpr:.1f}%)")
    print(f"  FN: {len(false_negatives)}/{attack_total} ({fnr:.1f}%)")
    print(f"  Avg latency: {avg_latency:.0f}ms")

    print(f"\n{BOLD}Per-category:{RESET}")
    for cat in sorted(by_category.keys()):
        d = by_category[cat]
        acc = d["correct"] / d["total"] * 100 if d["total"] else 0
        print(f"  {cat:30s} {d['correct']}/{d['total']} ({acc:.1f}%)")

    if false_positives:
        print(f"\n{BOLD}False positives:{RESET}")
        for r in false_positives:
            print(f"  {RED}{r['id']}{RESET}: {r['query'][:60]}")

    if false_negatives:
        print(f"\n{BOLD}False negatives:{RESET}")
        for r in false_negatives:
            print(f"  {RED}{r['id']}{RESET}: {r['query'][:60]}")

    return {
        "accuracy": round(accuracy, 1),
        "total": total,
        "correct": correct,
        "fp": len(false_positives),
        "fn": len(false_negatives),
        "fpr": round(fpr, 1),
        "fnr": round(fnr, 1),
        "avg_latency_ms": round(avg_latency),
        "per_category": {
            cat: {"correct": d["correct"], "total": d["total"],
                  "accuracy": round(d["correct"] / d["total"] * 100, 1) if d["total"] else 0}
            for cat, d in by_category.items()
        },
    }


def main():
    parser = argparse.ArgumentParser(description="E2E eval through AgentGuard proxy")
    parser.add_argument("--test-file", type=Path, default=DEFAULT_TEST_FILE,
                        help=f"Test cases JSON (default: {DEFAULT_TEST_FILE})")
    parser.add_argument("--proxy-url", default=DEFAULT_PROXY,
                        help=f"AgentGuard proxy URL (default: {DEFAULT_PROXY})")
    parser.add_argument("--output", type=Path, default=None,
                        help="Output JSON file (default: results/e2e_<timestamp>.json)")
    args = parser.parse_args()

    if not args.test_file.exists():
        print(f"{RED}Test file not found: {args.test_file}{RESET}")
        sys.exit(1)

    test_cases = load_test_cases(args.test_file)
    print(f"Loaded {len(test_cases)} test cases from {args.test_file.name}")

    # Verify proxy is up
    try:
        check = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             f"{args.proxy_url}/health"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        print(f"{RED}AgentGuard proxy not reachable at {args.proxy_url}{RESET}")
        sys.exit(1)

    results, by_category = run_eval(test_cases, args.proxy_url)
    summary = print_summary(results, by_category)

    # Save results
    RESULTS_DIR.mkdir(exist_ok=True)
    output_path = args.output or RESULTS_DIR / f"e2e_{int(time.time())}.json"
    output_data = {
        "timestamp": int(time.time()),
        "test_file": str(args.test_file),
        "proxy_url": args.proxy_url,
        "summary": summary,
        "results": results,
    }
    output_path.write_text(json.dumps(output_data, indent=2, ensure_ascii=False))
    print(f"\nResults saved: {output_path}")


if __name__ == "__main__":
    main()
