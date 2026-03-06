"""Run attack payloads against AgentGuard and/or the AI Judge model.

Usage:
    # Stage 1 only (requires AgentGuard running or uses Go test server)
    python eval/run_attacks.py --target stage1

    # Stage 2 only (requires mlx-lm + model adapters)
    python eval/run_attacks.py --target stage2

    # Both stages
    python eval/run_attacks.py --target all

    # Against a specific AgentGuard instance
    python eval/run_attacks.py --target stage1 --proxy-url http://localhost:10180
"""

import argparse
import json
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTACKS_DIR = REPO_ROOT / "attacks"
RESULTS_DIR = REPO_ROOT / "results"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def load_attacks():
    files = sorted(ATTACKS_DIR.glob("*.json"))
    attacks = []
    for f in files:
        if f.name == "schema.json":
            continue
        try:
            data = json.loads(f.read_text())
            data["_file"] = f.name
            attacks.append(data)
        except Exception as e:
            print(f"{RED}Error loading {f.name}: {e}{RESET}")
    return attacks


def test_stage1_via_go(attacks):
    """Generate a Go test file and run it against the real AgentGuard middleware."""
    agentguard_dir = Path.home() / "AgentGuard"
    if not agentguard_dir.exists():
        print(f"{RED}AgentGuard not found at {agentguard_dir}{RESET}")
        print("Set AGENTGUARD_DIR env var or clone the repo to ~/AgentGuard")
        return {}

    # Build test cases as JSON for the Go test to consume
    stage1_attacks = [a for a in attacks if a["target"] in ("stage1", "both")]
    if not stage1_attacks:
        print("No Stage 1 attacks to test.")
        return {}

    test_input = json.dumps(stage1_attacks, ensure_ascii=False)
    test_input_file = agentguard_dir / "redteam_input.json"
    test_input_file.write_text(test_input)

    # Run the existing red_team_test.go (it has its own scenarios)
    # For external attacks, we use curl against a running proxy
    print(f"\n{BOLD}Stage 1: Testing {len(stage1_attacks)} attacks via HTTP{RESET}\n")

    results = {}
    for atk in stage1_attacks:
        a = atk["attack"]
        method = a.get("method", "POST")
        path = a.get("path", "/api/query")
        body = a.get("body", "")
        headers = a.get("headers", {})

        # Build curl command
        curl_cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "-X", method, f"http://localhost:10180{path}"]
        for k, v in headers.items():
            curl_cmd.extend(["-H", f"{k}: {v}"])
        if body:
            curl_cmd.extend(["-d", body])

        try:
            result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=5)
            status_code = int(result.stdout.strip())
            blocked = status_code == 403
        except subprocess.TimeoutExpired:
            blocked = False
            status_code = 0
        except Exception:
            blocked = False
            status_code = -1

        expected_block = atk["expected_action"] == "block"
        correct = blocked == expected_block

        results[atk["id"]] = {
            "blocked": blocked,
            "status_code": status_code,
            "expected": atk["expected_action"],
            "correct": correct,
        }

        icon = f"{GREEN}OK{RESET}" if correct else f"{RED}FAIL{RESET}"
        action = "BLOCKED" if blocked else "PASSED"
        print(f"  [{icon}] {atk['id']}: {action} (HTTP {status_code}) — {atk['name']}")

    # Cleanup
    test_input_file.unlink(missing_ok=True)
    return results


def test_stage2_judge(attacks):
    """Test attacks against the AI Judge model via Ollama API."""
    stage2_attacks = [a for a in attacks if a["target"] in ("stage2", "both")]
    if not stage2_attacks:
        print("No Stage 2 attacks to test.")
        return {}

    try:
        import httpx
    except ImportError:
        print(f"{RED}httpx not installed. Run: pip install httpx{RESET}")
        return {}

    import os
    base_url = os.environ.get("JUDGE_BASE_URL", "http://localhost:11434/v1")
    model = os.environ.get("JUDGE_MODEL", "qwen3:8b")

    # Load system prompt
    prompt_file = Path.home() / "trust-agent-guard-model" / "prompts" / "system_prompt_v4.txt"
    if not prompt_file.exists():
        print(f"{RED}Judge system prompt not found: {prompt_file}{RESET}")
        return {}
    system_prompt = prompt_file.read_text()

    print(f"\n{BOLD}Stage 2: Testing {len(stage2_attacks)} attacks via Judge ({model}){RESET}\n")

    results = {}
    for atk in stage2_attacks:
        body = atk["attack"].get("body", "")
        # Extract query from JSON body
        try:
            parsed = json.loads(body)
            query = parsed.get("query", body)
        except Exception:
            query = body

        user_content = f"## Agent Action\n{query}"

        try:
            resp = httpx.post(
                f"{base_url}/chat/completions",
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_content + "\n\n/no_think"},
                    ],
                    "max_tokens": 1024,
                },
                timeout=30,
            )
            content = resp.json()["choices"][0]["message"]["content"]

            # Parse verdict
            import re
            content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL)
            match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", content, re.DOTALL)
            if match:
                json_str = match.group(1)
            else:
                start = content.find("{")
                if start != -1:
                    depth = 0
                    for i in range(start, len(content)):
                        if content[i] == "{":
                            depth += 1
                        elif content[i] == "}":
                            depth -= 1
                            if depth == 0:
                                json_str = content[start:i+1]
                                break
                    else:
                        json_str = "{}"
                else:
                    json_str = "{}"

            verdict = json.loads(json_str)
            threat = verdict.get("threat_confirmed", False)
            severity = verdict.get("severity", "NONE")
            blocked = threat and severity in ("CRITICAL", "HIGH")

        except Exception as e:
            print(f"  {YELLOW}[ERR]{RESET} {atk['id']}: {e}")
            blocked = False
            verdict = {}

        expected_block = atk["expected_action"] == "block"
        correct = blocked == expected_block

        results[atk["id"]] = {
            "blocked": blocked,
            "verdict": verdict,
            "expected": atk["expected_action"],
            "correct": correct,
        }

        icon = f"{GREEN}OK{RESET}" if correct else f"{RED}FAIL{RESET}"
        action = "BLOCKED" if blocked else "PASSED"
        threat_type = verdict.get("threat_type", "?")
        print(f"  [{icon}] {atk['id']}: {action} ({threat_type}/{severity}) — {atk['name']}")

    return results


def print_scoreboard(attacks, stage1_results, stage2_results):
    print(f"\n{'=' * 60}")
    print(f"{BOLD}AgentGuard Red Team Scoreboard{RESET}")
    print(f"{'=' * 60}\n")

    # Stage 1 stats
    if stage1_results:
        s1_correct = sum(1 for r in stage1_results.values() if r["correct"])
        s1_total = len(stage1_results)
        pct = s1_correct / s1_total * 100 if s1_total else 0
        print(f"  Stage 1 (Rules):  {s1_correct}/{s1_total} correct ({pct:.1f}%)")

    # Stage 2 stats
    if stage2_results:
        s2_correct = sum(1 for r in stage2_results.values() if r["correct"])
        s2_total = len(stage2_results)
        pct = s2_correct / s2_total * 100 if s2_total else 0
        print(f"  Stage 2 (Judge):  {s2_correct}/{s2_total} correct ({pct:.1f}%)")

    # Bypasses
    bypasses = []
    for atk in attacks:
        aid = atk["id"]
        s1 = stage1_results.get(aid, {})
        s2 = stage2_results.get(aid, {})
        if atk["expected_action"] == "block":
            s1_bypassed = s1 and not s1.get("blocked", True)
            s2_bypassed = s2 and not s2.get("blocked", True)
            if s1_bypassed or s2_bypassed:
                bypasses.append({
                    "id": aid,
                    "name": atk["name"],
                    "s1": "PASS" if s1_bypassed else ("BLOCK" if s1 else "-"),
                    "s2": "PASS" if s2_bypassed else ("BLOCK" if s2 else "-"),
                })

    if bypasses:
        print(f"\n  {RED}Bypasses:{RESET}")
        for b in bypasses:
            print(f"    {b['id']}: {b['name']}  S1={b['s1']} S2={b['s2']}")

    # Category breakdown
    cat_stats = defaultdict(lambda: {"total": 0, "s1_ok": 0, "s2_ok": 0})
    for atk in attacks:
        cat = atk["category"]
        cat_stats[cat]["total"] += 1
        if atk["id"] in stage1_results and stage1_results[atk["id"]]["correct"]:
            cat_stats[cat]["s1_ok"] += 1
        if atk["id"] in stage2_results and stage2_results[atk["id"]]["correct"]:
            cat_stats[cat]["s2_ok"] += 1

    print(f"\n  Category Breakdown:")
    for cat in sorted(cat_stats):
        s = cat_stats[cat]
        print(f"    {cat:25s}: {s['total']} attacks (S1: {s['s1_ok']}/{s['total']}, S2: {s['s2_ok']}/{s['total']})")

    # Contributors
    authors = defaultdict(int)
    for atk in attacks:
        authors[atk.get("author", "unknown")] += 1
    author_str = ", ".join(f"@{a} ({c})" for a, c in sorted(authors.items(), key=lambda x: -x[1]))
    print(f"\n  Contributors: {author_str}")
    print(f"{'=' * 60}")

    return bypasses


def main():
    parser = argparse.ArgumentParser(description="Run red team attacks against AgentGuard")
    parser.add_argument("--target", choices=["stage1", "stage2", "all"], default="all")
    parser.add_argument("--proxy-url", default="http://localhost:10180")
    args = parser.parse_args()

    attacks = load_attacks()
    if not attacks:
        print("No attack files found in attacks/")
        sys.exit(1)

    print(f"{BOLD}Loaded {len(attacks)} attack scenarios{RESET}")

    stage1_results = {}
    stage2_results = {}

    if args.target in ("stage1", "all"):
        stage1_results = test_stage1_via_go(attacks)

    if args.target in ("stage2", "all"):
        stage2_results = test_stage2_judge(attacks)

    bypasses = print_scoreboard(attacks, stage1_results, stage2_results)

    # Save results
    RESULTS_DIR.mkdir(exist_ok=True)
    results_file = RESULTS_DIR / f"run_{int(time.time())}.json"
    results_file.write_text(json.dumps({
        "timestamp": int(time.time()),
        "target": args.target,
        "total_attacks": len(attacks),
        "stage1": stage1_results,
        "stage2": stage2_results,
        "bypasses": bypasses,
    }, indent=2, ensure_ascii=False))
    print(f"\nResults saved: {results_file}")


if __name__ == "__main__":
    main()
