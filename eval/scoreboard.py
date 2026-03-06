"""Generate scoreboard from the latest results."""

import json
import sys
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
ATTACKS_DIR = Path(__file__).resolve().parent.parent / "attacks"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def main():
    # Find latest result
    results_files = sorted(RESULTS_DIR.glob("run_*.json"))
    if not results_files:
        print("No results found. Run eval/run_attacks.py first.")
        sys.exit(1)

    latest = json.loads(results_files[-1].read_text())

    # Load attacks for metadata
    attacks = []
    for f in sorted(ATTACKS_DIR.glob("*.json")):
        if f.name == "schema.json":
            continue
        try:
            attacks.append(json.loads(f.read_text()))
        except Exception:
            pass

    # Count patched vs unpatched
    patched = [a for a in attacks if "patched" in a]
    unpatched = [a for a in attacks if "patched" not in a and a["expected_action"] == "block"]

    print(f"\n{BOLD}AgentGuard Red Team Scoreboard{RESET}")
    print(f"{'=' * 60}")
    print(f"  Total attacks:    {len(attacks)}")
    print(f"  Patched:          {len(patched)}")
    print(f"  Unpatched:        {len(unpatched)}")

    s1 = latest.get("stage1", {})
    s2 = latest.get("stage2", {})

    if s1:
        correct = sum(1 for r in s1.values() if r.get("correct"))
        print(f"  Stage 1 accuracy: {correct}/{len(s1)} ({correct/len(s1)*100:.1f}%)")
    if s2:
        correct = sum(1 for r in s2.values() if r.get("correct"))
        print(f"  Stage 2 accuracy: {correct}/{len(s2)} ({correct/len(s2)*100:.1f}%)")

    bypasses = latest.get("bypasses", [])
    if bypasses:
        print(f"\n  {RED}Active Bypasses:{RESET}")
        for b in bypasses:
            print(f"    {b['id']}: {b['name']}")
    else:
        print(f"\n  {GREEN}No active bypasses!{RESET}")

    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
