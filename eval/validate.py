"""Validate attack JSON files against the schema."""

import json
import sys
from pathlib import Path

ATTACKS_DIR = Path(__file__).resolve().parent.parent / "attacks"
REQUIRED_FIELDS = ["id", "name", "author", "date", "category", "target", "attack", "why_dangerous", "expected_action"]
VALID_CATEGORIES = [
    "path_traversal", "ssrf", "command_injection", "header_injection",
    "payload_regex", "encoding_bypass", "prompt_injection",
    "credential_theft", "data_exfiltration", "supply_chain",
    "privilege_escalation", "social_engineering",
]
VALID_TARGETS = ["stage1", "stage2", "both"]
VALID_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
VALID_ACTIONS = ["block", "pass"]


def validate_attack(filepath: Path) -> list[str]:
    errors = []
    try:
        data = json.loads(filepath.read_text())
    except json.JSONDecodeError as e:
        return [f"Invalid JSON: {e}"]

    for field in REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    if "category" in data and data["category"] not in VALID_CATEGORIES:
        errors.append(f"Invalid category: {data['category']}")

    if "target" in data and data["target"] not in VALID_TARGETS:
        errors.append(f"Invalid target: {data['target']}")

    if "expected_action" in data and data["expected_action"] not in VALID_ACTIONS:
        errors.append(f"Invalid expected_action: {data['expected_action']}")

    if "attack" in data:
        attack = data["attack"]
        if "method" not in attack:
            errors.append("attack.method is required")
        elif attack["method"] not in VALID_METHODS:
            errors.append(f"Invalid method: {attack['method']}")
        if "path" not in attack:
            errors.append("attack.path is required")
        if "body" not in attack:
            errors.append("attack.body is required")

    return errors


def main():
    files = sorted(ATTACKS_DIR.glob("*.json"))
    files = [f for f in files if f.name != "schema.json"]

    if not files:
        print("No attack files found.")
        sys.exit(0)

    total_errors = 0
    ids_seen = set()

    for f in files:
        errors = validate_attack(f)

        # Check duplicate IDs
        try:
            data = json.loads(f.read_text())
            aid = data.get("id", "")
            if aid in ids_seen:
                errors.append(f"Duplicate ID: {aid}")
            ids_seen.add(aid)
        except Exception:
            pass

        if errors:
            total_errors += len(errors)
            print(f"\033[91mFAIL\033[0m {f.name}")
            for e in errors:
                print(f"  - {e}")
        else:
            print(f"\033[92mOK\033[0m   {f.name}")

    print(f"\n{len(files)} files checked, {total_errors} errors")
    sys.exit(1 if total_errors > 0 else 0)


if __name__ == "__main__":
    main()
