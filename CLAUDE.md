# AgentGuard Red Team

Adversarial testing repo for AgentGuard defense pipeline.

## Architecture

```
attacks/    — Attack scenarios (expected_action: "block")
benign/     — Safe scenarios for false positive testing (expected_action: "pass")
eval/       — Test runner and scoreboard
results/    — JSON results from each run
scheduler/  — Automated cycle (Claude Code headless + cron)
```

## E2E Pipeline

```
Attack payload → AgentGuard Proxy (Stage 1: 11 rules) → Gate API / Trust Layer (Stage 2: Detect → Route → Judge) → BLOCKED or PASSED
```

- Stage 1: localhost:10180 (AgentGuard proxy)
- Stage 2: https://api.dev.tynapse.com/v1/guard/evaluate (Trust Layer Gate API)
- Detect: Qwen3-0.6B × 7 LoRA rank 128 (vLLM :8002)
- Judge: Qwen3-14B LoRA (vLLM :8001)

## Eval Scripts

- `eval/run_attacks.py` — Stage 1/2 개별 테스트 (attack/benign JSON 형식)
- `eval/run_e2e_eval.py` — 논문용 E2E eval (test_cases_v5.json 70건, AgentGuard 프록시 경유)
- `eval/scoreboard.py` — 결과 요약
- `eval/validate.py` — JSON 스키마 검증

## JSON Schema

All attack/benign files follow `attacks/schema.json`. Key fields:
- `expected_action`: `"block"` (attacks) or `"pass"` (benign)
- `target`: `"stage1"`, `"stage2"`, or `"both"`
- `category`: See README for full list

## Related Repos

- `contail/AgentGuard` — Stage 1 defense rules (Go)
- `contail/trust-agent-guard-model` — Stage 2 ML models (Qwen3 LoRA adapters)
- `Tynapse/tynapse-trust-layer` — Gate API serving infrastructure

## Conventions

- Attack IDs: `author_NNN` (e.g., `bot_021`)
- Benign IDs: `benign_NNN`
- Auto-generated files use author `"redteam-bot"`
- Defense PRs on other repos must have `needs-review` label
