#!/bin/bash
# AgentGuard RedTeam Cycle — runs via cron or LaunchAgent
# Usage: ./scheduler/run_cycle.sh
#
# Cron example (every 6 hours):
#   0 */6 * * * /Users/contail/agentguard-redteam/scheduler/run_cycle.sh >> /tmp/redteam-cycle.log 2>&1
#
# LaunchAgent: see scheduler/com.agentguard.redteam.plist

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
PROMPT_FILE="$SCRIPT_DIR/prompt.md"
LOG_FILE="/tmp/redteam-cycle-$(date +%Y%m%d-%H%M).log"

echo "=== RedTeam Cycle started at $(date) ===" | tee "$LOG_FILE"

# Check if claude CLI is available
if ! command -v claude &>/dev/null; then
  echo "ERROR: claude CLI not found in PATH" | tee -a "$LOG_FILE"
  exit 1
fi

# Run Claude Code headless with the prompt
claude -p "$(cat "$PROMPT_FILE")" \
  --dangerously-skip-permissions \
  -d "$REPO_DIR" \
  2>&1 | tee -a "$LOG_FILE"

echo "=== RedTeam Cycle finished at $(date) ===" | tee -a "$LOG_FILE"
