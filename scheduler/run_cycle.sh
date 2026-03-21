#!/bin/bash
# AgentGuard RedTeam Cycle — runs via cron or LaunchAgent
# Usage: ./scheduler/run_cycle.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
PROMPT_FILE="$SCRIPT_DIR/prompt.md"
LOG_FILE="/tmp/redteam-cycle-$(date +%Y%m%d-%H%M).log"
AGENTGUARD_BIN="$HOME/AgentGuard/dist/agentguard-darwin-amd64"
PROXY_PID=""

echo "=== RedTeam Cycle started at $(date) ===" | tee "$LOG_FILE"

# Check if claude CLI is available
if ! command -v claude &>/dev/null; then
  echo "ERROR: claude CLI not found in PATH" | tee -a "$LOG_FILE"
  exit 1
fi

# Pull latest AgentGuard and rebuild
AGENTGUARD_REPO="$HOME/AgentGuard"
if [ -d "$AGENTGUARD_REPO" ]; then
  echo "Updating AgentGuard to latest main..." | tee -a "$LOG_FILE"
  cd "$AGENTGUARD_REPO"
  git pull origin main --ff-only 2>&1 | tee -a "$LOG_FILE" || true
  if command -v go &>/dev/null; then
    go build -o dist/agentguard-darwin-amd64 . 2>&1 | tee -a "$LOG_FILE" && \
      echo "Rebuilt binary OK" | tee -a "$LOG_FILE" || \
      echo "WARNING: Build failed, using existing binary" | tee -a "$LOG_FILE"
  fi
  cd "$REPO_DIR"
fi

# Start AgentGuard proxy if not running
if ! curl -s http://localhost:10180/health &>/dev/null; then
  if [ -f "$AGENTGUARD_BIN" ]; then
    echo "Starting AgentGuard proxy..." | tee -a "$LOG_FILE"
    AGENTGUARD_GATE_ENABLED=true "$AGENTGUARD_BIN" proxy --port 10180 &
    PROXY_PID=$!
    sleep 2
    if curl -s http://localhost:10180/health &>/dev/null; then
      echo "Proxy started (PID $PROXY_PID)" | tee -a "$LOG_FILE"
    else
      echo "WARNING: Proxy failed to start, continuing with Stage 2 only" | tee -a "$LOG_FILE"
      PROXY_PID=""
    fi
  else
    echo "WARNING: AgentGuard binary not found at $AGENTGUARD_BIN, skipping Stage 1" | tee -a "$LOG_FILE"
  fi
else
  echo "AgentGuard proxy already running" | tee -a "$LOG_FILE"
fi

# Run Claude Code headless with the prompt
claude -p "$(cat "$PROMPT_FILE")" \
  --dangerously-skip-permissions \
  -d "$REPO_DIR" \
  2>&1 | tee -a "$LOG_FILE"

# Stop proxy if we started it
if [ -n "$PROXY_PID" ]; then
  echo "Stopping proxy (PID $PROXY_PID)..." | tee -a "$LOG_FILE"
  kill "$PROXY_PID" 2>/dev/null || true
  wait "$PROXY_PID" 2>/dev/null || true
fi

echo "=== RedTeam Cycle finished at $(date) ===" | tee -a "$LOG_FILE"
