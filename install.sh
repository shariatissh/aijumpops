#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$REPO_DIR/jmsctl" "$REPO_DIR/jmsctl.py" "$REPO_DIR/aijumpops_mcp.py"

echo "[1/3] Installing AiJumpOps Python CLI & MCP entrypoints..."
pip install -q -e "$REPO_DIR" || true

echo "[2/3] Installing AiJumpOps Skill for OpenCode & Claude Code..."
mkdir -p "$HOME/.config/opencode/skills/aijumpops" "$HOME/.claude/skills/aijumpops"
cp "$REPO_DIR/skills/aijumpops/SKILL.md" "$HOME/.config/opencode/skills/aijumpops/SKILL.md"
cp "$REPO_DIR/skills/aijumpops/SKILL.md" "$HOME/.claude/skills/aijumpops/SKILL.md"

echo "[3/3] Creating .env from .env.example if not present..."
if [ ! -f "$REPO_DIR/.env" ]; then
    cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
    chmod 600 "$REPO_DIR/.env"
    echo "Created $REPO_DIR/.env (mode 0600). Run './jmsctl init' to configure your JumpServer credentials."
fi

echo "✅ AiJumpOps installed successfully!"
echo "   - CLI: $REPO_DIR/jmsctl"
echo "   - MCP Server: python3 $REPO_DIR/aijumpops_mcp.py"
