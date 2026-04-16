#!/bin/bash
# MacVM MCP installer
set -e

echo "[*] MacVM MCP installer"

# 1. Check Python
if ! command -v python3 >/dev/null; then
    echo "Python 3.10+ required"; exit 1
fi

# 2. Create venv
VENV="${VENV:-$HOME/.macvm-mcp/venv}"
mkdir -p "$(dirname "$VENV")"
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e .

# 3. Generate config from prompts
echo
echo "Configure macOS target:"
read -p "  macOS host IP: " IP
read -p "  SSH username [analyst]: " USER_; USER_=${USER_:-analyst}
read -p "  SSH key path [~/.ssh/id_ed25519]: " KEY; KEY=${KEY:-~/.ssh/id_ed25519}

cat > config.json <<EOF
{
  "ssh": {
    "host": "$IP",
    "port": 22,
    "username": "$USER_",
    "password": null,
    "key_file": "$KEY",
    "timeout": 30
  },
  "remote_work_dir": "/tmp/macmcp",
  "local_work_dir": "$HOME/macvm-analysis"
}
EOF

# 4. Test connection
echo "[*] Testing SSH connection..."
ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -i "$KEY" "$USER_@$IP" "echo Connection successful" || {
    echo "[!] SSH connection failed. Check your config."
    exit 1
}

cat <<EOF

[*] Installation complete.

Add this to your MCP client config (~/.claude/.mcp.json):

{
  "mcpServers": {
    "macvm": {
      "command": "$VENV/bin/python",
      "args": ["$(pwd)/server.py"],
      "env": {
        "MACMCP_CONFIG": "$(pwd)/config.json"
      }
    }
  }
}
EOF
