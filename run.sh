#!/bin/bash
# Mercuds IDS - Quick Launcher
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "🛡️  Starting Mercuds IDS..."
echo ""

# Default interface (change if needed)
IFACE="${1:-en0}"

sudo "$DIR/venv/bin/python" "$DIR/network_monitor/interactive.py" -i "$IFACE"
