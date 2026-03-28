#!/usr/bin/env bash
# NetProbe — Linux/macOS setup & launch script
set -e

VENV=".venv"
SCRIPT="netprobe.py"

echo ""
echo " ╔══════════════════════════════════════╗"
echo " ║  NetProbe — Network Troubleshooter   ║"
echo " ╚══════════════════════════════════════╝"
echo ""

# ── Python check ─────────────────────────────────────────────────────────────
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null && python --version 2>&1 | grep -q "3\."; then
    PYTHON=python
else
    echo "[ERROR] Python 3 not found."
    echo "        Ubuntu/Debian : sudo apt install python3 python3-venv python3-pip"
    echo "        RHEL/CentOS   : sudo yum install python3"
    echo "        macOS (brew)  : brew install python"
    exit 1
fi

PY_VER=$($PYTHON --version 2>&1)
echo " [OK] $PY_VER detected."

# ── traceroute check (Linux only) ─────────────────────────────────────────────
if [[ "$(uname -s)" == "Linux" ]] && ! command -v traceroute &>/dev/null; then
    echo " [!]  traceroute not found — install with:"
    echo "      sudo apt install traceroute   (Debian/Ubuntu)"
    echo "      sudo yum install traceroute   (RHEL/CentOS)"
    echo "      (Traceroute feature will show an error until installed)"
    echo ""
fi

# ── venv ──────────────────────────────────────────────────────────────────────
if [ ! -d "$VENV" ]; then
    echo " [..] Creating virtual environment..."
    $PYTHON -m venv "$VENV"
    echo " [OK] Virtual environment created."
else
    echo " [OK] Virtual environment exists."
fi

# ── activate ──────────────────────────────────────────────────────────────────
# shellcheck disable=SC1090
source "$VENV/bin/activate"

# ── pip upgrade ───────────────────────────────────────────────────────────────
echo " [..] Upgrading pip..."
pip install --upgrade pip -q

# ── install deps ──────────────────────────────────────────────────────────────
echo " [..] Installing dependencies..."
pip install -r requirements.txt -q
echo " [OK] Dependencies installed."

# ── launch ────────────────────────────────────────────────────────────────────
echo " [OK] Launching NetProbe..."
echo ""
python "$SCRIPT"
