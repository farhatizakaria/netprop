#!/usr/bin/env bash
# Quick launcher — skips setup, just activates venv and runs
VENV=".venv"

if [ ! -d "$VENV" ]; then
    echo "[!] Virtual environment not found. Run setup.sh first."
    exit 1
fi

source "$VENV/bin/activate"
python netprobe.py
