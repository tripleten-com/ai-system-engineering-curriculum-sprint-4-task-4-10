#!/usr/bin/env sh
# Coldline
# File: infra/scripts/preflight.sh
# Component: POSIX preflight wrapper
# Purpose: Run environment checks from a POSIX shell.
# Interacts With: infra/scripts/preflight.py
# Sprint/Task: Sprint 1 — Project 1
# Concepts: Early failure reporting
# Tools: POSIX shell, Python 3.12

set -eu

# macOS and many Linux distributions publish only python3, never a bare python.
python_command="$(command -v python3 || command -v python || true)"
if [ -z "$python_command" ]; then
    echo "preflight failed: Python 3.12 is required, but neither python3 nor python is on PATH" >&2
    exit 1
fi

export PATH="$PWD/.tools/bin:$PATH"
"$python_command" infra/scripts/preflight.py
