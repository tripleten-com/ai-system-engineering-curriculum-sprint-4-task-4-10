#!/usr/bin/env sh
# Coldline
# File: infra/scripts/bootstrap.sh
# Component: POSIX bootstrap wrapper
# Purpose: Run the shared Python bootstrap from a POSIX shell.
# Interacts With: infra/scripts/bootstrap.py
# Sprint/Task: Sprint 1 — Project 1
# Concepts: Cross-platform setup
# Tools: POSIX shell, Python 3.12

set -eu

# macOS and many Linux distributions publish only python3, never a bare python.
python_command="$(command -v python3 || command -v python || true)"
if [ -z "$python_command" ]; then
    echo "bootstrap failed: Python 3.12 is required, but neither python3 nor python is on PATH" >&2
    exit 1
fi

"$python_command" infra/scripts/bootstrap.py
export PATH="$PWD/.tools/bin:$PATH"
uv sync --frozen
