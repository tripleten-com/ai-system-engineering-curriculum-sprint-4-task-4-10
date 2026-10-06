#!/usr/bin/env sh
# Coldline
# File: .devcontainer/start-stack.sh
# Component: Codespaces startup
# Purpose: Start the same Compose stack used on a local workstation.
# Interacts With: pyproject.toml, compose.yaml
# Sprint/Task: Sprint 1 — Project 1
# Concepts: Local and Codespaces parity
# Tools: POSIX shell, Poe, Docker Compose

set -eu
uv run --frozen poe start
