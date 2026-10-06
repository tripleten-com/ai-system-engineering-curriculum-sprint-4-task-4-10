#!/usr/bin/env sh
# Coldline
# File: .devcontainer/post-create.sh
# Component: Codespaces setup
# Purpose: Install pinned local tools after the workspace is created.
# Interacts With: infra/scripts/bootstrap.sh
# Sprint/Task: Sprint 1 — Project 1
# Concepts: Reproducible setup
# Tools: POSIX shell, uv

set -eu
bash infra/scripts/bootstrap.sh
