# Coldline
# File: infra/scripts/bootstrap.ps1
# Component: Windows bootstrap wrapper
# Purpose: Run the shared Python bootstrap from PowerShell.
# Interacts With: infra/scripts/bootstrap.py
# Sprint/Task: Sprint 1 — Project 1
# Concepts: Cross-platform setup
# Tools: PowerShell, Python 3.12

$ErrorActionPreference = "Stop"
python infra/scripts/bootstrap.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$env:PATH = "$(Get-Location)\.tools\bin;$env:PATH"
uv sync --frozen
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
