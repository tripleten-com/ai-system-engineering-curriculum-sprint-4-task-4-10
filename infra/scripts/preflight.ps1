# Coldline
# File: infra/scripts/preflight.ps1
# Component: Windows preflight wrapper
# Purpose: Run environment checks from PowerShell.
# Interacts With: infra/scripts/preflight.py
# Sprint/Task: Sprint 1 — Project 1
# Concepts: Early failure reporting
# Tools: PowerShell, Python 3.12

$ErrorActionPreference = "Stop"
$env:PATH = "$(Get-Location)\.tools\bin;$env:PATH"
python infra/scripts/preflight.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
