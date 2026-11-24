# Coldline
# File: .devcontainer/Dockerfile
# Component: Codespaces setup
# Purpose: The pinned Python dev image, minus the yarn apt source whose signing key no
#          longer verifies; the docker-in-docker Feature's apt-get update fails on it otherwise.
# Interacts With: .devcontainer/devcontainer.json
# Sprint/Task: Sprint 1 — Project 1
# Concepts: Reproducible setup
FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm@sha256:7876580dc67fd460fd962f004cbeb480027e9bbc0657096f1087db11f9eaff39
RUN rm -f /etc/apt/sources.list.d/yarn.list
