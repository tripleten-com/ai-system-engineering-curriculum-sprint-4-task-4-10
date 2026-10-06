# syntax=docker/dockerfile:1.8@sha256:e87caa74dcb7d46cd820352bfea12591f3dba3ddc4285e19c7dcd13359f7cefd
# Coldline
# File: infra/containers/api.Dockerfile
# Component: API container image
# Purpose: Build and run the API as an unprivileged user with a stamped build identity.
# Interacts With: Root Python project, api package, infra/release/manifest.yaml
# Sprint/Task: Sprint 3 — Project 3
# Concepts: Reproducible container builds, immutable releases
# Tools: Docker, uv, Python 3.12

FROM ghcr.io/astral-sh/uv:0.11.8@sha256:3b7b60a81d3c57ef471703e5c83fd4aaa33abcd403596fb22ab07db85ae91347 AS uv
FROM python:3.12-slim-bookworm@sha256:0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579 AS builder

COPY --from=uv /uv /uvx /bin/
WORKDIR /workspace
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY . .
RUN uv sync --frozen --no-default-groups --group api

FROM python:3.12-slim-bookworm@sha256:0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579 AS runtime
# The release identity is baked in at build time. Two images built from the same
# source with different arguments answer /version differently, which is what makes
# a rollout and a rollback observable from outside the container.
ARG COLDLINE_BUILD_VERSION=dev
ARG COLDLINE_READY_DELAY_SECONDS=0
RUN groupadd --gid 10001 coldline && useradd --uid 10001 --gid coldline --create-home coldline
WORKDIR /workspace
COPY --from=builder /workspace /workspace
ENV PATH="/workspace/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
ENV COLDLINE_BUILD_VERSION=${COLDLINE_BUILD_VERSION} COLDLINE_READY_DELAY_SECONDS=${COLDLINE_READY_DELAY_SECONDS}
USER coldline
EXPOSE 8000
CMD ["uvicorn", "api.bootstrap:app", "--host", "0.0.0.0", "--port", "8000"]
