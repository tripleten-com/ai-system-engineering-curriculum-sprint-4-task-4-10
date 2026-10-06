"""Coldline.

===================

File:              infra/scripts/bootstrap.py
Component:         Developer tooling — Bootstrap
Purpose:           Install the pinned uv bootstrap binary after verifying its release hash.
Interacts With:    Local workstation, uv, and Docker Compose
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Reproducibility, preflight checks, bootstrap
Tools:             Python 3.12
"""

from __future__ import annotations

import hashlib
import http.client
import os
import platform
import shutil
import stat
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

UV_VERSION = "0.11.8"
DOWNLOAD_TIMEOUT_SECONDS = 30
DOWNLOAD_ATTEMPTS = 3
ARTIFACTS = {
    ("Darwin", "arm64"): (
        "uv-aarch64-apple-darwin.tar.gz",
        "c729adb365114e844dd7f9316313a7ed6443b89bb5681d409eebac78b0bd06c8",
    ),
    ("Darwin", "x86_64"): (
        "uv-x86_64-apple-darwin.tar.gz",
        "c59d73bf34b58bc8e33a11629f7a255c11789fd00f03cd3e68ab2d1603645de9",
    ),
    ("Windows", "AMD64"): (
        "uv-x86_64-pc-windows-msvc.zip",
        "c84629a56e0706b69a47ea35862208af827cb6fbfa1d0ca763c52c67594637e8",
    ),
    ("Linux", "x86_64"): (
        "uv-x86_64-unknown-linux-gnu.tar.gz",
        "56dd1b66701ecb62fe896abb919444e4b83c5e8645cca953e6ddd496ff8a0feb",
    ),
    ("Linux", "aarch64"): (
        "uv-aarch64-unknown-linux-gnu.tar.gz",
        "eee8dd658d20e5ac85fec9c2326b6cbc9d83a1eef09ef07433e58698ac849591",
    ),
}


def main() -> int:
    """Download, authenticate, and install uv and uvx inside this repository."""
    key = (platform.system(), platform.machine())
    if key not in ARTIFACTS:
        raise SystemExit(f"unsupported bootstrap platform: {key[0]} {key[1]}")
    artifact, expected_hash = ARTIFACTS[key]
    destination = Path(__file__).resolve().parents[2] / ".tools" / "bin"
    suffix = ".exe" if key[0] == "Windows" else ""
    installed = destination / f"uv{suffix}"
    if installed.exists() and _version(installed) == UV_VERSION:
        print(f"uv {UV_VERSION} already installed at {installed}")
        return 0

    url = f"https://github.com/astral-sh/uv/releases/download/{UV_VERSION}/{artifact}"
    with tempfile.TemporaryDirectory(prefix="coldline-uv-") as temporary:
        archive = Path(temporary) / artifact
        _download(url, archive)
        actual_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise SystemExit(
                f"uv archive hash mismatch: expected {expected_hash}, got {actual_hash}"
            )
        extracted = Path(temporary) / "extracted"
        extracted.mkdir()
        if artifact.endswith(".zip"):
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(extracted)
        else:
            with tarfile.open(archive, mode="r:gz") as bundle:
                bundle.extractall(extracted, filter="data")
        destination.mkdir(parents=True, exist_ok=True)
        for executable in (f"uv{suffix}", f"uvx{suffix}"):
            source = next(extracted.rglob(executable))
            target = destination / executable
            shutil.copy2(source, target)
            target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"installed uv {UV_VERSION} at {installed}")
    return 0


def _download(url: str, archive: Path) -> None:
    """Retry transient release-download failures without retaining partial bytes."""
    for attempt in range(DOWNLOAD_ATTEMPTS):
        try:
            with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
                with archive.open("wb") as output:
                    shutil.copyfileobj(response, output)
                    expected_length = response.info().get("Content-Length")
                    if expected_length is not None and output.tell() < int(expected_length):
                        raise ConnectionError(
                            f"incomplete uv archive: received {output.tell()} of "
                            f"{expected_length} bytes"
                        )
            return
        except (
            urllib.error.URLError,
            TimeoutError,
            ConnectionError,
            http.client.IncompleteRead,
        ) as error:
            archive.unlink(missing_ok=True)
            if isinstance(error, urllib.error.HTTPError):
                retryable = error.code == 429 or 500 <= error.code < 600
                error.close()
            else:
                reason = error.reason if isinstance(error, urllib.error.URLError) else error
                retryable = isinstance(
                    reason, (TimeoutError, ConnectionError, http.client.IncompleteRead)
                )
            if not retryable or attempt == DOWNLOAD_ATTEMPTS - 1:
                raise
            delay = 2**attempt
            print(
                f"uv download failed ({error}); retrying in {delay}s "
                f"(attempt {attempt + 2}/{DOWNLOAD_ATTEMPTS})",
                file=sys.stderr,
            )
            time.sleep(delay)


def _version(executable: Path) -> str:
    """Return the installed version without invoking a shell."""
    import subprocess

    result = subprocess.run(
        [os.fspath(executable), "--version"], check=True, capture_output=True, text=True
    )
    parts = result.stdout.split()
    if len(parts) >= 2 and parts[0] == "uv":
        return parts[1]
    return result.stdout.strip()


if __name__ == "__main__":
    sys.exit(main())
