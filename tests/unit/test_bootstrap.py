"""Coldline.

===================

File:              tests/unit/test_bootstrap.py
Component:         Unit tests — Bootstrap
Purpose:           Keep the pinned uv bootstrap re-runnable without network access.
Interacts With:    infra/scripts/bootstrap.py
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Reproducibility, idempotency, version parsing
Tools:             Python 3.12, pytest
"""

import hashlib
import http.client
import http.server
import importlib.util
import io
import ssl
import subprocess
import threading
import time
import urllib.error
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

BOOTSTRAP_PATH = Path(__file__).resolve().parents[2] / "infra/scripts/bootstrap.py"
SPEC = importlib.util.spec_from_file_location("coldline_bootstrap", BOOTSTRAP_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("bootstrap module could not be loaded")
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class DownloadResponse(io.BytesIO):
    """Serve an archive through the URL response boundary without a network."""

    def info(self) -> dict[str, str]:
        """Support the previous urlretrieve path while reproducing its failures."""
        return {}


@pytest.fixture
def archive_download(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    """Exercise installation with a real zip archive in an isolated repository."""
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("uv.exe", b"verified uv binary")
        bundle.writestr("uvx.exe", b"verified uvx binary")
    payload = archive.getvalue()
    monkeypatch.setattr(bootstrap, "__file__", str(tmp_path / "infra/scripts/bootstrap.py"))
    monkeypatch.setattr(bootstrap.platform, "system", lambda: "Windows")
    monkeypatch.setattr(bootstrap.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(
        bootstrap,
        "ARTIFACTS",
        {("Windows", "AMD64"): ("uv-test.zip", hashlib.sha256(payload).hexdigest())},
    )
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    return SimpleNamespace(payload=payload, root=tmp_path, sleeps=sleeps)


@pytest.mark.parametrize("failure", [429, 500, 504, "timeout", "wrapped-timeout"])
def test_bootstrap_retries_transient_download_failures(
    monkeypatch: pytest.MonkeyPatch, archive_download: SimpleNamespace, failure: int | str
) -> None:
    """A temporary failure must still install both authenticated executables."""
    calls = []

    def open_url(url: str, *args: object, **kwargs: object) -> DownloadResponse:
        calls.append(kwargs)
        if len(calls) < 3:
            if isinstance(failure, int):
                raise urllib.error.HTTPError(url, failure, "temporary failure", {}, None)
            if failure == "wrapped-timeout":
                raise urllib.error.URLError(TimeoutError("connection timed out"))
            raise TimeoutError("connection timed out")
        return DownloadResponse(archive_download.payload)

    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", open_url)

    assert bootstrap.main() == 0
    assert len(calls) == 3
    assert all(0 < call["timeout"] <= 60 for call in calls)
    assert archive_download.sleeps == [1, 2]
    assert (archive_download.root / ".tools/bin/uv.exe").read_bytes() == b"verified uv binary"
    assert (archive_download.root / ".tools/bin/uvx.exe").read_bytes() == b"verified uvx binary"


@pytest.mark.parametrize("recover", [False, True])
@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError("read timed out"),
        ConnectionResetError("connection reset"),
        http.client.RemoteDisconnected("remote disconnected"),
        http.client.IncompleteRead(b"partial", 100),
    ],
    ids=["timeout", "connection-reset", "remote-disconnected", "incomplete-read"],
)
def test_bootstrap_discards_partial_archives_after_interrupted_reads(
    monkeypatch: pytest.MonkeyPatch,
    archive_download: SimpleNamespace,
    recover: bool,
    failure: Exception,
) -> None:
    """Partial bytes cannot survive into a retry or a terminal failure."""
    calls = []
    archives: list[Path] = []

    class InterruptedResponse(DownloadResponse):
        """Write a partial chunk before the network read fails."""

        def read(self, size: int = -1) -> bytes:
            """Fail once the first chunk has been consumed."""
            if self.tell():
                raise failure
            return super().read(3)

    real_temporary = bootstrap.tempfile.TemporaryDirectory

    def temporary_directory(**kwargs: object):
        temporary = real_temporary(**kwargs)
        archives.append(Path(temporary.name) / "uv-test.zip")
        return temporary

    def sleep(delay: float) -> None:
        assert not archives[-1].exists()
        archive_download.sleeps.append(delay)

    def open_url(*args: object, **kwargs: object) -> DownloadResponse:
        calls.append(kwargs)
        if recover and len(calls) == 2:
            return DownloadResponse(archive_download.payload)
        return InterruptedResponse(b"partial archive")

    monkeypatch.setattr(bootstrap.tempfile, "TemporaryDirectory", temporary_directory)
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", open_url)
    monkeypatch.setattr(time, "sleep", sleep)

    if recover:
        assert bootstrap.main() == 0
        assert len(calls) == 2
    else:
        with pytest.raises(type(failure)):
            bootstrap.main()
        assert len(calls) == 3
        assert archive_download.sleeps == [1, 2]
        assert not (archive_download.root / ".tools").exists()
    assert not archives[-1].exists()


@pytest.mark.parametrize(
    "reason",
    [
        ConnectionResetError("connection reset"),
        http.client.RemoteDisconnected("remote disconnected"),
        http.client.IncompleteRead(b"partial", 100),
    ],
    ids=["connection-reset", "remote-disconnected", "incomplete-read"],
)
def test_bootstrap_retries_wrapped_connection_failures(
    monkeypatch: pytest.MonkeyPatch, archive_download: SimpleNamespace, reason: Exception
) -> None:
    """urllib-wrapped transient network failures use the same bounded retry policy."""
    attempts = []

    def open_url(*args: object, **kwargs: object) -> DownloadResponse:
        attempts.append(kwargs)
        if len(attempts) < 3:
            raise urllib.error.URLError(reason)
        return DownloadResponse(archive_download.payload)

    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", open_url)

    assert bootstrap.main() == 0
    assert len(attempts) == 3
    assert archive_download.sleeps == [1, 2]
    assert (archive_download.root / ".tools/bin/uv.exe").read_bytes() == b"verified uv binary"


@pytest.mark.parametrize("recover", [False, True])
def test_bootstrap_retries_premature_http_eof(
    monkeypatch: pytest.MonkeyPatch, archive_download: SimpleNamespace, recover: bool
) -> None:
    """A real short HTTP body retries and cleans up even when sized reads return EOF."""
    requests = []
    archives: list[Path] = []

    class ShortBodyHandler(http.server.BaseHTTPRequestHandler):
        """Serve a complete Content-Length header but deliberately truncate the body."""

        def do_GET(self) -> None:
            """Recover only on the third request when the scenario permits it."""
            requests.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", str(len(archive_download.payload)))
            self.end_headers()
            payload = archive_download.payload
            self.wfile.write(payload if recover and len(requests) == 3 else payload[:5])
            self.close_connection = True

        def log_message(self, format: str, *args: object) -> None:
            """Keep expected request traffic out of the unit-test output."""

    real_open = bootstrap.urllib.request.urlopen
    real_temporary = bootstrap.tempfile.TemporaryDirectory

    def temporary_directory(**kwargs: object):
        temporary = real_temporary(**kwargs)
        archives.append(Path(temporary.name) / "uv-test.zip")
        return temporary

    def sleep(delay: float) -> None:
        assert not archives[-1].exists()
        archive_download.sleeps.append(delay)

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), ShortBodyHandler) as server:
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        worker.start()

        def open_url(url: str, *, timeout: float):
            return real_open(f"http://127.0.0.1:{server.server_port}/uv-test.zip", timeout=timeout)

        monkeypatch.setattr(bootstrap.urllib.request, "urlopen", open_url)
        monkeypatch.setattr(bootstrap.tempfile, "TemporaryDirectory", temporary_directory)
        monkeypatch.setattr(time, "sleep", sleep)
        try:
            if recover:
                assert bootstrap.main() == 0
                assert (archive_download.root / ".tools/bin/uv.exe").read_bytes() == (
                    b"verified uv binary"
                )
            else:
                with pytest.raises(ConnectionError, match="incomplete"):
                    bootstrap.main()
                assert not (archive_download.root / ".tools").exists()
        finally:
            server.shutdown()
            worker.join(timeout=5)
    assert len(requests) == 3
    assert archive_download.sleeps == [1, 2]
    assert not archives[-1].exists()


@pytest.mark.parametrize("failure", [403, 404, "checksum", "unsupported", "certificate"])
def test_bootstrap_does_not_retry_permanent_failures(
    monkeypatch: pytest.MonkeyPatch, archive_download: SimpleNamespace, failure: int | str
) -> None:
    """Permanent failures must never retry or install untrusted executables."""
    calls = []

    def open_url(url: str, *args: object, **kwargs: object) -> DownloadResponse:
        calls.append(url)
        if isinstance(failure, int):
            raise urllib.error.HTTPError(url, failure, "permanent failure", {}, None)
        if failure == "certificate":
            raise urllib.error.URLError(ssl.SSLCertVerificationError("untrusted certificate"))
        return DownloadResponse(b"incorrect checksum")

    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", open_url)
    if failure == "unsupported":
        monkeypatch.setattr(bootstrap.platform, "machine", lambda: "unsupported")

    expected_error = urllib.error.HTTPError if isinstance(failure, int) else SystemExit
    if failure == "certificate":
        expected_error = urllib.error.URLError
    with pytest.raises(expected_error):
        bootstrap.main()
    assert len(calls) == (0 if failure == "unsupported" else 1)
    assert archive_download.sleeps == []
    assert not (archive_download.root / ".tools").exists()


def test_uv_version_parser_ignores_build_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recognize the pinned version even when uv prints build metadata."""
    result = SimpleNamespace(stdout="uv 0.11.8 (0e961dd9a 2026-04-27)\n")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: result)

    assert bootstrap._version(Path("uv")) == bootstrap.UV_VERSION


def test_bootstrap_covers_every_supported_student_platform() -> None:
    """Keep every documented host platform resolvable to a pinned uv artifact."""
    assert set(bootstrap.ARTIFACTS) == {
        ("Darwin", "arm64"),
        ("Darwin", "x86_64"),
        ("Windows", "AMD64"),
        ("Linux", "x86_64"),
        ("Linux", "aarch64"),
    }


def test_bootstrap_pins_one_authenticated_artifact_for_each_platform() -> None:
    """Every platform must name a distinct archive with a full SHA-256 digest."""
    artifacts = [artifact for artifact, _ in bootstrap.ARTIFACTS.values()]
    digests = [digest for _, digest in bootstrap.ARTIFACTS.values()]

    assert len(set(artifacts)) == len(artifacts)
    assert len(set(digests)) == len(digests)
    assert all(len(digest) == 64 and set(digest) <= set("0123456789abcdef") for digest in digests)


def test_macos_bootstrap_installs_an_extension_free_executable() -> None:
    """Take the POSIX tarball path on macOS, not the Windows zip and .exe path."""
    for machine in ("arm64", "x86_64"):
        artifact, _ = bootstrap.ARTIFACTS[("Darwin", machine)]
        assert artifact.endswith("-apple-darwin.tar.gz")
    assert ".exe" not in "".join(artifact for artifact, _ in bootstrap.ARTIFACTS.values())
