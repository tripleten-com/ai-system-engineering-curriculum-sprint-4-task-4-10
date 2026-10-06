"""Coldline.

===================

File:              tests/contract/authoring.py
Component:         Repository integrity verifier
Purpose:           Checks required Task repository structure and configuration.
Interacts With:    Source packages, Compose, Codespaces, schemas, and uv.lock
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Dependency direction, identity parity, repository integrity
Tools:             Python 3.12, AST, uv, Docker Compose YAML

Add-On 4.10 adds no Compose service, no published port, no visible directory and no source
package: its OpenTofu project sits under ``infra/tofu/`` and its image pin in
``infra/opentofu.yaml``, inside the existing ``infra/`` directory, and OpenTofu and Trivy run
in containers through ``docker run``, not as Compose services. It still supplies its own copy
of ``compose.yaml`` under its own Compose project name, because a project shared with an
earlier Task would let either checkout recreate or reset the other's containers and volumes.
The checks below are Task 4.7's with the Compose project name and the Task id moved on, and
OpenTofu's provider directory left out of the file walk: it is Git-ignored, holds the
provider binary, and is nothing a student or the export writes.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_CONTENT_DIRECTORIES = {
    "config",
    "docs",
    "infra",
    "loadtest",
    "migrations",
    "schemas",
    "security",
    "src",
    "tests",
}
EXPECTED_SOURCE_PACKAGES = {"adapters", "api", "common", "domain", "ports", "worker"}
EXPECTED_PORTS = {"JobQueue", "ModelProvider", "ObjectStore", "Retriever", "SecretProvider"}
EXPECTED_SERVICES = {
    "alertmanager",
    "api",
    "grafana",
    "initializer",
    "issuer",
    "jaeger",
    "localstack",
    "postgres",
    "prometheus",
    "redis",
    "worker",
}
# Task 4.2 published the token issuer on 8180 beside the inherited six; Tasks 4.3 to 4.7 and
# Add-On 4.10 add none.
EXPECTED_PUBLISHED_PORTS = {3000, 4566, 8000, 8180, 9090, 9093, 16686}
EXPECTED_PROFILES = {
    "alertmanager": ["observability"],
    "grafana": ["observability"],
    "jaeger": ["observability"],
    "localstack": ["localstack"],
    "prometheus": ["observability"],
}
DISTRIBUTION_NAME = "coldline-task-2-1"
# Each checkpoint owns its own Compose project so two materializations cannot
# share containers or volumes. The name is checked, not assumed: a whole-file
# Compose replacement that forgot to change it would otherwise reconfigure the
# previous Task's stack. Add-On 4.10 supplies its own compose.yaml, Task 4.7's under
# its own name. The images build from this checkout and the observability and issuer
# configuration is bind-mounted from it, so a shared name would let either checkout's
# `poe start` recreate, and its `poe reset` delete, the other's containers and volumes.
COMPOSE_PROJECT_NAME = "coldline-task-4-10"
TASK_ID = "4.10"
SCHEMA_FILES = (
    "infra/postgres/001_opening_checkpoint.sql",
    "infra/postgres/002_retrieval_corpus.sql",
    "infra/postgres/003_idempotency.sql",
    "infra/postgres/004_migration_baseline.sql",
)
# Provider-neutral internal collaborators, per owning module. A new class in one
# of these modules must be added here deliberately; a class that belongs behind
# one of the five ports does not belong in domain at all.
INTERNAL_COLLABORATORS = {
    "src/api/access_policy.py": {"ComposedAccessConstraints"},
    "src/domain/repositories.py": {
        "DocumentRepository",
        "ExceptionRepository",
        "RepositoryError",
        "StateConflict",
    },
    "src/domain/services.py": {
        "ContextAssembler",
        "OrchestratedRetrieval",
        "RetrievalOrchestrator",
    },
    "src/domain/access.py": {
        "AccessConstraint",
        "AccessConstraintProvider",
        "UnrestrictedAccessConstraints",
    },
    "src/domain/failures.py": {
        "CorpusFixtureError",
        "ObjectNotFound",
        "ObjectStoreUnavailable",
        "RetrievalUnavailable",
    },
    "src/domain/idempotency.py": {
        "ClaimState",
        "IdempotencyClaim",
        "IdempotencyConflict",
        "IdempotencyStore",
        "StoredResponse",
    },
    "src/domain/tenant_authorization.py": {"TenantBoundaryAccessConstraints"},
    "src/domain/errors.py": {
        "ProviderError",
        "RetryableProviderError",
        "TerminalProviderError",
    },
    "src/common/audit.py": {
        "AuditEvent",
        "AuditRecord",
        "AuditRecorder",
        "AuditSink",
        "AuditStore",
    },
}
# The adapters that may name a cloud SDK: the object store, the queue and, from Task 4.5,
# the secret store. Composition roots receive a client from an adapter factory.
CLOUD_SDK_ADAPTERS = ("src/adapters/object_store/", "src/adapters/queue/", "src/adapters/secrets/")
QUOTED_VALUE = r"\x27([^\x27]+)\x27"
IGNORED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tools",
    ".venv",
    "__pycache__",
    # Generated by `poe security-scan` and `poe attack-dev`; Git-ignored.
    "reports",
    "evidence",
    # Add-On 4.10: OpenTofu's provider directory under infra/tofu/, written by `tofu init`;
    # Git-ignored. `poe verify`'s own working copy lives under .tools/, ignored above.
    ".terraform",
}


def main() -> int:
    """Run every repository check and report all failures together.

    Returning every failure in one run keeps review cycles short. Public
    verification stays smaller and checks only the Task contract.
    """
    files = _repository_files()
    failures: list[str] = []
    failures.extend(_check_layout())
    failures.extend(_check_placeholders(files))
    failures.extend(_check_unfinished_work(files))
    failures.extend(_check_unresolved_template_tokens(files))
    failures.extend(_check_nested_git())
    failures.extend(_check_ports())
    failures.extend(_check_compose())
    failures.extend(_check_container_policy())
    failures.extend(_check_state_contract())
    failures.extend(_check_service_identities())
    failures.extend(_check_dependency_directions(files))
    failures.extend(_check_configuration_ownership(files))
    failures.extend(_check_submission_schema())
    failures.extend(_check_migration_baseline())
    failures.extend(_check_bootstrap_target())
    failures.extend(_check_markdown_links(files))
    failures.extend(_check_secrets(files))
    failures.extend(_check_lock())
    if failures:
        print("Repository verification failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("Repository verification passed: structure, boundaries, and pins are valid.")
    return 0


def _is_repository_file(path: Path) -> bool:
    """Return whether ``path`` is a source-controlled candidate rather than local tool output.

    Add-On 4.10: OpenTofu's state (``*.tfstate*``) and saved plans (``*.tfplan``) under
    infra/tofu/ are Git-ignored output, like ``.terraform/``, and may hold managed values.
    """
    return (
        path.is_file()
        and not any(part in IGNORED_PARTS for part in path.parts)
        and path.suffix not in (".pyc", ".tfplan")
        and ".tfstate" not in path.name
    )


def _repository_files() -> list[Path]:
    """Return source-controlled candidates while ignoring local tool output."""
    return [path for path in ROOT.rglob("*") if _is_repository_file(path)]


def _check_layout() -> list[str]:
    """Keep the visible repository and Python source trees easy to scan."""
    visible = {
        path.name
        for path in ROOT.iterdir()
        if path.is_dir() and not path.name.startswith(".") and _contains_repository_file(path)
    }
    source_packages = {
        path.name
        for path in (ROOT / "src").iterdir()
        if path.is_dir() and _contains_repository_file(path)
    }
    failures: list[str] = []
    if visible != EXPECTED_CONTENT_DIRECTORIES:
        failures.append(
            f"visible content directories differ: expected {sorted(EXPECTED_CONTENT_DIRECTORIES)}, "
            f"got {sorted(visible)}"
        )
    if source_packages != EXPECTED_SOURCE_PACKAGES:
        failures.append(
            f"source packages differ: expected {sorted(EXPECTED_SOURCE_PACKAGES)}, "
            f"got {sorted(source_packages)}"
        )
    return failures


def _contains_repository_file(directory: Path) -> bool:
    """Ignore empty folders and stale Python caches left by local execution."""
    return any(_is_repository_file(path) for path in directory.rglob("*"))


def _check_placeholders(files: list[Path]) -> list[str]:
    """Reject temporary placeholders and restricted-looking export paths.

    No Task 4.10 path may look like a solution, evaluator, or held-out asset. Task 4.6's
    held-out procedure left with that Task, and the completion/reference versions of the
    Task 4.6 documents this checkpoint supplies carry none of those names.
    """
    failures: list[str] = []
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        lowered = relative.lower()
        if path.name == ".gitkeep":
            failures.append(f"placeholder remains: {relative}")
        if any(part in lowered for part in ("solution", "held-out", "evaluator", "instructor")):
            failures.append(f"restricted-looking path is forbidden: {relative}")
    return failures


def _check_unfinished_work(files: list[Path]) -> list[str]:
    """Reject a shipped module left unimplemented by an *earlier* Task.

    Each Task ships exactly one set of deliberate gaps: its own. A
    ``NotImplementedError`` naming a previous Task means that Task's verified
    completion was not carried forward, and the starter is broken rather than
    unfinished. That is invisible to the current Task's own checks, because
    they do not exercise the previous Task's path.
    """
    marker = re.compile(r"NotImplementedError\(\s*[\"\']Task (\d+\.\d+)")
    failures: list[str] = []
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if path.suffix != ".py" or not relative.startswith("src/"):
            continue
        for referenced in marker.findall(path.read_text(encoding="utf-8")):
            if referenced != TASK_ID:
                failures.append(
                    f"{relative} is left unimplemented for Task {referenced}, but this is "
                    f"Task {TASK_ID}: the earlier Task's verified completion was not carried "
                    "forward"
                )
    return failures


def _check_unresolved_template_tokens(files: list[Path]) -> list[str]:
    """Reject unresolved template tokens in the released repository."""
    found: set[tuple[str, str]] = set()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        relative = path.relative_to(ROOT).as_posix()
        found.update((relative, token) for token in re.findall(r"(?<!\$)\{\{[^{}]+\}\}", text))
    return [f"unresolved template tokens: {sorted(found)}"] if found else []


def _check_nested_git() -> list[str]:
    """Reject nested repository metadata inside the Task root."""
    nested = [path for path in ROOT.rglob(".git") if path.parent.resolve() != ROOT.resolve()]
    return [f"nested Git metadata is forbidden: {path.relative_to(ROOT)}" for path in nested]


def _check_ports() -> list[str]:
    """Confirm that src/ports exposes exactly the five accepted interfaces."""
    ports = {
        node.name
        for path in (ROOT / "src/ports").glob("*.py")
        for node in _parse(path).body
        if isinstance(node, ast.ClassDef) and node.name != "Protocol"
    }
    failures: list[str] = []
    if ports != EXPECTED_PORTS:
        failures.append(
            f"five-port contract mismatch: expected {sorted(EXPECTED_PORTS)}, got {sorted(ports)}"
        )
    for path in (ROOT / "src").rglob("*.py"):
        if path.parent == ROOT / "src/ports":
            continue
        duplicates = {
            node.name
            for node in _parse(path).body
            if isinstance(node, ast.ClassDef) and node.name in EXPECTED_PORTS
        }
        if duplicates:
            failures.append(
                f"port interface redefined outside src/ports: "
                f"{path.relative_to(ROOT)} ({sorted(duplicates)})"
            )
    return failures


def _check_service_identities() -> list[str]:
    """Align process names, import roots, Compose services, and telemetry names."""
    failures: list[str] = []
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    if project["project"]["name"] != DISTRIBUTION_NAME:
        failures.append(f"root distribution identity must be {DISTRIBUTION_NAME}")

    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    if compose.get("name") != COMPOSE_PROJECT_NAME:
        failures.append(
            f"Compose project name must be {COMPOSE_PROJECT_NAME}, got {compose.get('name')!r}"
        )
    for service, telemetry_name in {"api": "coldline-api", "worker": "coldline-worker"}.items():
        if service not in compose["services"]:
            failures.append(f"Compose identity is missing for {service}")
        config_text = (ROOT / "src" / service / "config.py").read_text(encoding="utf-8")
        if f'service_name: str = "{telemetry_name}"' not in config_text:
            failures.append(f"telemetry identity mismatch for {service}")
    return failures


def _check_compose() -> list[str]:
    """Confirm the bounded runtime roster, profiles, and public ports."""
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    services = set(compose["services"])
    failures: list[str] = []
    if services != EXPECTED_SERVICES:
        failures.append(f"Compose service roster mismatch: {sorted(services)}")

    published: set[int] = set()
    for definition in compose["services"].values():
        for mapping in definition.get("ports", []):
            match = re.search(r":-(\d+)}", str(mapping))
            published.add(
                int(match.group(1)) if match else int(str(mapping).split(":", maxsplit=1)[0])
            )
    if published != EXPECTED_PUBLISHED_PORTS:
        failures.append(f"published port contract mismatch: {sorted(published)}")
    for service, profiles in EXPECTED_PROFILES.items():
        if compose["services"][service].get("profiles") != profiles:
            failures.append(f"{service} must belong to the {profiles} Compose profile")
    # LocalStack credentials are development values. A value interpolated from
    # the host environment could smuggle a real credential into the stack.
    localstack = compose["services"]["localstack"]
    if "${" in json.dumps(localstack.get("environment", {})):
        failures.append("LocalStack configuration must not interpolate host environment values")
    # Task 4.5: the secret store is one of LocalStack's emulated services.
    enabled = str(localstack.get("environment", {}).get("SERVICES", ""))
    if "secretsmanager" not in enabled.split(","):
        failures.append("LocalStack must enable secretsmanager beside s3 and sqs")

    devcontainer = json.loads(
        (ROOT / ".devcontainer/devcontainer.json").read_text(encoding="utf-8")
    )
    if set(devcontainer["forwardPorts"]) != published:
        failures.append("Codespaces forwarded ports do not match Compose public ports")
    attributes = devcontainer.get("portsAttributes", {})
    if {int(port) for port in attributes} != published:
        failures.append("Codespaces port attributes do not match forwarded ports")
    for port, attribute in attributes.items():
        if attribute.get("visibility") != "private":
            failures.append(f"Codespaces port {port} must remain private")
    return failures


def _check_container_policy() -> list[str]:
    """Keep the API and worker runtime images explicitly unprivileged."""
    failures: list[str] = []
    for service in ("api", "worker"):
        dockerfile = ROOT / "infra/containers" / f"{service}.Dockerfile"
        text = dockerfile.read_text(encoding="utf-8")
        if "\nUSER coldline\n" not in text:
            failures.append(f"{service} runtime image must declare USER coldline")
    return failures


def _check_state_contract() -> list[str]:
    """Keep the PostgreSQL constraints aligned with the domain enums and embedding."""
    module = _parse(ROOT / "src/domain/contracts.py")
    state_class = next(
        node
        for node in module.body
        if isinstance(node, ast.ClassDef) and node.name == "ExceptionState"
    )
    contract_states = {
        node.value.value
        for node in state_class.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    sql = (ROOT / SCHEMA_FILES[0]).read_text(encoding="utf-8")
    match = re.search(r"state IN \(([^)]+)\)", sql)
    sql_states = set(re.findall(QUOTED_VALUE, match.group(1))) if match else set()
    failures: list[str] = []
    if sql_states != contract_states:
        failures.append(
            "PostgreSQL state constraint differs from ExceptionState: "
            f"{sorted(sql_states)} != {sorted(contract_states)}"
        )

    tier_class = next(
        node for node in module.body if isinstance(node, ast.ClassDef) and node.name == "AccessTier"
    )
    contract_tiers = {
        node.value.value
        for node in tier_class.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    corpus_sql = (ROOT / SCHEMA_FILES[1]).read_text(encoding="utf-8")
    tier_groups = re.findall(r"access_tier IN \(([^)]+)\)", corpus_sql)
    if not tier_groups:
        failures.append("corpus schema declares no access_tier constraint")
    for group in tier_groups:
        sql_tiers = set(re.findall(QUOTED_VALUE, group))
        if sql_tiers != contract_tiers:
            failures.append(
                "PostgreSQL access_tier constraint differs from AccessTier: "
                f"{sorted(sql_tiers)} != {sorted(contract_tiers)}"
            )

    # The dense arm only works when the declared vector width and the domain
    # embedding width are the same number.
    embedding_source = (ROOT / "src/domain/embedding.py").read_text(encoding="utf-8")
    dimensions = re.search(r"EMBEDDING_DIMENSIONS = (\d+)", embedding_source)
    declared = re.search(r"embedding vector\((\d+)\)", corpus_sql)
    if dimensions is None or declared is None:
        failures.append("embedding width is not declared in both the schema and the domain")
    elif dimensions.group(1) != declared.group(1):
        failures.append(
            f"vector column width {declared.group(1)} differs from EMBEDDING_DIMENSIONS "
            f"{dimensions.group(1)}"
        )
    return failures


def _check_dependency_directions(files: list[Path]) -> list[str]:
    """Reject imports that cross the inward-pointing source boundaries."""
    failures: list[str] = []
    provider_modules = ("asyncpg", "boto3", "botocore", "fastapi", "redis", "sqlalchemy")
    cloud_modules = ("boto3", "botocore")
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if path.suffix != ".py" or not relative.startswith("src/"):
            continue
        package = relative.split("/", maxsplit=2)[1]
        imports = _imports(_parse(path))
        if package == "domain" and any(
            name == boundary or name.startswith(f"{boundary}.")
            for name in imports
            for boundary in ("adapters", "api", "common", "ports", "worker")
        ):
            failures.append(f"domain imports outward: {relative}")
        if package == "ports" and any(
            name == boundary or name.startswith(f"{boundary}.")
            for name in imports
            for boundary in ("adapters", "api", "common", "worker")
        ):
            failures.append(f"ports import outward: {relative}")
        # `common` sits beside `domain`: the services and the adapters may import it, and it
        # may import nothing that would make one service depend on the other or on a provider.
        if package == "common" and any(
            name == boundary or name.startswith(f"{boundary}.")
            for name in imports
            for boundary in ("adapters", "api", "worker")
        ):
            failures.append(f"common imports outward: {relative}")
        if package in {"domain", "ports", "common"} and any(
            name == provider or name.startswith(f"{provider}.")
            for name in imports
            for provider in provider_modules
        ):
            failures.append(f"{package} imports a provider or framework: {relative}")
        if package == "adapters" and any(
            name == service or name.startswith(f"{service}.")
            for name in imports
            for service in ("api", "worker")
        ):
            failures.append(f"adapters import a service: {relative}")
        if package == "api" and any(
            name == "worker" or name.startswith("worker.") for name in imports
        ):
            failures.append(f"API imports worker code: {relative}")
        if package == "worker" and any(
            name == "api" or name.startswith("api.") for name in imports
        ):
            failures.append(f"worker imports API code: {relative}")
        # Only the object-store, queue and secret-store adapters may name a cloud SDK.
        # Composition roots receive a client from an adapter factory instead
        # of building one.
        if not relative.startswith(CLOUD_SDK_ADAPTERS) and any(
            name == cloud or name.startswith(f"{cloud}.")
            for name in imports
            for cloud in cloud_modules
        ):
            failures.append(f"cloud SDK import outside an approved adapter: {relative}")

    for relative, expected in INTERNAL_COLLABORATORS.items():
        collaborators = _parse(ROOT / relative)
        declared = {node.name for node in collaborators.body if isinstance(node, ast.ClassDef)}
        if declared != expected:
            failures.append(
                f"internal collaborator allowlist mismatch in {relative}: {sorted(declared)}"
            )
    return failures


def _check_configuration_ownership(files: list[Path]) -> list[str]:
    """Keep direct runtime environment reads in each process config module."""
    allowed = {"src/api/config.py", "src/worker/config.py"}
    failures: list[str] = []
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if path.suffix != ".py" or not relative.startswith("src/"):
            continue
        text = path.read_text(encoding="utf-8")
        if ("os.environ" in text or "os.getenv" in text) and relative not in allowed:
            failures.append(f"runtime environment read outside service config.py: {relative}")
    return failures


def _check_submission_schema() -> list[str]:
    """Confirm the answer schema exposes one direct answers mapping."""
    schema = json.loads(
        (ROOT / "docs/contracts/submission.schema.json").read_text(encoding="utf-8")
    )
    if schema.get("required") != ["answers"] or set(schema.get("properties", {})) != {"answers"}:
        return ["submission schema must expose exactly one top-level answers mapping"]
    return []


def _check_migration_baseline() -> list[str]:
    """Keep the stamped baseline, the baseline revision, and the tool wiring aligned.

    Three things have to agree before a rollback is safe: the initializer stamps
    one revision identifier, exactly one committed revision declares itself the
    root of the chain, and Alembic is pointed at the directory holding it. A
    disagreement would let ``downgrade`` walk past the initialized schema, or
    leave a generated revision chained to nothing.
    """
    stamped = re.search(
        rf"SELECT {QUOTED_VALUE}",
        (ROOT / "infra/postgres/004_migration_baseline.sql").read_text(encoding="utf-8"),
    )
    if stamped is None:
        return ["migration baseline SQL stamps no revision identifier"]

    failures: list[str] = []
    roots: set[str] = set()
    for path in (ROOT / "migrations/versions").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        identifier = re.search(r"""^revision: str = ["']([^"']+)["']""", text, re.MULTILINE)
        if identifier is None:
            failures.append(f"{path.relative_to(ROOT)} declares no revision identifier")
        elif "down_revision: str | None = None" in text:
            roots.add(identifier.group(1))
    if roots != {stamped.group(1)}:
        failures.append(
            f"migration chain roots {sorted(roots)} do not match the stamped baseline "
            f"{stamped.group(1)!r}"
        )

    configuration = (ROOT / "alembic.ini").read_text(encoding="utf-8")
    if "script_location = migrations" not in configuration:
        failures.append("alembic.ini must point script_location at the migrations directory")
    if re.search(r"(?m)^sqlalchemy\.url", configuration):
        failures.append("alembic.ini must not commit a database URL")
    return failures


def _check_bootstrap_target() -> list[str]:
    """Keep the pinned uv binary at the root path used by every wrapper and workflow."""
    bootstrap = (ROOT / "infra/scripts/bootstrap.py").read_text(encoding="utf-8")
    if 'Path(__file__).resolve().parents[2] / ".tools" / "bin"' not in bootstrap:
        return ["bootstrap must install uv below the Task root .tools/bin directory"]
    return []


def _check_markdown_links(files: list[Path]) -> list[str]:
    """Resolve local Markdown links within the Task repository."""
    failures: list[str] = []
    pattern = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
    for path in files:
        if path.suffix.lower() != ".md":
            continue
        for target in pattern.findall(path.read_text(encoding="utf-8")):
            target = target.strip().strip("<>").split("#", maxsplit=1)[0]
            if not target or target.startswith(("http://", "https://", "mailto:")):
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                failures.append(f"broken Markdown link in {path.relative_to(ROOT)}: {target}")
    return failures


def _check_secrets(files: list[Path]) -> list[str]:
    """Reject common private-key and cloud-token shapes from the student-safe tree."""
    patterns = {
        "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    }
    failures: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in patterns.items():
            if pattern.search(text):
                failures.append(f"possible {label} in {path.relative_to(ROOT)}")
    return failures


def _check_lock() -> list[str]:
    """Confirm uv can resolve the committed lock without changing it."""
    executable = ROOT / ".tools" / "bin" / ("uv.exe" if sys.platform == "win32" else "uv")
    try:
        result = subprocess.run(
            [executable, "lock", "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return [f"pinned uv is missing at {executable.relative_to(ROOT)}; run bootstrap first"]
    return [] if result.returncode == 0 else [result.stderr.strip() or "uv.lock is stale"]


def _parse(path: Path) -> ast.Module:
    """Parse one Python module for boundary checks."""
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(module: ast.Module) -> set[str]:
    """Collect absolute import roots from one syntax tree."""
    names: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


if __name__ == "__main__":
    raise SystemExit(main())
