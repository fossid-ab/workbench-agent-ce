"""Shared API test fixtures (credentials, Workbench client, live Test Scan data)."""

import os
import uuid

import pytest

from workbench_agent.api import WorkbenchClient
from workbench_agent.api.exceptions import (
    ProjectNotFoundError,
    ScanNotFoundError,
)
from workbench_agent.api.utils.version import normalize_workbench_version

DEFAULT_UNIDENTIFIED_SCAN_NAME = "Unidentified Test Scan"
DEFAULT_IDENTIFIED_SCAN_NAME = "Identified Test Scan"
DEFAULT_DEPENDENCY_ANALYSIS_SCAN_NAME = "Dependency Analysis Test Scan"

# Substrings for known test-data layout (same Project Sample Mix on both scans).
SNIPPET_PATH_MARKER = os.environ.get("WORKBENCH_TEST_SNIPPET_PATH_MARKER", "Snippet")
OPENFASTPATH_MARKER = os.environ.get("WORKBENCH_TEST_OPENFASTPATH_MARKER", "OpenFastPath")


def _resolve_scan_code(
    workbench_client: WorkbenchClient,
    project_name: str,
    scan_name: str,
) -> str:
    _, scan = workbench_client.resolver.find_project_and_scan(
        project_name,
        scan_name,
    )
    return scan.code


def _scan_code_fixture(
    workbench_client,
    test_project_name,
    scan_name,
    *,
    env_override_key: str,
    label: str,
):
    override = os.environ.get(env_override_key)
    if override:
        return override
    try:
        return _resolve_scan_code(workbench_client, test_project_name, scan_name)
    except (ProjectNotFoundError, ScanNotFoundError) as exc:
        pytest.skip(
            f"{label} not found ({test_project_name!r} / {scan_name!r}): {exc}. "
            f"Create the scan or set {env_override_key}."
        )


@pytest.fixture(scope="session")
def workbench_config():
    """
    Workbench credentials from environment; skips if missing.

    Live tests read ``WORKBENCH_URL``, ``WORKBENCH_USER``, and
    ``WORKBENCH_TOKEN`` from the process environment.
    """
    config = {
        "url": os.environ.get("WORKBENCH_URL"),
        "user": os.environ.get("WORKBENCH_USER"),
        "token": os.environ.get("WORKBENCH_TOKEN"),
    }
    missing = [k for k, v in config.items() if not v]
    if missing:
        missing_vars = ", ".join(f"WORKBENCH_{k.upper()}" for k in missing)
        pytest.skip(
            f"Missing required environment variables: {missing_vars}. "
            "Set WORKBENCH_URL, WORKBENCH_USER, and WORKBENCH_TOKEN."
        )
    return config


@pytest.fixture(scope="session")
def workbench_client(workbench_config):
    """Real WorkbenchClient connected to the configured server."""
    return WorkbenchClient(
        api_url=workbench_config["url"],
        api_user=workbench_config["user"],
        api_token=workbench_config["token"],
    )


@pytest.fixture(scope="session")
def workbench_version_raw(workbench_client):
    """Raw version string from getConfig (e.g. ``2026.1.0#25559481630``)."""
    return workbench_client.get_workbench_config().get("version", "Unknown")


@pytest.fixture(scope="session")
def workbench_version(workbench_client, workbench_version_raw):
    """
    Normalized MAJOR.MINOR.PATCH used for contracts and fixtures.

    Matches :meth:`WorkbenchClient.get_workbench_version` /
    :func:`workbench_agent.api.utils.version.normalize_workbench_version`.
    """
    cached = getattr(workbench_client, "_workbench_version", "") or ""
    if cached:
        return cached
    normalized = normalize_workbench_version(str(workbench_version_raw))
    return normalized or "unknown"


@pytest.fixture(scope="session")
def test_project_name():
    return os.environ.get("WORKBENCH_TEST_PROJECT_NAME", "Test Project")


@pytest.fixture(scope="session")
def unidentified_test_scan_name():
    """
    Scan with pending identification work (mutations and pending read tests).

    ``WORKBENCH_TEST_SCAN_NAME`` is kept as a backward-compatible alias.
    """
    return (
        os.environ.get("WORKBENCH_TEST_UNIDENTIFIED_SCAN_NAME")
        or os.environ.get("WORKBENCH_TEST_SCAN_NAME")
        or DEFAULT_UNIDENTIFIED_SCAN_NAME
    )


@pytest.fixture(scope="session")
def identified_test_scan_name():
    """Scan with completed identifications (read-only identified-state tests)."""
    return os.environ.get(
        "WORKBENCH_TEST_IDENTIFIED_SCAN_NAME",
        DEFAULT_IDENTIFIED_SCAN_NAME,
    )


@pytest.fixture(scope="session")
def dependency_analysis_test_scan_name():
    """
    Scan with Dependency Analysis only (no KB / FossID matches).

    Used for ``get_dependency_analysis_results`` and related read tests.
    """
    return os.environ.get(
        "WORKBENCH_TEST_DA_SCAN_NAME",
        DEFAULT_DEPENDENCY_ANALYSIS_SCAN_NAME,
    )


@pytest.fixture(scope="session")
def test_scan_name(unidentified_test_scan_name):
    """Default live-test scan: Unidentified Test Scan (pending files)."""
    return unidentified_test_scan_name


@pytest.fixture(scope="session")
def test_project_code(workbench_client, test_project_name):
    """
    Project code for Test Project (resolver lookup).

    Set WORKBENCH_TEST_PROJECT_CODE to skip name resolution.
    """
    override = os.environ.get("WORKBENCH_TEST_PROJECT_CODE")
    if override:
        return override
    try:
        return workbench_client.resolver.find_project(test_project_name)
    except ProjectNotFoundError as exc:
        pytest.skip(
            f"Test project not found ({test_project_name!r}): {exc}. "
            "Create Test Project or set WORKBENCH_TEST_PROJECT_CODE."
        )


@pytest.fixture(scope="session")
def test_scan_code(workbench_client, test_project_name, test_scan_name):
    """
    Unidentified Test Scan code — pending files, mutations, auditor workflow.

    Set ``WORKBENCH_TEST_SCAN_CODE`` (or ``WORKBENCH_TEST_UNIDENTIFIED_SCAN_CODE``)
    to skip name resolution.
    """
    override = os.environ.get("WORKBENCH_TEST_UNIDENTIFIED_SCAN_CODE") or os.environ.get(
        "WORKBENCH_TEST_SCAN_CODE"
    )
    if override:
        return override
    return _scan_code_fixture(
        workbench_client,
        test_project_name,
        test_scan_name,
        env_override_key="WORKBENCH_TEST_SCAN_CODE",
        label="Unidentified test scan",
    )


@pytest.fixture(scope="session")
def identified_test_scan_code(workbench_client, test_project_name, identified_test_scan_name):
    """Identified Test Scan code — stable identified components and licenses."""
    return _scan_code_fixture(
        workbench_client,
        test_project_name,
        identified_test_scan_name,
        env_override_key="WORKBENCH_TEST_IDENTIFIED_SCAN_CODE",
        label="Identified test scan",
    )


@pytest.fixture(scope="session")
def dependency_analysis_test_scan_code(
    workbench_client, test_project_name, dependency_analysis_test_scan_name
):
    """Dependency Analysis Test Scan code — DA import, no KB identified components."""
    return _scan_code_fixture(
        workbench_client,
        test_project_name,
        dependency_analysis_test_scan_name,
        env_override_key="WORKBENCH_TEST_DA_SCAN_CODE",
        label="Dependency Analysis test scan",
    )


def pending_file_paths(pending_files: dict) -> list:
    """
    Relative paths from scans.get_pending_files.

    The API returns {file_id: relative_path}; files_and_folders expects paths.
    """
    paths = []
    for value in pending_files.values():
        if isinstance(value, str) and value:
            paths.append(value)
    return paths


def _find_path(paths: list, marker: str) -> str | None:
    for path in paths:
        if marker in path:
            return path
    return None


@pytest.fixture(scope="session")
def pending_files(workbench_client, test_scan_code):
    """
    Pending identification files from ``scans.get_pending_files``.

    Returns ``{file_id: relative_path}``. All unidentified-scan live tests that
    need file paths should derive from this fixture (or ``pending_paths``).
    """
    pending = workbench_client.scans.get_pending_files(test_scan_code)
    if not pending:
        pytest.skip(
            f"No pending files on scan {test_scan_code!r}. "
            "Upload content, run the scan, and ensure files are pending ID."
        )
    return pending


@pytest.fixture(scope="session")
def pending_paths(pending_files):
    """
    Relative paths from ``scans.get_pending_files`` (dict values).

    Feed these paths to ``files_and_folders.get_identification``,
    ``get_fossid_results``, and the rest of the auditor workflow.
    """
    paths = pending_file_paths(pending_files)
    if not paths:
        pytest.skip(
            "get_pending_files returned no path values. "
            "Expected dict values to be relative file paths."
        )
    return paths


@pytest.fixture
def pending_path(pending_paths):
    """First pending relative path for read-only identification tests."""
    return pending_paths[0]


@pytest.fixture(scope="session")
def snippet_file_path(pending_paths):
    """
    A file under test-data 'Files with Snippets' (partial FossID matches).

    Override discovery with WORKBENCH_TEST_SNIPPET_FILE_PATH if needed.
    """
    override = os.environ.get("WORKBENCH_TEST_SNIPPET_FILE_PATH")
    if override:
        return override
    path = _find_path(pending_paths, SNIPPET_PATH_MARKER)
    if not path:
        pytest.skip(
            f"No pending path containing {SNIPPET_PATH_MARKER!r}. "
            "Ensure Unidentified Test Scan includes Files with Snippets test data."
        )
    return path


@pytest.fixture(scope="session")
def openfastpath_dir(pending_paths):
    """
    OpenFastPath folder at scan root for directory-level identification tests.

    Returns the directory path ``OpenFastPath`` when any pending file is
    under that tree.
    """
    override = os.environ.get("WORKBENCH_TEST_OPENFASTPATH_DIR")
    if override:
        return override
    if _find_path(pending_paths, OPENFASTPATH_MARKER):
        return OPENFASTPATH_MARKER
    pytest.skip(
        f"No pending paths under {OPENFASTPATH_MARKER!r}. "
        "Ensure Unidentified Test Scan includes OpenFastPath test data."
    )


@pytest.fixture(scope="session")
def openfastpath_file_path(pending_paths, openfastpath_dir):
    """A pending file under ``OpenFastPath/`` (same path on both test scans)."""
    path = next(
        (p for p in pending_paths if p.startswith(openfastpath_dir + "/")),
        None,
    )
    if not path:
        pytest.skip("No pending file under OpenFastPath")
    return path


@pytest.fixture(scope="session")
def scan_has_pending(workbench_client, test_scan_code):
    """Ensure the test scan has at least one pending file."""
    metrics = workbench_client.identification.get_scan_metrics(test_scan_code)
    pending = int(metrics.get("pending_identification", 0) or 0)
    if pending < 1:
        pytest.skip(
            f"Scan {test_scan_code!r} has no pending_identification "
            f"(metrics: {metrics}). Re-run the scan on Unidentified Test Scan."
        )
    return metrics


@pytest.fixture(scope="session")
def scan_has_identified(workbench_client, identified_test_scan_code):
    """Ensure Identified Test Scan has at least one identified file."""
    metrics = workbench_client.identification.get_scan_metrics(identified_test_scan_code)
    identified = int(metrics.get("identified_files", 0) or 0)
    if identified < 1:
        pytest.skip(
            f"Scan {identified_test_scan_code!r} has no identified_files "
            f"(metrics: {metrics}). Use Identified Test Scan."
        )
    return metrics


@pytest.fixture(scope="session")
def scan_has_da_results(workbench_client, dependency_analysis_test_scan_code):
    """Ensure Dependency Analysis Test Scan has dependency analysis results."""
    results = workbench_client.scans.get_dependency_analysis_results(
        dependency_analysis_test_scan_code
    )
    if not results:
        pytest.skip(
            f"Scan {dependency_analysis_test_scan_code!r} has no dependency "
            "analysis results. Run Dependency Analysis on Dependency Analysis "
            "Test Scan."
        )
    return results


@pytest.fixture(scope="session")
def scan_has_vulnerabilities(
    workbench_client,
    identified_test_scan_code,
    dependency_analysis_test_scan_code,
):
    """
    First test scan (identified, then DA) that returns CVE rows.

    CVE listing requires identified components and/or dependency analysis.
    """
    for scan_code in (
        identified_test_scan_code,
        dependency_analysis_test_scan_code,
    ):
        vulnerabilities = workbench_client.vulnerability.list_scan_vulnerabilities(scan_code)
        if vulnerabilities:
            return {
                "scan_code": scan_code,
                "vulnerabilities": vulnerabilities,
            }
    pytest.skip(
        "Neither Identified Test Scan nor Dependency Analysis Test Scan "
        "returned vulnerabilities. Ensure KB CVE data is available for "
        "sample components."
    )


@pytest.fixture(scope="session")
def identified_file_path(openfastpath_file_path):
    """
    File path with catalog linkage on Identified Test Scan.

    Same relative paths exist on both scans (Project Sample Mix); discovery
    uses pending files on Unidentified Test Scan. Snippet files may be marked
    identified with a file license only — prefer OpenFastPath for linked
    catalog components.
    """
    return openfastpath_file_path


@pytest.fixture
def allow_mutations():
    """Skip unless WORKBENCH_ALLOW_MUTATIONS is set."""
    if os.environ.get("WORKBENCH_ALLOW_MUTATIONS", "").lower() not in (
        "1",
        "true",
        "yes",
    ):
        pytest.skip(
            "Set WORKBENCH_ALLOW_MUTATIONS=1 to run mutation tests "
            "against the shared Unidentified Test Scan."
        )


@pytest.fixture
def unique_component_name():
    """Unique component name for create/delete mutation tests."""
    return f"api-test-component-{uuid.uuid4().hex[:12]}"


@pytest.fixture
def mutation_pending_path(pending_paths, pending_path):
    """
    Path used for mutations; prefers second pending file when available
    so read-only tests can keep using the first path.
    """
    if len(pending_paths) > 1:
        return pending_paths[1]
    return pending_path


@pytest.fixture
def identification_service(workbench_client):
    """IdentificationService wired on WorkbenchClient."""
    return workbench_client.identification


@pytest.fixture
def dependency_service(workbench_client):
    """DependencyService wired on WorkbenchClient."""
    return workbench_client.dependencies


@pytest.fixture
def vulnerability_service(workbench_client):
    """VulnerabilityService wired on WorkbenchClient."""
    return workbench_client.vulnerability
