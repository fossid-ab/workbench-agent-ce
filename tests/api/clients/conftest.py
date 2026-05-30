"""Live-test fixtures for API clients (Test Scan, pending paths, mutations)."""

import os
import uuid

import pytest

from workbench_agent.api.exceptions import (
    ProjectNotFoundError,
    ScanNotFoundError,
)

# Substrings for known test-data layout on Test Scan (cs-demo).
SNIPPET_PATH_MARKER = os.environ.get(
    "WORKBENCH_TEST_SNIPPET_PATH_MARKER", "Snippet"
)
OPENFASTPATH_MARKER = os.environ.get(
    "WORKBENCH_TEST_OPENFASTPATH_MARKER", "OpenFastPath"
)


@pytest.fixture(scope="session")
def test_project_name():
    return os.environ.get("WORKBENCH_TEST_PROJECT_NAME", "Test Project")


@pytest.fixture(scope="session")
def test_scan_name():
    return os.environ.get("WORKBENCH_TEST_SCAN_NAME", "Test Scan")


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
    Resolve scan code by env override or resolver lookup.

    Set WORKBENCH_TEST_SCAN_CODE to skip name resolution.
    """
    override = os.environ.get("WORKBENCH_TEST_SCAN_CODE")
    if override:
        return override
    try:
        _, scan_code, _ = workbench_client.resolver.find_project_and_scan(
            test_project_name,
            test_scan_name,
        )
        return scan_code
    except (ProjectNotFoundError, ScanNotFoundError) as exc:
        pytest.skip(
            f"Test scan not found ({test_project_name!r} / "
            f"{test_scan_name!r}): {exc}. "
            "Create the project and scan or set WORKBENCH_TEST_SCAN_CODE."
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
    """Pending identification files for the test scan (file_id -> path)."""
    pending = workbench_client.scans.get_pending_files(test_scan_code)
    if not pending:
        pytest.skip(
            f"No pending files on scan {test_scan_code!r}. "
            "Upload content, run the scan, and ensure files are pending ID."
        )
    return pending


@pytest.fixture(scope="session")
def pending_paths(pending_files):
    """Relative paths of pending files for identification tests."""
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
            "Ensure Test Scan includes Files with Snippets test data."
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
        "Ensure Test Scan includes OpenFastPath test data."
    )


@pytest.fixture(scope="session")
def scan_has_pending(workbench_client, test_scan_code):
    """Ensure the test scan has at least one pending file."""
    metrics = workbench_client.results.get_scan_metrics(test_scan_code)
    pending = int(metrics.get("pending_identification", 0) or 0)
    if pending < 1:
        pytest.skip(
            f"Scan {test_scan_code!r} has no pending_identification "
            f"(metrics: {metrics}). Re-run the scan on Test Scan."
        )
    return metrics


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
            "against the shared Test Scan."
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
