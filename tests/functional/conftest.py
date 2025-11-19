"""Shared fixtures for functional tests."""

import os
import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def workbench_config():
    """
    Check for required Workbench environment variables.
    
    Skips tests if any required variable is missing.
    """
    config = {
        "url": os.environ.get("WORKBENCH_URL"),
        "user": os.environ.get("WORKBENCH_USER"),
        "token": os.environ.get("WORKBENCH_TOKEN"),
    }
    
    missing = [k for k, v in config.items() if not v]
    if missing:
        missing_vars = ', '.join(f'WORKBENCH_{k.upper()}' for k in missing)
        pytest.skip(
            f"Missing required environment variables: {missing_vars}. "
            "Set WORKBENCH_URL, WORKBENCH_USER, and WORKBENCH_TOKEN to run functional tests."
        )
    
    return config


@pytest.fixture
def temp_source_dir():
    """
    Create a temporary source directory with sample files for scanning.
    
    Returns the path to the temporary directory.
    Automatically cleaned up after test.
    """
    tmp_dir = tempfile.mkdtemp()
    
    # Create sample Python files
    Path(tmp_dir, "main.py").write_text("print('Hello, World!')\n")
    Path(tmp_dir, "README.md").write_text("# Test Project\n")
    Path(tmp_dir, "requirements.txt").write_text("requests==2.28.0\n")
    
    yield tmp_dir
    
    # Cleanup
    shutil.rmtree(tmp_dir, ignore_errors=True)


@pytest.fixture
def temp_reports_dir(tmp_path):
    """
    Create a temporary directory for downloaded reports.
    
    Returns a Path object to the reports directory.
    """
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


@pytest.fixture
def unique_scan_name(request):
    """
    Generate a unique scan name for each test.
    
    Uses test class name and a short UUID to ensure uniqueness,
    even when running tests in parallel.
    """
    import uuid
    
    # Get test class name (e.g., "TestScanWorkflow")
    test_class = request.node.cls.__name__ if request.node.cls else "Test"
    
    # Generate short unique ID (first 8 chars of UUID)
    unique_id = str(uuid.uuid4())[:8]
    
    return f"{test_class}-{unique_id}"


@pytest.fixture
def project_name():
    """Return the standard project name used for functional tests."""
    return "FunctionalTestProject"


@pytest.fixture
def fixtures_dir():
    """Return the path to the test fixtures directory."""
    return Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def fossid_toolbox_path():
    """
    Check if fossid-toolbox is available on PATH.
    
    Skips tests that require it if not found.
    """
    toolbox = shutil.which("fossid-toolbox")
    if not toolbox:
        pytest.skip("fossid-toolbox not found in PATH. Required for blind-scan tests.")
    return toolbox

