"""CLI helpers for functional tests (subprocess invocations)."""

import subprocess


def run_delete_scan_workbench(
    project_name: str,
    scan_name: str,
) -> subprocess.CompletedProcess:
    """Run workbench-agent delete-scan to remove a scan after a workflow test."""
    return subprocess.run(
        [
            "workbench-agent",
            "delete-scan",
            "--project-name",
            project_name,
            "--scan-name",
            scan_name,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def run_delete_scan_by_code(
    project_code: str,
    scan_code: str,
) -> subprocess.CompletedProcess:
    """Run delete-scan using internal project/scan codes (legacy cleanup)."""
    return subprocess.run(
        [
            "workbench-agent",
            "delete-scan",
            "--project-code",
            project_code,
            "--scan-code",
            scan_code,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def assert_delete_scan_succeeded(
    result: subprocess.CompletedProcess,
    project_name: str,
    scan_name: str,
) -> None:
    """Assert delete-scan exited 0; include stdout/stderr on failure."""
    assert result.returncode == 0, (
        f"delete-scan cleanup failed with exit code {result.returncode}\n"
        f"project={project_name!r} scan={scan_name!r}\n"
        f"STDOUT: {result.stdout}\n"
        f"STDERR: {result.stderr}"
    )


def run_legacy_workbench_agent(*extra: str) -> subprocess.CompletedProcess:
    """Run a legacy (no-subcommand) workbench-agent invocation."""
    return subprocess.run(
        ["workbench-agent", *extra],
        capture_output=True,
        text=True,
        check=False,
    )


def assert_legacy_succeeded(
    result: subprocess.CompletedProcess,
    *,
    expected_scan_section: str = "SCAN",
) -> str:
    """Assert a legacy two-phase run exited 0 and ran scan then show-results."""
    combined = result.stdout + result.stderr
    assert result.returncode == 0, (
        f"Legacy command failed with exit code {result.returncode}\n"
        f"STDOUT: {result.stdout}\n"
        f"STDERR: {result.stderr}"
    )
    assert expected_scan_section in combined
    assert "SHOW-RESULTS" in combined
    return combined


def assert_delete_scan_by_code_succeeded(
    result: subprocess.CompletedProcess,
    project_code: str,
    scan_code: str,
) -> None:
    """Assert code-based delete-scan exited 0."""
    assert result.returncode == 0, (
        f"delete-scan cleanup failed with exit code {result.returncode}\n"
        f"project_code={project_code!r} scan_code={scan_code!r}\n"
        f"STDOUT: {result.stdout}\n"
        f"STDERR: {result.stderr}"
    )
