"""
Functional tests for import-da workflow.

Tests the complete end-to-end workflow:
import-da → show-results → evaluate-gates → download-reports
"""

import subprocess

import pytest


@pytest.mark.functional
@pytest.mark.requires_workbench
class TestImportDAWorkflow:
    """Test complete import-da workflow with all follow-up commands."""

    def test_import_da_workflow(
        self,
        workbench_config,
        temp_reports_dir,
        project_name,
        unique_scan_name,
        fixtures_dir,
    ):
        """
        Test complete import-da workflow.

        Steps:
        1. Import dependency analysis results
        2. Show results with all display options
        3. Evaluate quality gates
        4. Download project-level reports
        5. Download scan-level reports
        """
        # Check for fixture file
        da_file = fixtures_dir / "analyzer-result.json"
        if not da_file.exists():
            pytest.skip(f"Test fixture not found: {da_file}")

        # Step 1: Import-DA
        print(
            f"\n[IMPORT-DA] Step 1: Importing DA results '{unique_scan_name}'"
        )
        result = subprocess.run(
            [
                "workbench-agent",
                "import-da",
                "--project-name",
                project_name,
                "--scan-name",
                unique_scan_name,
                "--path",
                str(da_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            f"Import-da command failed with exit code {result.returncode}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )
        print(f"[IMPORT-DA] Step 1: ✓ DA results imported successfully")

        # Step 2: Show Results
        print(f"[IMPORT-DA] Step 2: Showing results")
        result = subprocess.run(
            [
                "workbench-agent",
                "show-results",
                "--project-name",
                project_name,
                "--scan-name",
                unique_scan_name,
                "--show-scan-metrics",
                "--show-licenses",
                "--show-components",
                "--show-policy-warnings",
                "--show-vulnerabilities",
                "--show-dependencies",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            f"Show results command failed with exit code {result.returncode}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )
        print(f"[IMPORT-DA] Step 2: ✓ Results displayed successfully")

        # Step 3: Evaluate Gates
        print(f"[IMPORT-DA] Step 3: Evaluating quality gates")
        result = subprocess.run(
            [
                "workbench-agent",
                "evaluate-gates",
                "--project-name",
                project_name,
                "--scan-name",
                unique_scan_name,
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            f"Evaluate gates command failed with exit code {result.returncode}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )
        print(f"[IMPORT-DA] Step 3: ✓ Gates evaluated successfully")

        # Step 4: Download Reports (Project Scope)
        print(f"[IMPORT-DA] Step 4: Downloading project-level reports")
        project_reports_dir = temp_reports_dir / "project"
        project_reports_dir.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            [
                "workbench-agent",
                "download-reports",
                "--project-name",
                project_name,
                "--report-scope",
                "project",
                "--report-save-path",
                str(project_reports_dir),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            f"Download project reports failed with exit code {result.returncode}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )
        print(f"[IMPORT-DA] Step 4: ✓ Project reports downloaded successfully")

        # Step 5: Download Reports (Scan Scope)
        print(f"[IMPORT-DA] Step 5: Downloading scan-level reports")
        scan_reports_dir = temp_reports_dir / "scan"
        scan_reports_dir.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            [
                "workbench-agent",
                "download-reports",
                "--project-name",
                project_name,
                "--scan-name",
                unique_scan_name,
                "--report-scope",
                "scan",
                "--report-save-path",
                str(scan_reports_dir),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, (
            f"Download scan reports failed with exit code {result.returncode}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )
        print(f"[IMPORT-DA] Step 5: ✓ Scan reports downloaded successfully")
        print(f"[IMPORT-DA] ✓ Complete workflow passed!")
