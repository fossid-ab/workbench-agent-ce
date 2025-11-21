# tests/integration/test_download_reports_integration.py

import sys
from unittest.mock import mock_open, patch

from workbench_agent.main import main


class TestDownloadReportsIntegration:
    """Integration tests for the download-reports command"""

    def test_download_reports_success_spdx(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test download-reports command for SPDX report generation.
        """
        # Create a temporary directory for report downloads
        report_dir = tmp_path / "reports"
        report_dir.mkdir()

        # Mock report service methods
        from workbench_agent.api.utils.process_waiter import WaitResult

        mock_workbench_api.reports.SCAN_REPORT_TYPES = {
            "html",
            "spdx",
            "spdx_lite",
            "cyclone_dx",
            "xlsx",
            "dynamic_top_matched_components",
            "string_match",
        }
        mock_workbench_api.reports.generate_scan_report.return_value = 12345
        mock_workbench_api.reports.download_scan_report.return_value = (
            b"Mock SPDX report content"
        )
        mock_workbench_api.reports.save_report.return_value = str(
            report_dir / "report.rdf"
        )
        mock_workbench_api.waiting.wait_for_scan_report_completion.return_value = WaitResult(
            status_data={"status": "FINISHED"}, duration=5.0, success=True
        )

        # Mock file operations
        with (
            patch("os.makedirs", return_value=None),
            patch("builtins.open", new_callable=mock_open),
        ):

            args = [
                "workbench-agent",
                "download-reports",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProj",
                "--scan-name",
                "TestScan",
                "--report-scope",
                "scan",
                "--report-type",
                "spdx",
                "--report-save-path",
                str(report_dir),
            ]

            with patch.object(sys, "argv", args):
                return_code = main()

            assert return_code == 0, "download-reports should succeed"

            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert "DOWNLOAD-REPORTS" in combined_output

    def test_download_reports_success_multiple_types(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test download-reports command for multiple report types.
        """
        # Create a temporary directory for report downloads
        report_dir = tmp_path / "reports"
        report_dir.mkdir()

        # Mock report service methods
        from workbench_agent.api.utils.process_waiter import WaitResult

        mock_workbench_api.reports.SCAN_REPORT_TYPES = {
            "html",
            "spdx",
            "spdx_lite",
            "cyclone_dx",
            "xlsx",
            "dynamic_top_matched_components",
            "string_match",
        }
        mock_workbench_api.reports.generate_scan_report.side_effect = [
            12345,
            12346,
            12347,
        ]
        mock_workbench_api.reports.download_scan_report.side_effect = [
            b"Mock SPDX report content",
            b"Mock CycloneDX report content",
            b"Mock XLSX report content",
        ]
        mock_workbench_api.reports.save_report.return_value = str(
            report_dir / "report.rdf"
        )
        mock_workbench_api.waiting.wait_for_scan_report_completion.return_value = WaitResult(
            status_data={"status": "FINISHED"}, duration=5.0, success=True
        )

        # Mock file operations
        with (
            patch("os.makedirs", return_value=None),
            patch("builtins.open", new_callable=mock_open),
        ):

            args = [
                "workbench-agent",
                "download-reports",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProj",
                "--scan-name",
                "TestScan",
                "--report-scope",
                "scan",
                "--report-type",
                "spdx,cyclone_dx,xlsx",
                "--report-save-path",
                str(report_dir),
            ]

            with patch.object(sys, "argv", args):
                return_code = main()

            assert (
                return_code == 0
            ), "download-reports with multiple types should succeed"

            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert "DOWNLOAD-REPORTS" in combined_output

    def test_download_reports_project_scope(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test download-reports command with project scope.
        """
        # Create a temporary directory for report downloads
        report_dir = tmp_path / "reports"
        report_dir.mkdir()

        # Mock report service methods
        from workbench_agent.api.utils.process_waiter import WaitResult

        mock_workbench_api.reports.PROJECT_REPORT_TYPES = {
            "xlsx",
            "spdx",
            "spdx_lite",
            "cyclone_dx",
        }
        mock_workbench_api.reports.generate_project_report.return_value = 12345
        mock_workbench_api.reports.download_project_report.return_value = (
            b"Mock project SPDX report content"
        )
        mock_workbench_api.reports.save_report.return_value = str(
            report_dir / "report.rdf"
        )
        mock_workbench_api.waiting.wait_for_project_report_completion.return_value = WaitResult(
            status_data={"status": "FINISHED"}, duration=5.0, success=True
        )

        # Mock file operations
        with (
            patch("os.makedirs", return_value=None),
            patch("builtins.open", new_callable=mock_open),
        ):

            args = [
                "workbench-agent",
                "download-reports",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProj",
                "--report-scope",
                "project",
                "--report-type",
                "spdx",
                "--report-save-path",
                str(report_dir),
            ]

            with patch.object(sys, "argv", args):
                return_code = main()

            assert (
                return_code == 0
            ), "download-reports with project scope should succeed"

            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert "DOWNLOAD-REPORTS" in combined_output

    def test_download_reports_project_not_found(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test download-reports command when project is not found (should fail).
        """
        report_dir = tmp_path / "reports"
        report_dir.mkdir()

        # Mock resolver to raise ProjectNotFoundError
        from workbench_agent.api.exceptions import ProjectNotFoundError

        mock_workbench_api.resolver.find_project.side_effect = (
            ProjectNotFoundError("Project 'NonExistentProj' not found")
        )

        args = [
            "workbench-agent",
            "download-reports",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "NonExistentProj",
            "--scan-name",
            "TestScan",
            "--report-scope",
            "scan",
            "--report-type",
            "spdx",
            "--report-save-path",
            str(report_dir),
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        # Should fail due to project not found
        assert (
            return_code != 0
        ), "download-reports should fail when project is not found"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert any(
            term in combined_output.lower()
            for term in ["not found", "error", "project"]
        )

    def test_download_reports_scan_not_found(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test download-reports command when scan is not found (should fail).
        """
        report_dir = tmp_path / "reports"
        report_dir.mkdir()

        # Mock scan resolver to raise ScanNotFoundError
        from workbench_agent.api.exceptions import ScanNotFoundError

        mock_workbench_api.resolver.find_scan.side_effect = ScanNotFoundError(
            "Scan 'NonExistentScan' not found in project 'TestProj'"
        )

        args = [
            "workbench-agent",
            "download-reports",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-name",
            "TestProj",
            "--scan-name",
            "NonExistentScan",
            "--report-scope",
            "scan",
            "--report-type",
            "spdx",
            "--report-save-path",
            str(report_dir),
        ]

        with patch.object(sys, "argv", args):
            return_code = main()

        # Should fail due to scan not found
        assert (
            return_code != 0
        ), "download-reports should fail when scan is not found"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert any(
            term in combined_output.lower()
            for term in ["not found", "error", "scan"]
        )

    def test_download_reports_invalid_directory(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test download-reports command with invalid save directory.
        """
        # Use a path that doesn't exist and can't be created
        invalid_path = "/root/nonexistent/path"

        # Mock os.makedirs to raise a PermissionError
        with patch(
            "os.makedirs", side_effect=PermissionError("Permission denied")
        ):
            args = [
                "workbench-agent",
                "download-reports",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProj",
                "--scan-name",
                "TestScan",
                "--report-scope",
                "scan",
                "--report-type",
                "spdx",
                "--report-save-path",
                invalid_path,
            ]

            with patch.object(sys, "argv", args):
                return_code = main()

            # Should fail due to directory creation error
            assert (
                return_code != 0
            ), "download-reports should fail when directory cannot be created"
            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert any(
                term in combined_output.lower()
                for term in ["permission", "error", "directory", "path"]
            )
