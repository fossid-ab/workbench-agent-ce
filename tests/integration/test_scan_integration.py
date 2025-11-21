# tests/integration/test_scan_integration.py

import sys
from unittest.mock import mock_open, patch

from workbench_agent.main import main


# --- Helper Function to Create Dummy Files/Dirs ---
def create_dummy_path(tmp_path, is_dir=False, content="dummy content"):
    path = tmp_path / ("dummy_dir" if is_dir else "dummy_file.zip")
    if is_dir:
        path.mkdir()
        (path / "file_inside.txt").write_text(content)
    else:
        path.write_text(content)
    return str(path)


class TestScanIntegration:
    """Integration tests for the scan command"""

    def test_scan_success_flow_simple(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Integration test for a successful 'scan' command flow.
        Uses the mock_workbench_api fixture for the new WorkbenchClient structure.
        """
        dummy_path = create_dummy_path(tmp_path, is_dir=False)

        # File system operations
        with (
            patch("os.path.exists", return_value=True),
            patch("os.path.isdir", return_value=False),
            patch("os.path.getsize", return_value=100),
            patch(
                "builtins.open",
                new_callable=mock_open,
                read_data=b"dummy data",
            ),
        ):
            args = [
                "workbench-agent",
                "scan",
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
                "--path",
                dummy_path,
            ]

            with patch.object(sys, "argv", args):
                return_code = main()
                assert (
                    return_code == 0
                ), "Command should exit with success code"

            # Verify we got a success message in the output
            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert (
                "Workbench Agent finished successfully" in combined_output
            )

    def test_scan_with_autoid_flags(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test scan command with AutoID flags enabled.
        """
        dummy_path = create_dummy_path(tmp_path, is_dir=False)

        # File system operations
        with (
            patch("os.path.exists", return_value=True),
            patch("os.path.isdir", return_value=False),
            patch("os.path.getsize", return_value=100),
            patch(
                "builtins.open",
                new_callable=mock_open,
                read_data=b"dummy data",
            ),
        ):
            args = [
                "workbench-agent",
                "scan",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProj",
                "--scan-name",
                "TestScanAutoID",
                "--path",
                dummy_path,
                "--autoid-file-licenses",
                "--autoid-file-copyrights",
                "--autoid-pending-ids",
            ]

            with patch.object(sys, "argv", args):
                return_code = main()
                assert return_code == 0, "Scan with AutoID should succeed"

            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert "SCAN" in combined_output

    def test_scan_with_dependency_analysis(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test scan command with dependency analysis enabled.
        """
        dummy_path = create_dummy_path(tmp_path, is_dir=False)

        # File system operations
        with (
            patch("os.path.exists", return_value=True),
            patch("os.path.isdir", return_value=False),
            patch("os.path.getsize", return_value=100),
            patch(
                "builtins.open",
                new_callable=mock_open,
                read_data=b"dummy data",
            ),
        ):
            args = [
                "workbench-agent",
                "scan",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProj",
                "--scan-name",
                "TestScanDA",
                "--path",
                dummy_path,
                "--run-dependency-analysis",
            ]

            with patch.object(sys, "argv", args):
                return_code = main()
                assert return_code == 0, "Scan with DA should succeed"

            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert "SCAN" in combined_output

    def test_scan_failure_invalid_path(self, tmp_path, capsys):
        """
        Test scan command with invalid path (should fail).
        """
        # Don't create the dummy path, so it doesn't exist
        invalid_path = str(tmp_path / "nonexistent_file.zip")

        args = [
            "workbench-agent",
            "scan",
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
            "--path",
            invalid_path,
        ]

        with patch.object(sys, "argv", args):
            return_code = main()
            assert return_code != 0, "Scan with invalid path should fail"

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        # Should contain some indication of path error
        assert any(
            term in combined_output.lower()
            for term in [
                "path",
                "file",
                "not found",
                "error",
            ]
        )
