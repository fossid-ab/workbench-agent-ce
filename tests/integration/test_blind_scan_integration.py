# tests/integration/test_blind_scan_integration.py

import shutil
import sys
from unittest.mock import MagicMock, mock_open, patch

import pytest

from workbench_agent.main import main


# --- Helper Function to Create Dummy Directories ---
def create_dummy_directory(tmp_path, content="dummy content"):
    """Create a dummy directory with some files for testing."""
    dummy_dir = tmp_path / "test_source_code"
    dummy_dir.mkdir()

    # Add some files to make it look like a real project
    (dummy_dir / "main.py").write_text("print('Hello, World!')")
    (dummy_dir / "requirements.txt").write_text(
        "requests==2.28.0\nflask==2.2.0"
    )
    (dummy_dir / "README.md").write_text(
        "# Test Project\nThis is a test project."
    )

    # Create a subdirectory
    sub_dir = dummy_dir / "src"
    sub_dir.mkdir()
    (sub_dir / "utils.py").write_text("def helper_function(): pass")

    return str(dummy_dir)


class TestBlindScanIntegration:
    """Integration tests for the blind-scan command"""

    @pytest.fixture(scope="class")
    def toolbox_available(self):
        """Check if fossid-toolbox is available on the system."""
        toolbox_path = shutil.which("fossid-toolbox")
        if not toolbox_path:
            pytest.skip("fossid-toolbox not available on system PATH")
        return toolbox_path

    def test_blind_scan_success_flow(
        self, mock_workbench_api, tmp_path, capsys, toolbox_available
    ):
        """
        Integration test for a successful 'blind-scan' command flow.
        Tests the complete workflow from hash generation to scan completion.
        Uses real ToolboxWrapper to test actual hash generation.
        """
        dummy_path = create_dummy_directory(tmp_path)

        # Use real ToolboxWrapper - no mocking needed!
        # The handler will use the real toolbox to generate hashes

        # Mock file system operations
        with (
            patch("os.path.exists", return_value=True),
            patch("os.path.isdir", return_value=True),
            patch(
                "workbench_agent.handlers.blind_scan.cleanup_temp_file",
                return_value=True,
            ),
        ):
            args = [
                "workbench-agent",
                "blind-scan",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProject",
                "--scan-name",
                "TestBlindScan",
                "--path",
                dummy_path,
                "--fossid-toolbox-path",
                toolbox_available,
            ]

            with patch.object(sys, "argv", args):
                return_code = main()
                assert (
                    return_code == 0
                ), "Command should exit with success code"

            # Verify we got success messages in the output
            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert "BLIND-SCAN" in combined_output
            assert "Validating FossID Toolbox" in combined_output
            assert "Generating file hashes" in combined_output
            assert "Hash generation completed" in combined_output

    def test_blind_scan_with_dependency_analysis(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test blind-scan command with dependency analysis enabled.
        """
        dummy_path = create_dummy_directory(tmp_path)

        # Mock ToolboxWrapper
        mock_toolbox = MagicMock()
        mock_toolbox.get_version.return_value = (
            "FossID Toolbox version 2023.2.1"
        )
        mock_toolbox.generate_hashes.return_value = (
            "/tmp/blind_scan_result_TESTRAND.fossid"
        )

        with (
            patch(
                "workbench_agent.handlers.blind_scan.ToolboxWrapper",
                return_value=mock_toolbox,
            ),
            patch("os.path.exists", return_value=True),
            patch("os.path.isdir", return_value=True),
            patch(
                "workbench_agent.handlers.blind_scan.cleanup_temp_file",
                return_value=True,
            ),
        ):
            args = [
                "workbench-agent",
                "blind-scan",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProject",
                "--scan-name",
                "TestBlindScanDA",
                "--path",
                dummy_path,
                "--run-dependency-analysis",
                "--fossid-toolbox-path",
                "/usr/bin/fossid-toolbox",
            ]

            with patch.object(sys, "argv", args):
                return_code = main()
                assert (
                    return_code == 0
                ), "Command should exit with success code"

            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert "DEPENDENCY_ANALYSIS" in combined_output

    def test_blind_scan_no_wait_mode(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test blind-scan command with --no-wait flag.
        """
        dummy_path = create_dummy_directory(tmp_path)

        # Mock ToolboxWrapper
        mock_toolbox = MagicMock()
        mock_toolbox.get_version.return_value = (
            "FossID Toolbox version 2023.2.1"
        )
        mock_toolbox.generate_hashes.return_value = (
            "/tmp/blind_scan_result_TESTRAND.fossid"
        )

        with (
            patch(
                "workbench_agent.handlers.blind_scan.ToolboxWrapper",
                return_value=mock_toolbox,
            ),
            patch("os.path.exists", return_value=True),
            patch("os.path.isdir", return_value=True),
            patch(
                "workbench_agent.handlers.blind_scan.cleanup_temp_file",
                return_value=True,
            ),
        ):
            args = [
                "workbench-agent",
                "blind-scan",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProject",
                "--scan-name",
                "TestBlindScanNoWait",
                "--path",
                dummy_path,
                "--no-wait",
                "--fossid-toolbox-path",
                "/usr/bin/fossid-toolbox",
            ]

            with patch.object(sys, "argv", args):
                return_code = main()
                assert (
                    return_code == 0
                ), "Command should exit with success code"

            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert (
                "--no-wait" in combined_output
                or "no-wait" in combined_output.lower()
            )

    def test_blind_scan_invalid_path(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test blind-scan command with an invalid path.
        """
        # Mock file system to return False for path existence
        with patch("os.path.exists", return_value=False):
            args = [
                "workbench-agent",
                "blind-scan",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProject",
                "--scan-name",
                "TestBlindScanBadPath",
                "--path",
                "/nonexistent/path",
                "--fossid-toolbox-path",
                "/usr/bin/fossid-toolbox",
            ]

            with patch.object(sys, "argv", args):
                return_code = main()
                assert return_code != 0, "Command should exit with error code"

            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert "does not exist" in combined_output

    def test_blind_scan_file_instead_of_directory(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test blind-scan command with a file path instead of directory.
        """
        # Create a file instead of directory
        dummy_file = tmp_path / "test_file.py"
        dummy_file.write_text("print('test')")

        with (
            patch("os.path.exists", return_value=True),
            patch("os.path.isdir", return_value=False),
        ):
            args = [
                "workbench-agent",
                "blind-scan",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProject",
                "--scan-name",
                "TestBlindScanFile",
                "--path",
                str(dummy_file),
                "--fossid-toolbox-path",
                "/usr/bin/fossid-toolbox",
            ]

            with patch.object(sys, "argv", args):
                return_code = main()
                assert return_code != 0, "Command should exit with error code"

            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert "must be a directory" in combined_output

    def test_blind_scan_cli_version_warning(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test blind-scan command when Toolbox version check fails (should fail with error).
        """
        dummy_path = create_dummy_directory(tmp_path)

        # Mock ToolboxWrapper with version failure
        mock_toolbox = MagicMock()
        mock_toolbox.get_version.side_effect = Exception(
            "Version check failed"
        )
        mock_toolbox.generate_hashes.return_value = (
            "/tmp/blind_scan_result_TESTRAND.fossid"
        )

        with (
            patch(
                "workbench_agent.handlers.blind_scan.ToolboxWrapper",
                return_value=mock_toolbox,
            ),
            patch("os.path.exists", return_value=True),
            patch("os.path.isdir", return_value=True),
            patch(
                "workbench_agent.handlers.blind_scan.cleanup_temp_file",
                return_value=True,
            ),
        ):
            args = [
                "workbench-agent",
                "blind-scan",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProject",
                "--scan-name",
                "TestBlindScanVersionWarning",
                "--path",
                dummy_path,
                "--fossid-toolbox-path",
                "/usr/bin/fossid-toolbox",
            ]

            with patch.object(sys, "argv", args):
                return_code = main()
                assert (
                    return_code != 0
                ), "Command should fail when version check fails"

            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert (
                "Version check failed" in combined_output
                or "Toolbox" in combined_output
            )

    def test_blind_scan_dependency_analysis_only(
        self, mock_workbench_api, tmp_path, capsys
    ):
        """
        Test blind-scan command with dependency analysis only (no KB scan).
        """
        dummy_path = create_dummy_directory(tmp_path)

        # Mock ToolboxWrapper
        mock_toolbox = MagicMock()
        mock_toolbox.get_version.return_value = (
            "FossID Toolbox version 2023.2.1"
        )
        mock_toolbox.generate_hashes.return_value = (
            "/tmp/blind_scan_result_TESTRAND.fossid"
        )

        with (
            patch(
                "workbench_agent.handlers.blind_scan.ToolboxWrapper",
                return_value=mock_toolbox,
            ),
            patch("os.path.exists", return_value=True),
            patch("os.path.isdir", return_value=True),
            patch(
                "workbench_agent.handlers.blind_scan.cleanup_temp_file",
                return_value=True,
            ),
        ):
            args = [
                "workbench-agent",
                "blind-scan",
                "--api-url",
                "http://dummy.com",
                "--api-user",
                "test",
                "--api-token",
                "token",
                "--project-name",
                "TestProject",
                "--scan-name",
                "TestBlindScanDAOnly",
                "--path",
                dummy_path,
                "--dependency-analysis-only",
                "--fossid-toolbox-path",
                "/usr/bin/fossid-toolbox",
            ]

            with patch.object(sys, "argv", args):
                return_code = main()
                assert (
                    return_code == 0
                ), "Command should exit with success code"

            captured = capsys.readouterr()
            combined_output = captured.out + captured.err
            assert "Dependency Analysis" in combined_output
