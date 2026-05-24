# tests/unit/utilities/test_toolbox_wrapper.py

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.api.exceptions import ProcessError
from workbench_agent.exceptions import FileSystemError
from workbench_agent.utilities.toolbox_wrapper import ToolboxWrapper


class TestToolboxWrapperInitialization:
    """Test ToolboxWrapper initialization and validation."""

    def test_init_success(self):
        """Test successful ToolboxWrapper initialization."""
        toolbox_path = (
            shutil.which("fossid-toolbox")
            or "/usr/local/bin/fossid-toolbox"
        )
        try:
            toolbox_wrapper = ToolboxWrapper(
                toolbox_path=toolbox_path, timeout="300"
            )
        except FileSystemError:
            pytest.skip("fossid-toolbox not available")

        assert toolbox_wrapper.toolbox_path == toolbox_path
        assert toolbox_wrapper.timeout == "300"

    def test_init_with_default_timeout(self):
        """Test initialization with default timeout."""
        toolbox_path = (
            shutil.which("fossid-toolbox")
            or "/usr/local/bin/fossid-toolbox"
        )
        try:
            toolbox_wrapper = ToolboxWrapper(toolbox_path=toolbox_path)
        except FileSystemError:
            pytest.skip("fossid-toolbox not available")

        assert toolbox_wrapper.timeout == "300"


class TestToolboxWrapperGetVersion:
    """Test the get_version method."""

    @pytest.fixture
    def toolbox_wrapper(self):
        """Create a ToolboxWrapper instance for testing."""
        toolbox_path = (
            shutil.which("fossid-toolbox")
            or "/usr/local/bin/fossid-toolbox"
        )
        try:
            return ToolboxWrapper(toolbox_path)
        except FileSystemError:
            pytest.skip("fossid-toolbox not available")

    def test_get_version_success(self, toolbox_wrapper):
        """Test successful version retrieval using real toolbox."""
        version = toolbox_wrapper.get_version()
        assert version is not None
        assert len(version) > 0
        assert "fossid" in version.lower() or "toolbox" in version.lower()


class TestToolboxWrapperGenerateHashes:
    """Test the generate_hashes method."""

    @pytest.fixture
    def toolbox_wrapper(self):
        """Create a ToolboxWrapper instance for testing."""
        toolbox_path = (
            shutil.which("fossid-toolbox")
            or "/usr/local/bin/fossid-toolbox"
        )
        try:
            return ToolboxWrapper(toolbox_path)
        except FileSystemError:
            pytest.skip("fossid-toolbox not available")

    def test_generate_hashes_success(self, toolbox_wrapper):
        """Test successful hash generation using real toolbox."""
        # Use the test file itself as input
        test_file = Path(__file__)
        assert test_file.exists(), "Test file should exist"

        # Generate hashes - this will actually run the toolbox
        result_file = toolbox_wrapper.generate_hashes(str(test_file))

        # Verify result file was created and has content
        assert os.path.exists(
            result_file
        ), f"Result file should exist: {result_file}"
        assert result_file.endswith(
            ".fossid"
        ), "Result file should have .fossid extension"
        assert (
            os.path.getsize(result_file) > 0
        ), "Result file should not be empty"

        # Clean up
        if os.path.exists(result_file):
            os.remove(result_file)

    def test_generate_hashes_with_dependency_analysis(
        self, toolbox_wrapper
    ):
        """Test hash generation with dependency analysis enabled using real toolbox."""
        # Use the test file itself as input
        test_file = Path(__file__)
        assert test_file.exists(), "Test file should exist"

        # Generate hashes with dependency analysis enabled
        result_file = toolbox_wrapper.generate_hashes(
            str(test_file), run_dependency_analysis=True
        )

        # Verify result file was created and has content
        assert os.path.exists(
            result_file
        ), f"Result file should exist: {result_file}"
        assert result_file.endswith(
            ".fossid"
        ), "Result file should have .fossid extension"
        assert (
            os.path.getsize(result_file) > 0
        ), "Result file should not be empty"

        # Clean up
        if os.path.exists(result_file):
            os.remove(result_file)

    def test_generate_hashes_path_not_exists(self, toolbox_wrapper):
        """Test hash generation when input path doesn't exist."""
        with pytest.raises(
            FileSystemError, match="Scan path does not exist"
        ):
            toolbox_wrapper.generate_hashes(
                "/nonexistent/path/that/does/not/exist"
            )

    def test_generate_hashes_empty_output(self, toolbox_wrapper):
        """Test hash generation with empty output file (warning case)."""
        # Create a temporary empty file
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".py"
        ) as tmp_file:
            tmp_file.write("# Empty test file\n")
            tmp_path = tmp_file.name

        try:
            # Generate hashes - toolbox should handle empty files gracefully
            result_file = toolbox_wrapper.generate_hashes(tmp_path)

            # Result file should still be created (even if empty)
            assert os.path.exists(
                result_file
            ), f"Result file should exist: {result_file}"
            assert result_file.endswith(
                ".fossid"
            ), "Result file should have .fossid extension"

            # Clean up
            if os.path.exists(result_file):
                os.remove(result_file)
        finally:
            # Clean up temp input file
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestToolboxWrapperTempFileSafety:
    """
    Mocked tests for the secure temp-file path used by generate_hashes.

    The end-to-end generate_hashes_* tests above require a real
    fossid-toolbox binary and skip in CI; these tests mock the binary
    + subprocess so the temp-file behavior is always exercised.
    """

    @pytest.fixture
    def wrapper(self, tmp_path):
        """Wrapper backed by a fake executable file."""
        fake_toolbox = tmp_path / "fossid-toolbox"
        fake_toolbox.write_text("#!/bin/sh\nexit 0\n")
        fake_toolbox.chmod(0o755)
        return ToolboxWrapper(toolbox_path=str(fake_toolbox))

    def test_temp_file_lives_in_system_temp_dir(self, wrapper, tmp_path):
        """Output file is allocated under tempfile.gettempdir(), not /tmp."""
        scan_target = tmp_path / "src.py"
        scan_target.write_text("x = 1\n")

        completed = MagicMock()
        completed.returncode = 0
        completed.stderr = ""

        with patch(
            "workbench_agent.utilities.toolbox_wrapper.subprocess.run",
            return_value=completed,
        ):
            result_path = wrapper.generate_hashes(str(scan_target))

        try:
            assert result_path.startswith(tempfile.gettempdir())
            assert os.path.basename(result_path).startswith(
                "blind_scan_result_"
            )
            assert result_path.endswith(".fossid")
            assert os.path.exists(result_path)
        finally:
            if os.path.exists(result_path):
                os.unlink(result_path)

    def test_temp_file_is_cleaned_up_on_nonzero_exit(
        self, wrapper, tmp_path
    ):
        """Non-zero exit removes the temp file before raising."""
        scan_target = tmp_path / "src.py"
        scan_target.write_text("x = 1\n")

        failed = MagicMock()
        failed.returncode = 2
        failed.stderr = "boom"

        captured: dict = {}

        def fake_run(*_args, **_kwargs):
            captured["path"] = _kwargs["stdout"].name
            return failed

        with patch(
            "workbench_agent.utilities.toolbox_wrapper.subprocess.run",
            side_effect=fake_run,
        ):
            with pytest.raises(ProcessError, match="exit code 2"):
                wrapper.generate_hashes(str(scan_target))

        assert "path" in captured
        assert not os.path.exists(captured["path"])

    def test_temp_file_is_cleaned_up_on_timeout(self, wrapper, tmp_path):
        """Subprocess timeout removes the temp file before raising."""
        scan_target = tmp_path / "src.py"
        scan_target.write_text("x = 1\n")

        captured: dict = {}

        def fake_run(*_args, **_kwargs):
            captured["path"] = _kwargs["stdout"].name
            raise subprocess.TimeoutExpired(cmd="fossid-toolbox", timeout=1)

        with patch(
            "workbench_agent.utilities.toolbox_wrapper.subprocess.run",
            side_effect=fake_run,
        ):
            with pytest.raises(ProcessError, match="timed out"):
                wrapper.generate_hashes(str(scan_target))

        assert "path" in captured
        assert not os.path.exists(captured["path"])


