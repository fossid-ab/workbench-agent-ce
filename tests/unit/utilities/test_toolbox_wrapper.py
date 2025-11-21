# tests/unit/utilities/test_toolbox_wrapper.py

import os
import shutil
import tempfile
from pathlib import Path

import pytest

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
                toolbox_path=toolbox_path, timeout="120"
            )
        except FileSystemError:
            pytest.skip("fossid-toolbox not available")

        assert toolbox_wrapper.toolbox_path == toolbox_path
        assert toolbox_wrapper.timeout == "120"

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

        assert toolbox_wrapper.timeout == "120"


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
        toolbox_wrapper.cleanup_temp_file(result_file)

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
        toolbox_wrapper.cleanup_temp_file(result_file)

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
            toolbox_wrapper.cleanup_temp_file(result_file)
        finally:
            # Clean up temp input file
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestToolboxWrapperRandstring:
    """Test the randstring static method."""

    def test_randstring_default_length(self):
        """Test randstring with default length."""
        result = ToolboxWrapper.randstring()
        assert len(result) == 10
        assert result.isalpha()
        assert result.isupper()

    def test_randstring_custom_length(self):
        """Test randstring with custom length."""
        result = ToolboxWrapper.randstring(5)
        assert len(result) == 5
        assert result.isalpha()
        assert result.isupper()

    def test_randstring_zero_length(self):
        """Test randstring with zero length."""
        result = ToolboxWrapper.randstring(0)
        assert len(result) == 0
        assert result == ""

    def test_randstring_only_valid_chars(self):
        """Test that randstring only contains valid characters."""
        result = ToolboxWrapper.randstring(100)
        valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        for char in result:
            assert char in valid_chars


class TestToolboxWrapperCleanupTempFile:
    """Test the cleanup_temp_file method."""

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

    def test_cleanup_success(self, toolbox_wrapper):
        """Test successful file cleanup."""
        # Create a temporary file to clean up
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".fossid"
        ) as tmp_file:
            tmp_path = tmp_file.name
            tmp_file.write("test content")

        assert os.path.exists(
            tmp_path
        ), "Temp file should exist before cleanup"

        result = toolbox_wrapper.cleanup_temp_file(tmp_path)

        assert result is True
        assert not os.path.exists(
            tmp_path
        ), "Temp file should be deleted after cleanup"

    def test_cleanup_file_not_exists(self, toolbox_wrapper):
        """Test cleanup when file doesn't exist."""
        result = toolbox_wrapper.cleanup_temp_file(
            "/tmp/nonexistent_file_12345.fossid"
        )
        assert result is False

    def test_cleanup_empty_path(self, toolbox_wrapper):
        """Test cleanup with empty file path."""
        result = toolbox_wrapper.cleanup_temp_file("")
        assert result is False

    def test_cleanup_none_path(self, toolbox_wrapper):
        """Test cleanup with None file path."""
        result = toolbox_wrapper.cleanup_temp_file(None)
        assert result is False
