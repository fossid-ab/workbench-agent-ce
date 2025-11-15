import os
import stat
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from workbench_agent.exceptions import FileSystemError
from workbench_agent.utilities.prep_upload_archive import UploadArchivePrep


# --- Tests for should_exclude_file ---
def test_should_exclude_file_defaults():
    """Test default exclusions."""
    # Should exclude git directories
    assert UploadArchivePrep.should_exclude_file("/path/to/.git/config") is True
    assert UploadArchivePrep.should_exclude_file("/path/to/project/.git/HEAD") is True

    # Should exclude cache files
    assert UploadArchivePrep.should_exclude_file("/path/to/__pycache__/module.pyc") is True
    assert UploadArchivePrep.should_exclude_file("/path/to/file.pyc") is True

    # Should exclude node_modules
    assert UploadArchivePrep.should_exclude_file("/path/to/node_modules/package/index.js") is True

    # Should exclude OS files
    assert UploadArchivePrep.should_exclude_file("/path/to/.DS_Store") is True
    assert UploadArchivePrep.should_exclude_file("/path/to/Thumbs.db") is True

    # Should exclude IDE files
    assert UploadArchivePrep.should_exclude_file("/path/to/.vscode/settings.json") is True
    assert UploadArchivePrep.should_exclude_file("/path/to/.idea/workspace.xml") is True

    # Should exclude temp files
    assert UploadArchivePrep.should_exclude_file("/path/to/file.tmp") is True
    assert UploadArchivePrep.should_exclude_file("/path/to/file.temp") is True


def test_should_exclude_file_include_regular():
    """Test that regular files are not excluded."""
    assert UploadArchivePrep.should_exclude_file("/path/to/main.py") is False
    assert UploadArchivePrep.should_exclude_file("/path/to/README.md") is False
    assert UploadArchivePrep.should_exclude_file("/path/to/package.json") is False
    assert UploadArchivePrep.should_exclude_file("/path/to/src/module.js") is False


def test_should_exclude_file_custom_exclusions():
    """Test custom exclusion patterns."""
    custom_exclusions = {"*.log", "build", "secret.txt"}

    assert UploadArchivePrep.should_exclude_file("/path/to/app.log", custom_exclusions) is True
    assert UploadArchivePrep.should_exclude_file("/path/to/debug.log", custom_exclusions) is True
    assert (
        UploadArchivePrep.should_exclude_file("/path/to/build/output.js", custom_exclusions) is True
    )
    assert UploadArchivePrep.should_exclude_file("/path/to/secret.txt", custom_exclusions) is True

    # Should not exclude files not in custom set
    assert UploadArchivePrep.should_exclude_file("/path/to/main.py", custom_exclusions) is False


def test_should_exclude_file_empty_exclusions():
    """Test with empty exclusions set."""
    assert UploadArchivePrep.should_exclude_file("/path/to/.git/config", set()) is False
    assert UploadArchivePrep.should_exclude_file("/path/to/any/file.txt", set()) is False


# --- Tests for validate_file_for_archive ---
@patch("os.path.isfile")
@patch("os.access")
@patch("os.stat")
def test_validate_file_for_archive_valid_file(mock_stat, mock_access, mock_isfile):
    """Test validation of a valid file."""
    mock_isfile.return_value = True
    mock_access.return_value = True
    mock_stat.return_value = MagicMock(st_size=1024)

    assert UploadArchivePrep.validate_file_for_archive("/path/to/file.txt") is True


@patch("os.path.isfile")
def test_validate_file_for_archive_not_file(mock_isfile):
    """Test validation when path is not a file."""
    mock_isfile.return_value = False

    assert UploadArchivePrep.validate_file_for_archive("/path/to/directory") is False


@patch("os.path.isfile")
@patch("os.access")
def test_validate_file_for_archive_not_readable(mock_access, mock_isfile):
    """Test validation when file is not readable."""
    mock_isfile.return_value = True
    mock_access.return_value = False

    assert UploadArchivePrep.validate_file_for_archive("/path/to/file.txt") is False


@patch("os.path.isfile")
@patch("os.access")
@patch("os.stat")
def test_validate_file_for_archive_empty_file(mock_stat, mock_access, mock_isfile):
    """Test validation of empty file."""
    mock_isfile.return_value = True
    mock_access.return_value = True
    mock_stat.return_value = MagicMock(st_size=0)

    # Empty files should be allowed if they are real files
    assert UploadArchivePrep.validate_file_for_archive("/path/to/empty.txt") is True


@patch("os.path.isfile")
@patch("os.access")
@patch("os.stat")
def test_validate_file_for_archive_stat_error(mock_stat, mock_access, mock_isfile):
    """Test validation when stat fails."""
    mock_isfile.return_value = True
    mock_access.return_value = True
    mock_stat.side_effect = OSError("Stat failed")

    assert UploadArchivePrep.validate_file_for_archive("/path/to/file.txt") is False


@patch("os.path.isfile")
def test_validate_file_for_archive_exception(mock_isfile):
    """Test validation when unexpected exception occurs."""
    mock_isfile.side_effect = Exception("Unexpected error")

    assert UploadArchivePrep.validate_file_for_archive("/path/to/file.txt") is False


# --- Tests for _parse_gitignore ---
@patch("os.path.exists")
def test_parse_gitignore_file_not_exists(mock_exists):
    """Test parsing when .gitignore doesn't exist."""
    mock_exists.return_value = False

    patterns = UploadArchivePrep._parse_gitignore("/fake/path")

    assert patterns == []


@patch("os.path.exists")
@patch(
    "builtins.open", new_callable=mock_open, read_data="*.log\n__pycache__/\n# Comment\n\nbuild/\n"
)
def test_parse_gitignore_success(mock_file, mock_exists):
    """Test successful parsing of .gitignore."""
    mock_exists.return_value = True

    patterns = UploadArchivePrep._parse_gitignore("/test/path")

    expected_patterns = ["*.log", "__pycache__/", "build/"]
    assert patterns == expected_patterns
    mock_file.assert_called_once_with("/test/path/.gitignore", "r", encoding="utf-8")


@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open)
def test_parse_gitignore_read_error(mock_file, mock_exists):
    """Test handling of read errors."""
    mock_exists.return_value = True
    mock_file.side_effect = IOError("Cannot read file")

    patterns = UploadArchivePrep._parse_gitignore("/test/path")

    assert patterns == []


# --- Tests for _is_excluded_by_gitignore ---
def test_is_excluded_by_gitignore_simple_patterns():
    """Test simple gitignore pattern matching."""
    patterns = ["*.log", "build/", "__pycache__"]

    # Should match
    assert UploadArchivePrep._is_excluded_by_gitignore("app.log", patterns) is True
    assert UploadArchivePrep._is_excluded_by_gitignore("debug.log", patterns) is True
    assert (
        UploadArchivePrep._is_excluded_by_gitignore("build", patterns, is_dir=True) is True
    )  # build directory
    assert UploadArchivePrep._is_excluded_by_gitignore("__pycache__", patterns) is True

    # Should not match
    assert UploadArchivePrep._is_excluded_by_gitignore("main.py", patterns) is False
    assert UploadArchivePrep._is_excluded_by_gitignore("src/main.py", patterns) is False
    # build/output.js should NOT match because the pattern "build/" matches the directory, not files inside it
    assert (
        UploadArchivePrep._is_excluded_by_gitignore("build/output.js", patterns, is_dir=False)
        is False
    )


def test_is_excluded_by_gitignore_directory_patterns():
    """Test directory-specific patterns."""
    patterns = ["build/", "*.log"]

    # Directory patterns should match directories
    assert UploadArchivePrep._is_excluded_by_gitignore("build", patterns, is_dir=True) is True
    assert UploadArchivePrep._is_excluded_by_gitignore("src/build", patterns, is_dir=True) is True

    # File patterns should match files
    assert UploadArchivePrep._is_excluded_by_gitignore("error.log", patterns, is_dir=False) is True


def test_is_excluded_by_gitignore_empty_patterns():
    """Test with empty patterns list."""
    assert UploadArchivePrep._is_excluded_by_gitignore("any/file.txt", []) is False


# --- Tests for create_zip_archive ---
def test_create_zip_archive_source_not_directory():
    """Test error when source is not a directory."""
    with pytest.raises(FileSystemError, match="Source path is not a directory"):
        UploadArchivePrep.create_zip_archive("/nonexistent/path")


@patch("os.path.isdir")
@patch("tempfile.mkdtemp")
@patch("os.walk")
@patch("zipfile.ZipFile")
@patch("os.path.exists")
@patch("os.path.getsize")
@patch("workbench_agent.utilities.prep_upload_archive.UploadArchivePrep._parse_gitignore")
def test_create_zip_archive_success(
    mock_parse_gitignore,
    mock_getsize,
    mock_exists,
    mock_zipfile,
    mock_walk,
    mock_mkdtemp,
    mock_isdir,
):
    """Test successful archive creation."""
    # Setup mocks
    mock_isdir.return_value = True
    mock_mkdtemp.return_value = "/tmp/workbench_upload_123"
    mock_parse_gitignore.return_value = []
    mock_exists.return_value = True
    mock_getsize.return_value = 1024  # Non-zero size

    # Mock file walking
    mock_walk.return_value = [
        ("/source", ["subdir"], ["file1.py", "file2.txt"]),
        ("/source/subdir", [], ["file3.js"]),
    ]

    # Mock zipfile
    mock_zip_instance = MagicMock()
    mock_zipfile.return_value.__enter__.return_value = mock_zip_instance

    # Mock file validation
    with patch.object(UploadArchivePrep, "validate_file_for_archive", return_value=True):
        with patch.object(UploadArchivePrep, "should_exclude_file", return_value=False):
            result = UploadArchivePrep.create_zip_archive("/source")

    # Verify archive was created
    assert result.endswith("_upload.zip")
    mock_zipfile.assert_called_once()

    # Verify files were added to zip
    assert mock_zip_instance.write.call_count == 3  # 3 files


@patch("os.path.isdir")
@patch("tempfile.mkdtemp")
@patch("os.walk")
@patch("zipfile.ZipFile")
@patch("os.path.exists")
@patch("os.path.getsize")
@patch("workbench_agent.utilities.prep_upload_archive.UploadArchivePrep._parse_gitignore")
def test_create_zip_archive_with_exclusions(
    mock_parse_gitignore,
    mock_getsize,
    mock_exists,
    mock_zipfile,
    mock_walk,
    mock_mkdtemp,
    mock_isdir,
):
    """Test archive creation with file exclusions."""
    # Setup mocks
    mock_isdir.return_value = True
    mock_mkdtemp.return_value = "/tmp/workbench_upload_123"
    mock_parse_gitignore.return_value = ["*.log"]
    mock_exists.return_value = True
    mock_getsize.return_value = 1024  # Non-zero size

    # Mock file walking
    mock_walk.return_value = [("/source", [], ["file1.py", "debug.log", "file2.txt"])]

    # Mock zipfile
    mock_zip_instance = MagicMock()
    mock_zipfile.return_value.__enter__.return_value = mock_zip_instance

    # Mock file validation - all files valid
    with patch.object(UploadArchivePrep, "validate_file_for_archive", return_value=True):
        # Mock exclusion - exclude .log files
        def mock_should_exclude(file_path, exclusions=None):
            return file_path.endswith(".log")

        def mock_gitignore_exclude(path, patterns, is_dir=False):
            return path.endswith(".log")

        with patch.object(
            UploadArchivePrep, "should_exclude_file", side_effect=mock_should_exclude
        ):
            with patch.object(
                UploadArchivePrep, "_is_excluded_by_gitignore", side_effect=mock_gitignore_exclude
            ):
                result = UploadArchivePrep.create_zip_archive("/source")

    # Verify only non-excluded files were added
    assert mock_zip_instance.write.call_count == 2  # Only .py and .txt files


@patch("os.path.isdir")
@patch("tempfile.mkdtemp")
@patch("os.path.exists")
@patch("os.path.getsize")
def test_create_zip_archive_custom_name(mock_getsize, mock_exists, mock_mkdtemp, mock_isdir):
    """Test archive creation with custom name."""
    mock_isdir.return_value = True
    mock_mkdtemp.return_value = "/tmp/workbench_upload_123"
    mock_exists.return_value = True
    mock_getsize.return_value = 1024  # Non-zero size

    with patch("os.walk", return_value=[]):
        with patch("zipfile.ZipFile"):
            with patch.object(UploadArchivePrep, "_parse_gitignore", return_value=[]):
                result = UploadArchivePrep.create_zip_archive(
                    "/source", archive_name="custom_archive"
                )

    assert result.endswith("custom_archive.zip")


@patch("os.path.isdir")
@patch("tempfile.mkdtemp")
@patch("os.path.exists")
@patch("os.path.getsize")
def test_create_zip_archive_custom_name_with_extension(
    mock_getsize, mock_exists, mock_mkdtemp, mock_isdir
):
    """Test archive creation with custom name already having .zip extension."""
    mock_isdir.return_value = True
    mock_mkdtemp.return_value = "/tmp/workbench_upload_123"
    mock_exists.return_value = True
    mock_getsize.return_value = 1024  # Non-zero size

    with patch("os.walk", return_value=[]):
        with patch("zipfile.ZipFile"):
            with patch.object(UploadArchivePrep, "_parse_gitignore", return_value=[]):
                result = UploadArchivePrep.create_zip_archive("/source", archive_name="custom.zip")

    assert result.endswith("custom.zip")
    # Should not have double .zip extension
    assert not result.endswith(".zip.zip")


@patch("os.path.isdir")
@patch("tempfile.mkdtemp")
@patch("zipfile.ZipFile")
def test_create_zip_archive_zipfile_error(mock_zipfile, mock_mkdtemp, mock_isdir):
    """Test handling of zipfile creation errors."""
    mock_isdir.return_value = True
    mock_mkdtemp.return_value = "/tmp/workbench_upload_123"
    mock_zipfile.side_effect = OSError("Cannot create zip")

    with patch.object(UploadArchivePrep, "_parse_gitignore", return_value=[]):
        with pytest.raises(FileSystemError, match="Archive creation failed"):
            UploadArchivePrep.create_zip_archive("/source")


# --- Tests for _get_file_type_description ---
@patch("os.path.isfile")
@patch("os.path.isdir")
@patch("os.path.islink")
def test_get_file_type_description_file(mock_islink, mock_isdir, mock_isfile):
    """Test file type description for regular file."""
    mock_isfile.return_value = True
    mock_isdir.return_value = False
    mock_islink.return_value = False

    result = UploadArchivePrep._get_file_type_description("/path/to/file.txt")
    assert result == "regular file"


@patch("os.path.isfile")
@patch("os.path.isdir")
@patch("os.path.islink")
def test_get_file_type_description_directory(mock_islink, mock_isdir, mock_isfile):
    """Test file type description for directory."""
    mock_isfile.return_value = False
    mock_isdir.return_value = True
    mock_islink.return_value = False

    result = UploadArchivePrep._get_file_type_description("/path/to/directory")
    assert result == "directory"


@patch("os.path.isfile")
@patch("os.path.isdir")
@patch("os.path.islink")
def test_get_file_type_description_symlink(mock_islink, mock_isdir, mock_isfile):
    """Test file type description for symlink."""
    mock_isfile.return_value = False
    mock_isdir.return_value = False
    mock_islink.return_value = True

    with patch("os.path.realpath", return_value="/path/to/target"):
        with patch("os.path.exists", return_value=True):
            result = UploadArchivePrep._get_file_type_description("/path/to/symlink")
            assert result == "symlink -> /path/to/target"


@patch("os.path.isfile")
@patch("os.path.isdir")
@patch("os.path.islink")
def test_get_file_type_description_unknown(mock_islink, mock_isdir, mock_isfile):
    """Test file type description for unknown type."""
    mock_isfile.return_value = False
    mock_isdir.return_value = False
    mock_islink.return_value = False

    result = UploadArchivePrep._get_file_type_description("/path/to/special")
    assert result == "special file"


# --- Integration test for create_zip_archive ---
def test_create_zip_archive_integration():
    """Integration test: Create a ZIP archive from a real directory structure and verify contents."""
    import shutil

    temp_dir = None
    zip_path = None

    try:
        # Use context manager for temporary directory to ensure cleanup
        with tempfile.TemporaryDirectory() as temp_str:
            temp_dir = Path(temp_str)

            # Create directory structure
            (temp_dir / "src").mkdir()
            (temp_dir / "docs").mkdir()
            (temp_dir / ".git").mkdir()  # Should be excluded
            (temp_dir / "__pycache__").mkdir()  # Should be excluded

            # Create some files
            (temp_dir / "src" / "main.py").write_text("print('Hello, world!')")
            (temp_dir / "docs" / "readme.md").write_text("# Test Project")
            (temp_dir / ".git" / "config").write_text("# Git config")
            (temp_dir / ".gitignore").write_text("*.log\nbuild/\n")

            # Create a file that should be excluded by gitignore
            (temp_dir / "debug.log").write_text("DEBUG LOG")
            (temp_dir / "build").mkdir()
            (temp_dir / "build" / "output.txt").write_text("Build output")

            # Call the method to create a zip archive
            zip_path = UploadArchivePrep.create_zip_archive(str(temp_dir))

            # Verify the zip file was created
            assert os.path.exists(zip_path), f"ZIP file was not created at {zip_path}"

            # Extract the contents to a new temp directory for verification
            with tempfile.TemporaryDirectory() as extract_str:
                extract_dir = Path(extract_str)

                with zipfile.ZipFile(zip_path, "r") as zip_ref:
                    zip_ref.extractall(extract_dir)

                # Get list of all extracted files - normalize paths for cross-platform compatibility
                extracted_files = []
                for root, _, files in os.walk(extract_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, extract_dir)
                        # Normalize path for cross-platform comparison
                        norm_path = rel_path.replace(os.sep, "/")
                        extracted_files.append(norm_path)

                # Check included files - archives contain relative paths from source directory
                included_files = [
                    "src/main.py",
                    "docs/readme.md",
                    ".gitignore",  # .gitignore should be included
                ]
                for file_path in included_files:
                    norm_path = file_path.replace("/", os.sep)
                    assert (
                        norm_path in extracted_files or file_path in extracted_files
                    ), f"Expected file {file_path} not found in ZIP contents: {extracted_files}"

                # Check excluded files/directories (by .gitignore)
                excluded_gitignore = [
                    "debug.log",  # *.log pattern
                    "build/output.txt",  # build/ pattern
                ]
                for file_path in excluded_gitignore:
                    norm_path = file_path.replace("/", os.sep)
                    assert (
                        norm_path not in extracted_files and file_path not in extracted_files
                    ), f"Gitignore-excluded file {file_path} found in ZIP contents: {extracted_files}"

                # Check excluded directories (always excluded)
                excluded_dirs = [".git", "__pycache__"]
                for dir_name in excluded_dirs:
                    prefix = f"{dir_name}/"
                    has_excluded = any(
                        f.startswith(prefix) or f.startswith(prefix.replace("/", os.sep))
                        for f in extracted_files
                    )
                    assert (
                        not has_excluded
                    ), f"Always-excluded directory content from {dir_name} found in ZIP: {extracted_files}"

    finally:
        # Ensure cleanup happens even if assertions fail
        # Note: Using context managers above should handle most cleanup,
        # but this is a backup for the zip file which may be in a separate location
        if zip_path and os.path.exists(zip_path):
            try:
                parent_dir = os.path.dirname(zip_path)
                if os.path.exists(parent_dir):
                    shutil.rmtree(parent_dir, ignore_errors=True)
            except Exception:
                pass  # Ignore cleanup errors
