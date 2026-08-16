"""
Wrapper for FossID Toolbox invocations.

Used for blind-scan hashing (``fossid-toolbox hash``) and for the
``analyze`` command's dependency pipeline (``fossid-toolbox da``).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import traceback
from dataclasses import dataclass
from typing import List, Optional

from packaging import version as packaging_version

from workbench_agent.api.exceptions import ProcessError
from workbench_agent.exceptions import FileSystemError, ValidationError
from workbench_agent.utilities.upload_data_prep import cleanup_temp_path

logger = logging.getLogger("workbench-agent")

# Minimum FossID Toolbox version supported by this Workbench Agent CE release.
MINIMUM_TOOLBOX_VERSION = "1.7.11"

DA_REPORT_NAME = "analyzer-result.json"
DA_SOURCES_NAME = "first-party-sources.json"


@dataclass
class DaPipelineResult:
    """Outcome of a ``fossid-toolbox da --pipeline`` run."""

    report_path: str
    output_dir: str
    #: Sidecar listing the project's own source files, written only when
    #: ``emit_source_files`` was requested.
    sources_path: Optional[str] = None


def build_da_pipeline_args(
    *,
    input_path: str,
    output_dir: str,
    ecosystem: Optional[str] = None,
    bazel_target: Optional[str] = None,
    bazel_path: Optional[str] = None,
    bazel_mode: Optional[str] = None,
    gradle_project: Optional[str] = None,
    force_pipeline_build: bool = False,
    emit_source_files: bool = False,
) -> List[str]:
    """
    Build the argument list for ``fossid-toolbox da --pipeline``.

    Returns flags after the ``da`` subcommand. ``-c/--fossid-conf-path``
    is a Toolbox global and is applied by ``run_da_pipeline``, not here.
    """
    args = [
        "--pipeline",
        "--input",
        input_path,
        "--output",
        output_dir,
    ]
    if ecosystem:
        args.extend(["--ecosystem", ecosystem])
    if bazel_target:
        args.extend(["--bazel-target", bazel_target])
    if bazel_path:
        args.extend(["--bazel-path", bazel_path])
    if bazel_mode:
        args.extend(["--bazel-mode", bazel_mode])
    if gradle_project:
        args.extend(["--gradle-project", gradle_project])
    if force_pipeline_build:
        args.append("--force-pipeline-build")
    if emit_source_files:
        args.append("--emit-source-files")
    return args


def resolve_fossid_toolbox_path(configured: Optional[str]) -> str:
    """
    Return the path to the fossid-toolbox executable.

    If ``configured`` is set, it is used as-is. Otherwise ``fossid-toolbox``
    is resolved via the process environment PATH (``shutil.which``).
    """
    if configured:
        return configured
    resolved = shutil.which("fossid-toolbox")
    if not resolved:
        raise ValidationError(
            "fossid-toolbox not found in PATH. Install FossID Toolbox or "
            "pass --fossid-toolbox-path with the path to the executable."
        )
    return resolved


def validate_fossid_file(file_path: str) -> None:
    """
    Validate the encoding and schema of a pre-generated .fossid file.

    The file must be valid UTF-8.
    Each line must be a JSON object containing at minimum:
    - path (str): Relative file path
    - size (int): File size in bytes
    - hashes_ffm (list): Hash objects, each with format (int) and data (str)

    Args:
        file_path: Path to the .fossid file to validate

    Raises:
        ValidationError: If the file is not UTF-8, is empty, or has invalid
            schema
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except UnicodeDecodeError as e:
        raise ValidationError(
            f"The .fossid file '{file_path}' is not valid UTF-8 "
            f"(byte {e.start}: {e.reason}). Re-generate it with "
            f"fossid-toolbox or re-encode it as UTF-8."
        ) from e
    except Exception as e:
        raise ValidationError(f"Failed to read .fossid file '{file_path}': {e}") from e

    if not lines or all(line.strip() == "" for line in lines):
        raise ValidationError(f"The .fossid file '{file_path}' is empty.")

    required_fields = {"path": str, "size": int, "hashes_ffm": list}

    for line_num, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValidationError(
                f"Invalid JSON on line {line_num} of " f"'{file_path}': {e}"
            ) from e

        if not isinstance(entry, dict):
            raise ValidationError(f"Line {line_num} of '{file_path}' is not a JSON object.")

        for field, expected_type in required_fields.items():
            if field not in entry:
                raise ValidationError(
                    f"Line {line_num} of '{file_path}' is missing " f"required field '{field}'."
                )
            if not isinstance(entry[field], expected_type):
                raise ValidationError(
                    f"Line {line_num} of '{file_path}': '{field}' must "
                    f"be {expected_type.__name__}."
                )

        for i, hash_entry in enumerate(entry["hashes_ffm"]):
            if not isinstance(hash_entry, dict):
                raise ValidationError(
                    f"Line {line_num} of '{file_path}': " f"'hashes_ffm[{i}]' must be an object."
                )
            if "format" not in hash_entry or "data" not in hash_entry:
                raise ValidationError(
                    f"Line {line_num} of '{file_path}': "
                    f"'hashes_ffm[{i}]' must have 'format' and "
                    f"'data' fields."
                )

    non_empty = sum(1 for line in lines if line.strip())
    logger.info(f"Validated .fossid file '{file_path}': {non_empty} entries.")


class ToolboxWrapper:
    """
    A class to interact with FossID Toolbox.

    Attributes:
        toolbox_path (str): Path to the FossID Toolbox executable
        timeout (str): Timeout for Toolbox subprocesses in seconds
    """

    def __init__(self, toolbox_path: str, timeout: str = "300"):
        """
        Initialize ToolboxWrapper.

        Args:
            toolbox_path: Path to the fossid-toolbox executable
            timeout: Timeout in seconds (default: "300")

        Raises:
            FileSystemError: If toolbox_path doesn't exist or isn't executable
        """
        self.toolbox_path = toolbox_path
        self.timeout = timeout

        # Validate CLI path exists and is executable
        if not os.path.exists(toolbox_path):
            raise FileSystemError(f"FossID Toolbox not found at path: {toolbox_path}")
        if not os.access(toolbox_path, os.X_OK):
            raise FileSystemError(f"FossID Toolbox not executable: {toolbox_path}")

        logger.debug(
            f"ToolboxWrapper initialized with toolbox_path={toolbox_path}, " f"timeout={timeout}"
        )

    def get_version(self) -> str:
        """
        Get Toolbox version.

        Returns:
            str: Version from "fossid-toolbox --version"

        Raises:
            ProcessError: If toolbox execution fails
        """
        args = [self.toolbox_path, "--version"]
        logger.debug(f"Getting Toolbox version with: {' '.join(args)}")

        try:
            result = subprocess.check_output(
                args, stderr=subprocess.STDOUT, timeout=int(self.timeout)
            )
            version = result.decode("utf-8").strip()
            logger.debug("FossID Toolbox version: %s", version)
            return version
        except subprocess.TimeoutExpired as e:
            error_msg = f"Toolbox version check timed out after " f"{self.timeout} seconds"
            logger.error(error_msg)
            raise ProcessError(error_msg) from e
        except (PermissionError, OSError) as e:
            # Raised when the file cannot be executed at all, e.g. it is
            # missing the execute bit or is not a runnable binary.
            error_msg = (
                f"Could not run FossID Toolbox at '{self.toolbox_path}': {e}. "
                f"Ensure the file is executable and that it points to a "
                f"valid fossid-toolbox binary."
            )
            logger.error(error_msg)
            raise ProcessError(error_msg) from e
        except subprocess.CalledProcessError as e:
            # A negative return code means the process was killed by a signal
            # (for example -9 = SIGKILL), which usually indicates the binary
            # could not actually run.
            error_msg = (
                f"Toolbox version check failed: FossID Toolbox at "
                f"'{self.toolbox_path}' exited with code {e.returncode}. "
                f"Ensure the file is executable and points to a valid "
                f"fossid-toolbox binary."
            )
            logger.error(error_msg)
            raise ProcessError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error getting Toolbox version: {e}"
            logger.error(error_msg)
            raise ProcessError(error_msg) from e

    def validate_toolbox_version(
        self,
        version_string: str,
        minimum: str = MINIMUM_TOOLBOX_VERSION,
        purpose: str = "this agent",
    ) -> None:
        """
        Validate that the Toolbox version is supported by this agent.

        Parses the version number out of the raw ``--version`` output
        (for example "FossID Toolbox version 1.7.11") and compares it
        against the minimum supported version using semantic version
        ordering.

        Args:
            version_string: Raw version output from get_version()
            minimum: Minimum supported version (defaults to
                MINIMUM_TOOLBOX_VERSION)
            purpose: Feature name used in the error message

        Raises:
            ProcessError: If the detected version is below the minimum
        """
        match = re.search(r"(\d+\.\d+(?:\.\d+)*)", version_string)
        if not match:
            logger.warning(
                f"Could not parse Toolbox version from '{version_string}'. "
                f"Proceeding without a version compatibility check."
            )
            return

        detected = match.group(1)
        try:
            parsed_version = packaging_version.parse(detected)
            min_version = packaging_version.parse(minimum)
        except packaging_version.InvalidVersion:
            logger.warning(
                f"Could not parse Toolbox version '{detected}'. "
                f"Proceeding without a version compatibility check."
            )
            return

        if parsed_version < min_version:
            from workbench_agent import __version__

            error_msg = (
                f"FossID Toolbox {detected} is not supported. Workbench Agent "
                f"CE {__version__} requires Toolbox {minimum} or later."
                f"Please download a newer version of Toolbox."
            )
            logger.error(error_msg)
            raise ProcessError(error_msg)

        logger.debug(
            f"Toolbox {detected} satisfies minimum supported " f"version {minimum}"
        )

    def generate_hashes(
        self,
        path: str,
        run_dependency_analysis: bool = False,
        enable_lac_extraction: bool = True,
    ) -> str:
        """
        Generate hashes using FossID Toolbox.

        Uses the FossID Toolbox hash command to generate signatures
        for the given path. The output is redirected to a temporary file.

        Args:
            path: Path of the code to generate hashes for
            run_dependency_analysis: Whether to enable manifest
                generation for dependency analysis (default: False)
            enable_lac_extraction: Whether to enable License and Copyright
                (LAC) extraction during hashing (default: True)

        Returns:
            str: Path to temporary .fossid file containing generated
                 hashes and signatures

        Raises:
            FileSystemError: If the input path doesn't exist
            ProcessError: If toolbox execution fails
        """
        if not os.path.exists(path):
            raise FileSystemError(f"Scan path does not exist: {path}")

        # Securely allocate the output file in the system temp dir.
        try:
            fd, temporary_file_path = tempfile.mkstemp(
                prefix="blind_scan_result_", suffix=".fossid"
            )
            os.close(fd)
        except OSError as e:
            raise FileSystemError(f"Failed to create temporary hash file: {e}") from e

        logger.info(f"Hashing path: {path}")
        logger.debug(f"Temporary file will be created at: {temporary_file_path}")

        # Build fossid-toolbox hash command
        # Format: fossid-toolbox hash [OPTIONS] <PATHS>...
        cmd_args = [self.toolbox_path, "hash"]  # Hash command

        if run_dependency_analysis:
            # Enable manifest for dependency analysis
            cmd_args.append("--enable-manifest=true")
            logger.debug("Manifest capture enabled for dependency analysis")

        if enable_lac_extraction:
            # Enable License and Copyright (LAC) extraction
            cmd_args.append("--enable-la")
            logger.debug("LAC extraction enabled")

        cmd_args.append(path)  # Path to scan (must be last)
        logger.debug(f"Executing fossid-toolbox hash command: {' '.join(cmd_args)}")

        try:
            # Execute command and redirect output to temporary file.
            # Use binary mode for the file because subprocess writes the
            # child's raw bytes via the underlying file descriptor and
            # bypasses Python's text-mode wrapper. Decode stderr explicitly
            # as UTF-8 with replacement so a non-UTF-8 byte in a diagnostic
            # message can't crash the parent on a non-UTF-8 system locale.
            with open(temporary_file_path, "wb") as outfile:
                result = subprocess.run(
                    cmd_args,
                    stdout=outfile,
                    stderr=subprocess.PIPE,
                    encoding="utf-8",
                    errors="replace",
                    timeout=int(self.timeout),
                    check=False,  # We handle return code manually
                )

            if result.returncode != 0:
                error_msg = (
                    f"Toolbox hash generation failed with exit code "
                    f"{result.returncode}: {result.stderr}"
                )
                logger.error(error_msg)
                cleanup_temp_path(temporary_file_path)
                raise ProcessError(error_msg)

            # Verify temporary file was created and has content
            if not os.path.exists(temporary_file_path):
                raise ProcessError(f"Temporary file was not created: " f"{temporary_file_path}")

            file_size = os.path.getsize(temporary_file_path)
            if file_size == 0:
                logger.warning("Hash generation completed but generated empty file.")
            else:
                logger.info(
                    f"Hash generation completed successfully. "
                    f"Generated {file_size} bytes of signature data."
                )

            return temporary_file_path

        except subprocess.TimeoutExpired as e:
            error_msg = f"Hash generation timed out after {self.timeout} seconds"
            logger.error(error_msg)
            cleanup_temp_path(temporary_file_path)
            raise ProcessError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error during hash generation: {e}"
            logger.error(error_msg)
            logger.debug(traceback.format_exc())
            cleanup_temp_path(temporary_file_path)
            raise ProcessError(error_msg) from e

    def run_da_pipeline(
        self,
        *,
        input_path: str,
        ecosystem: Optional[str] = None,
        bazel_target: Optional[str] = None,
        bazel_path: Optional[str] = None,
        bazel_mode: Optional[str] = None,
        gradle_project: Optional[str] = None,
        force_pipeline_build: bool = False,
        emit_source_files: bool = False,
        fossid_conf_path: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> DaPipelineResult:
        """
        Run ``fossid-toolbox da --pipeline`` and return the report path.

        With ``emit_source_files``, Toolbox also writes the first-party
        source list for the KB scan; its path comes back as
        ``DaPipelineResult.sources_path``.

        A temporary output directory is created for the report. Callers
        own cleanup of ``DaPipelineResult.output_dir``.
        """
        output_dir = tempfile.mkdtemp(prefix="workbench_agent_da_")
        args = build_da_pipeline_args(
            input_path=input_path,
            output_dir=output_dir,
            ecosystem=ecosystem,
            bazel_target=bazel_target,
            bazel_path=bazel_path,
            bazel_mode=bazel_mode,
            gradle_project=gradle_project,
            force_pipeline_build=force_pipeline_build,
            emit_source_files=emit_source_files,
        )
        cmd = [self.toolbox_path]
        if fossid_conf_path:
            cmd.extend(["-c", fossid_conf_path])
        cmd.append("da")
        cmd.extend(args)

        run_timeout = timeout if timeout is not None else int(self.timeout)
        logger.debug("Running Toolbox DA pipeline: %s", " ".join(cmd))
        print("Scanning Project with Toolbox Dependency Analysis...")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=run_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            shutil.rmtree(output_dir, ignore_errors=True)
            raise ProcessError(
                f"Toolbox DA pipeline timed out after {run_timeout} seconds"
            ) from e
        except OSError as e:
            shutil.rmtree(output_dir, ignore_errors=True)
            raise ProcessError(
                f"Failed to run FossID Toolbox at '{self.toolbox_path}': {e}"
            ) from e

        if result.stdout:
            logger.debug("Toolbox DA stdout:\n%s", result.stdout)
        if result.stderr:
            logger.debug("Toolbox DA stderr:\n%s", result.stderr)

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            shutil.rmtree(output_dir, ignore_errors=True)
            raise ProcessError(
                f"Toolbox DA pipeline failed with exit code {result.returncode}"
                + (f": {detail}" if detail else "")
            )

        report_path = os.path.join(output_dir, DA_REPORT_NAME)
        if not os.path.isfile(report_path):
            shutil.rmtree(output_dir, ignore_errors=True)
            raise ProcessError(
                f"Toolbox DA pipeline completed but {DA_REPORT_NAME} was "
                f"not written under {output_dir}"
            )

        sources_path = (
            os.path.join(output_dir, DA_SOURCES_NAME)
            if emit_source_files
            else None
        )

        logger.debug("Toolbox DA pipeline wrote %s", report_path)
        return DaPipelineResult(
            report_path=report_path,
            output_dir=output_dir,
            sources_path=sources_path,
        )
