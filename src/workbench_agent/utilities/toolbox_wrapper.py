"""
Wrapper for FossID Toolbox invocations.

This module provides a wrapper for invoking FossID Toolbox,
used primarily for blind scanning using its hash command.
"""

import logging
import os
import re
import subprocess
import tempfile
import traceback

from packaging import version as packaging_version

from workbench_agent.api.exceptions import ProcessError
from workbench_agent.exceptions import FileSystemError
from workbench_agent.utilities.upload_data_prep import cleanup_temp_path

logger = logging.getLogger("workbench-agent")

# Minimum FossID Toolbox version supported by this Workbench Agent CE release.
# This defines the agent-to-Toolbox compatibility matrix for blind-scan.
MINIMUM_TOOLBOX_VERSION = "1.7.5"


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
            logger.info(f"FossID Toolbox version: {version}")
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
        self, version_string: str, minimum: str = MINIMUM_TOOLBOX_VERSION
    ) -> None:
        """
        Validate that the Toolbox version is supported by this agent.

        Parses the version number out of the raw ``--version`` output
        (for example "FossID Toolbox version 1.7.5") and compares it
        against the minimum supported version using semantic version
        ordering. This enforces the Workbench Agent CE to FossID Toolbox
        compatibility matrix for blind-scan.

        Args:
            version_string: Raw version output from get_version()
            minimum: Minimum supported version (defaults to
                MINIMUM_TOOLBOX_VERSION)

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
                f"CE {__version__} requires FossID Toolbox {minimum} or later "
                f"for blind-scan. Please download a newer version of FossID "
                f"Toolbox."
            )
            logger.error(error_msg)
            raise ProcessError(error_msg)

        logger.debug(
            f"Toolbox version {detected} satisfies minimum supported " f"version {minimum}"
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
