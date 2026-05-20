"""
Wrapper for FossID Toolbox invocations.

This module provides a wrapper for invoking FossID Toolbox,
used primarily for blind scanning using its hash command.
"""

import logging
import os
import subprocess
import tempfile
import traceback

from workbench_agent.api.exceptions import ProcessError
from workbench_agent.exceptions import FileSystemError
from workbench_agent.utilities.upload_data_prep import cleanup_temp_path

logger = logging.getLogger("workbench-agent")


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
            raise FileSystemError(
                f"FossID Toolbox not found at path: {toolbox_path}"
            )
        if not os.access(toolbox_path, os.X_OK):
            raise FileSystemError(
                f"FossID Toolbox not executable: {toolbox_path}"
            )

        logger.debug(
            f"ToolboxWrapper initialized with toolbox_path={toolbox_path}, "
            f"timeout={timeout}"
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
            error_msg = (
                f"Toolbox version check timed out after "
                f"{self.timeout} seconds"
            )
            logger.error(error_msg)
            raise ProcessError(error_msg) from e
        except subprocess.CalledProcessError as e:
            error_msg = (
                f"Toolbox version check failed: {e.cmd} "
                f"(exit code: {e.returncode})"
            )
            logger.error(error_msg)
            raise ProcessError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error getting Toolbox version: {e}"
            logger.error(error_msg)
            raise ProcessError(error_msg) from e

    def generate_hashes(
        self, path: str, run_dependency_analysis: bool = False
    ) -> str:
        """
        Generate hashes using FossID Toolbox.

        Uses the FossID Toolbox hash command to generate signatures
        for the given path. The output is redirected to a temporary file.

        Args:
            path: Path of the code to generate hashes for
            run_dependency_analysis: Whether to enable manifest
                generation for dependency analysis (default: False)

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
            raise FileSystemError(
                f"Failed to create temporary hash file: {e}"
            ) from e

        logger.info(f"Hashing path: {path}")
        logger.debug(
            f"Temporary file will be created at: {temporary_file_path}"
        )

        # Build fossid-toolbox hash command
        # Format: fossid-toolbox hash [OPTIONS] <PATHS>...
        cmd_args = [self.toolbox_path, "hash"]  # Hash command

        if run_dependency_analysis:
            # Enable manifest for dependency analysis
            cmd_args.append("--enable-manifest=true")
            logger.debug(
                "Manifest capture enabled for dependency analysis"
            )

        cmd_args.append(path)  # Path to scan (must be last)
        logger.debug(
            f"Executing fossid-toolbox hash command: {' '.join(cmd_args)}"
        )

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
                raise ProcessError(
                    f"Temporary file was not created: "
                    f"{temporary_file_path}"
                )

            file_size = os.path.getsize(temporary_file_path)
            if file_size == 0:
                logger.warning(
                    "Hash generation completed but generated empty file."
                )
            else:
                logger.info(
                    f"Hash generation completed successfully. "
                    f"Generated {file_size} bytes of signature data."
                )

            return temporary_file_path

        except subprocess.TimeoutExpired as e:
            error_msg = (
                f"Hash generation timed out after {self.timeout} seconds"
            )
            logger.error(error_msg)
            cleanup_temp_path(temporary_file_path)
            raise ProcessError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error during hash generation: {e}"
            logger.error(error_msg)
            logger.debug(traceback.format_exc())
            cleanup_temp_path(temporary_file_path)
            raise ProcessError(error_msg) from e
