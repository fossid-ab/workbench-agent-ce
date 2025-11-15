"""
Wrapper for FossID Toolbox invocations.

This module provides a wrapper for invoking FossID Toolbox,
used primarily for blind scanning using its hash command.
"""

import logging
import os
import random
import subprocess
import traceback

from workbench_agent.exceptions import FileSystemError, ProcessError

logger = logging.getLogger("workbench-agent")


class ToolboxWrapper:
    """
    A class to interact with FossID Toolbox.

    Attributes:
        toolbox_path (str): Path to the FossID Toolbox executable
        timeout (str): Timeout for Toolbox expressed in seconds
    """

    def __init__(self, toolbox_path: str, timeout: str = "120"):
        """
        Initialize ToolboxWrapper.

        Args:
            toolbox_path: Path to the fossid-toolbox executable
            timeout: Timeout in seconds (default: "120")

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
        except subprocess.CalledProcessError as e:
            error_msg = f"Toolbox version check failed: {e.cmd} " f"(exit code: {e.returncode})"
            logger.error(error_msg)
            raise ProcessError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error getting Toolbox version: {e}"
            logger.error(error_msg)
            raise ProcessError(error_msg) from e

    def generate_hashes(self, path: str, run_dependency_analysis: bool = False) -> str:
        """
        Generate cryptographic file hashes and signatures using FossID Toolbox.

        Uses the FossID Toolbox hash command to generate cryptographic
        hashes and signatures for files in the given path. The output
        is redirected to a temporary file which is then uploaded to
        Workbench for blind scanning.

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

        temporary_file_path = f"/tmp/blind_scan_result_{self.randstring(8)}.fossid"
        logger.info(f"Starting hash generation for path: {path}")
        logger.debug(f"Temporary file will be created at: {temporary_file_path}")

        # Create temporary file, make it empty if already exists
        try:
            with open(temporary_file_path, "w"):
                pass  # Create empty file
        except Exception as e:
            raise FileSystemError(
                f"Failed to create temporary file " f"{temporary_file_path}: {e}"
            ) from e

        # Build fossid-toolbox hash command
        # Format: fossid-toolbox hash [OPTIONS] <PATHS>...
        cmd_args = [self.toolbox_path, "hash"]  # Hash subcommand

        if run_dependency_analysis:
            # Enable manifest for dependency analysis
            cmd_args.append("--enable-manifest=true")
            logger.debug("Manifest capture enabled for dependency analysis")

        cmd_args.append(path)  # Path to scan (must be last)
        logger.debug(f"Executing fossid-toolbox hash command: {' '.join(cmd_args)}")

        try:
            # Execute command and redirect output to temporary file
            with open(temporary_file_path, "w") as outfile:
                result = subprocess.run(
                    cmd_args,
                    stdout=outfile,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=int(self.timeout),
                    check=False,  # We handle return code manually
                )

            if result.returncode != 0:
                error_msg = (
                    f"Toolbox hash generation failed with exit code "
                    f"{result.returncode}: {result.stderr}"
                )
                logger.error(error_msg)
                # Clean up temporary file
                if os.path.exists(temporary_file_path):
                    os.remove(temporary_file_path)
                raise ProcessError(error_msg)

            # Verify temporary file was created and has content
            if not os.path.exists(temporary_file_path):
                raise ProcessError(f"Temporary file was not created: " f"{temporary_file_path}")

            file_size = os.path.getsize(temporary_file_path)
            if file_size == 0:
                logger.warning("Hash generation completed but generated empty " "results file")
            else:
                logger.info(
                    f"Hash generation completed successfully. "
                    f"Generated {file_size} bytes of signature data."
                )

            return temporary_file_path

        except subprocess.TimeoutExpired as e:
            error_msg = f"Hash generation timed out after {self.timeout} seconds"
            logger.error(error_msg)
            # Clean up temporary file
            if os.path.exists(temporary_file_path):
                os.remove(temporary_file_path)
            raise ProcessError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error during hash generation: {e}"
            logger.error(error_msg)
            logger.debug(traceback.format_exc())
            # Clean up temporary file
            if os.path.exists(temporary_file_path):
                os.remove(temporary_file_path)
            raise ProcessError(error_msg) from e

    @staticmethod
    def randstring(length: int = 10) -> str:
        """
        Generate a random string of a given length.

        Parameters:
            length: Length of the generated string (default: 10)

        Returns:
            str: Random string of specified length
        """
        valid_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return "".join((random.choice(valid_letters) for i in range(length)))

    def cleanup_temp_file(self, file_path: str) -> bool:
        """
        Clean up a temporary file created by blind scan.

        Args:
            file_path: Path to the temporary file to delete

        Returns:
            bool: True if file was successfully deleted, False otherwise
        """
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.debug(f"Cleaned up temporary file: {file_path}")
                return True
            else:
                logger.warning(f"Temporary file does not exist: {file_path}")
                return False
        except Exception as e:
            logger.error(f"Failed to clean up temporary file {file_path}: {e}")
            return False
