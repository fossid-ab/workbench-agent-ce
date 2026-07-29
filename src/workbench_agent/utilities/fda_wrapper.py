"""
Wrapper for FossID Dependency Analyzer (fda) pipeline invocations.

Used by the ``analyze`` command to extract a resolved dependency graph
via ``fda --pipeline`` and produce a standard ``analyzer-result.json``.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Optional

from workbench_agent.api.exceptions import ProcessError
from workbench_agent.exceptions import FileSystemError, ValidationError

logger = logging.getLogger("workbench-agent")


FDA_REPORT_NAME = "analyzer-result.json"
FDA_SOURCES_NAME = "first-party-sources.json"


@dataclass
class FdaPipelineResult:
    """Outcome of an ``fda --pipeline`` run."""

    report_path: str
    output_dir: str
    #: Sidecar listing the project's own source files, written only when
    #: ``emit_source_files`` was requested.
    sources_path: Optional[str] = None


def resolve_fda_path(configured: Optional[str]) -> str:
    """
    Return the path to the ``fda`` executable.

    If ``configured`` is set, it is used as-is. Otherwise ``fda`` is
    resolved via ``PATH``.
    """
    if configured:
        if not os.path.exists(configured):
            raise FileSystemError(f"fda not found at path: {configured}")
        if not os.access(configured, os.X_OK):
            raise FileSystemError(f"fda is not executable: {configured}")
        return configured

    resolved = shutil.which("fda")
    if not resolved:
        raise ValidationError(
            "fda not found in PATH. Install FossID Dependency Analyzer "
            "or pass --fda-path with the path to the executable."
        )
    return resolved


def build_pipeline_args(
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
    fossid_conf_path: Optional[str] = None,
) -> List[str]:
    """
    Build the argument list for ``fda --pipeline`` (excluding the binary).

    Flag names mirror fdar's pipeline CLI so the agent stays a thin
    passthrough for ecosystem-specific options.
    """
    args = [
        "--pipeline",
        "--input",
        input_path,
        "--output",
        output_dir,
    ]
    if fossid_conf_path:
        args.extend(["--fossid-conf-path", fossid_conf_path])
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


def run_pipeline(
    *,
    fda_bin: str,
    input_path: str,
    ecosystem: Optional[str] = None,
    bazel_target: Optional[str] = None,
    bazel_path: Optional[str] = None,
    bazel_mode: Optional[str] = None,
    gradle_project: Optional[str] = None,
    force_pipeline_build: bool = False,
    emit_source_files: bool = False,
    fossid_conf_path: Optional[str] = None,
    timeout: int = 3600,
) -> FdaPipelineResult:
    """
    Run ``fda --pipeline`` and return the path to ``analyzer-result.json``.

    With ``emit_source_files``, fda also writes the first-party source
    list used for the KB scan; its path comes back as
    ``FdaPipelineResult.sources_path``.

    A temporary output directory is created for the report. Callers own
    cleanup of ``FdaPipelineResult.output_dir``.
    """
    output_dir = tempfile.mkdtemp(prefix="workbench_agent_fda_")
    args = build_pipeline_args(
        input_path=input_path,
        output_dir=output_dir,
        ecosystem=ecosystem,
        bazel_target=bazel_target,
        bazel_path=bazel_path,
        bazel_mode=bazel_mode,
        gradle_project=gradle_project,
        force_pipeline_build=force_pipeline_build,
        emit_source_files=emit_source_files,
        fossid_conf_path=fossid_conf_path,
    )
    cmd = [fda_bin, *args]
    logger.info("Running fda pipeline: %s", " ".join(cmd))
    print(f"\nRunning fda pipeline...\n  {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        shutil.rmtree(output_dir, ignore_errors=True)
        raise ProcessError(f"fda pipeline timed out after {timeout} seconds") from e
    except OSError as e:
        shutil.rmtree(output_dir, ignore_errors=True)
        raise ProcessError(f"Failed to run fda at '{fda_bin}': {e}") from e

    if result.stdout:
        logger.debug("fda stdout:\n%s", result.stdout)
    if result.stderr:
        logger.debug("fda stderr:\n%s", result.stderr)

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        shutil.rmtree(output_dir, ignore_errors=True)
        raise ProcessError(
            f"fda pipeline failed with exit code {result.returncode}"
            + (f": {detail}" if detail else "")
        )

    report_path = os.path.join(output_dir, FDA_REPORT_NAME)
    if not os.path.isfile(report_path):
        shutil.rmtree(output_dir, ignore_errors=True)
        raise ProcessError(
            f"fda pipeline completed but {FDA_REPORT_NAME} was not written under {output_dir}"
        )

    sources_path = None
    if emit_source_files:
        sources_path = os.path.join(output_dir, FDA_SOURCES_NAME)
        if not os.path.isfile(sources_path):
            shutil.rmtree(output_dir, ignore_errors=True)
            raise ProcessError(
                f"fda pipeline completed but {FDA_SOURCES_NAME} was not "
                f"written under {output_dir}. This build of fda does not "
                "support --emit-source-files; upgrade FossID-DA."
            )

    print(f"fda pipeline wrote {report_path}")
    return FdaPipelineResult(
        report_path=report_path,
        output_dir=output_dir,
        sources_path=sources_path,
    )
