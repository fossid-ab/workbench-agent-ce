"""
Bazel first-party source discovery for the ``analyze`` command.

Collects workspace source files that feed a given Bazel target so they
can be KB-scanned (unmanaged / first-party code) via upload or
``--blind-scan``. Managed package coordinates come from
``fda --pipeline`` separately.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from typing import List, Optional, Set

from workbench_agent.api.exceptions import ProcessError
from workbench_agent.exceptions import ValidationError

logger = logging.getLogger("workbench-agent")

# Filenames that are build metadata, not product source.
_SKIP_BASENAMES = {
    "BUILD",
    "BUILD.bazel",
    "MODULE.bazel",
    "MODULE.bazel.lock",
    "WORKSPACE",
    "WORKSPACE.bazel",
    ".bazelrc",
    ".bazelversion",
}


def resolve_bazel_path(configured: Optional[str]) -> str:
    """Return the bazel executable path (configured or from PATH)."""
    if configured:
        if not os.path.exists(configured):
            raise ValidationError(f"bazel not found at path: {configured}")
        if not os.access(configured, os.X_OK):
            raise ValidationError(f"bazel is not executable: {configured}")
        return configured

    resolved = shutil.which("bazel") or shutil.which("bazelisk")
    if not resolved:
        raise ValidationError(
            "bazel not found in PATH. Install Bazel/Bazelisk or pass "
            "--bazel-path with the path to the executable."
        )
    return resolved


def label_to_workspace_path(label: str) -> Optional[str]:
    """
    Convert a main-repo Bazel source label to a workspace-relative path.

    ``//pkg:src/main.rs`` → ``pkg/src/main.rs``
    ``//:README.md`` → ``README.md``

    Returns ``None`` for external labels (``@…``) and non-labels.
    """
    label = label.strip()
    if not label or not label.startswith("//"):
        return None
    # Drop any trailing `` (config)`` annotation.
    label = label.split(" (", 1)[0].strip()
    body = label[2:]  # strip leading //
    if ":" not in body:
        return None
    package, name = body.split(":", 1)
    if not name or name in _SKIP_BASENAMES:
        return None
    if os.path.basename(name) in _SKIP_BASENAMES:
        return None
    if package:
        return f"{package}/{name}"
    return name


def collect_source_files(
    workspace_path: str,
    target: str,
    bazel_bin: str,
    timeout: int = 180,
) -> List[str]:
    """
    Return sorted workspace-relative source paths for ``deps(target)``.

    Uses::

        bazel query 'kind("source file", deps(<target>))' --output=label

    External ``@…`` labels are dropped — those are covered by the fda
    pipeline as managed dependencies when possible.
    """
    query = f'kind("source file", deps({target}))'
    cmd = [bazel_bin, "query", query, "--output=label"]
    logger.info("Collecting Bazel sources: %s", " ".join(cmd))
    print(f"\nCollecting first-party sources for {target}...")

    try:
        result = subprocess.run(
            cmd,
            cwd=workspace_path,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise ProcessError(
            f"bazel source query timed out after {timeout} seconds"
        ) from e
    except OSError as e:
        raise ProcessError(f"Failed to run bazel at '{bazel_bin}': {e}") from e

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise ProcessError(
            f"bazel source query failed with exit code {result.returncode}"
            + (f": {detail}" if detail else "")
        )

    paths: Set[str] = set()
    for line in result.stdout.splitlines():
        rel = label_to_workspace_path(line)
        if not rel:
            continue
        abs_path = os.path.join(workspace_path, rel)
        if os.path.isfile(abs_path):
            paths.add(rel)
        else:
            logger.debug("Skipping missing source path: %s", rel)

    ordered = sorted(paths)
    print(f"Found {len(ordered)} first-party source file(s) for {target}")
    logger.info("Bazel source files (%d): %s", len(ordered), ordered[:20])
    return ordered


def stage_sources(
    workspace_path: str,
    relative_paths: List[str],
) -> str:
    """
    Copy selected workspace files into a temporary staging directory.

    Returns the staging directory path. Caller owns cleanup.
    Hardlinks are preferred when possible; falls back to copy.
    """
    if not relative_paths:
        raise ValidationError(
            "No first-party source files were found for the Bazel target. "
            "Check that --bazel-target is correct."
        )

    staging_dir = tempfile.mkdtemp(prefix="workbench_agent_bazel_src_")
    linked = 0
    for rel in relative_paths:
        src = os.path.join(workspace_path, rel)
        dest = os.path.join(staging_dir, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            os.link(src, dest)
        except OSError:
            shutil.copy2(src, dest)
        linked += 1

    logger.info("Staged %d source file(s) under %s", linked, staging_dir)
    return staging_dir
