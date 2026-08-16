"""
First-party source handling for the ``analyze`` command.

``fossid-toolbox da --pipeline --emit-source-files`` decides which workspace
files feed the analyzed unit (Bazel target, Maven module, …) and writes
them to a ``first-party-sources.json`` sidecar. This module reads that
list and stages the files so they can be KB-scanned (unmanaged /
first-party code) via upload or ``--blind-scan``. Managed package
coordinates come from the Toolbox DA report separately.

Discovery lives in Toolbox DA, not here: it already walks the dependency
graph, so keeping one source of truth avoids the agent and Toolbox
disagreeing about what belongs to the unit.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from typing import List

from workbench_agent.exceptions import FileSystemError, ValidationError

logger = logging.getLogger("workbench-agent")

# Sidecar schema versions this agent understands.
_SUPPORTED_SCHEMA_VERSIONS = {1}


def load_first_party_sources(sidecar_path: str) -> List[str]:
    """
    Return the workspace-relative source paths listed by Toolbox DA.

    Reads the ``first-party-sources.json`` written by
    ``fossid-toolbox da --pipeline --emit-source-files``. An empty list
    is a valid result (nothing to KB-scan); a malformed or
    unknown-version file is an error.
    """
    try:
        with open(sidecar_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except OSError as e:
        raise FileSystemError(
            f"Failed to read the Toolbox DA source list at '{sidecar_path}': {e}"
        ) from e
    except json.JSONDecodeError as e:
        raise FileSystemError(
            f"The Toolbox DA source list at '{sidecar_path}' is not valid JSON: {e}"
        ) from e

    if not isinstance(payload, dict):
        raise FileSystemError(
            f"The Toolbox DA source list at '{sidecar_path}' is not a JSON object."
        )

    schema_version = payload.get("schema_version")
    if schema_version not in _SUPPORTED_SCHEMA_VERSIONS:
        raise ValidationError(
            f"Unsupported Toolbox DA source list schema_version "
            f"{schema_version!r} in '{sidecar_path}'. Upgrade the "
            "Workbench Agent."
        )

    files = payload.get("files") or []
    if not isinstance(files, list) or not all(isinstance(f, str) for f in files):
        raise FileSystemError(
            f"The Toolbox DA source list at '{sidecar_path}' has a "
            "malformed 'files' entry; expected a list of paths."
        )

    missing = payload.get("missing") or []
    if missing:
        logger.info(
            "Toolbox DA reported %d source path(s) that were absent on disk",
            len(missing),
        )

    logger.debug("Toolbox DA listed %d first-party source file(s)", len(files))
    return files


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
            "No first-party source files were found to stage."
        )

    staging_dir = tempfile.mkdtemp(prefix="workbench_agent_src_")
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
