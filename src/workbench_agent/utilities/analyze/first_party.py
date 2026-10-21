"""First-party source strategies for the ``analyze`` command."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Sequence, Set

from workbench_agent.exceptions import ValidationError
from workbench_agent.utilities.analyze.first_party_sources import (
    load_first_party_sources,
    stage_sources,
)
from workbench_agent.utilities.upload_data_prep import UploadArchivePrep

logger = logging.getLogger("workbench-agent")

# Extra directory names skipped when KB-scanning a project tree (path strategy).
PATH_BUILD_EXCLUDES: frozenset[str] = frozenset({"target", "build", "out", "dist"})


class FirstPartyStrategy(str, Enum):
    """How ``analyze`` obtains first-party sources for the KB scan."""

    SIDECAR = "sidecar"  # Toolbox first-party-sources.json
    PATH = "path"  # Whole tree under --path (Detect/Snyk-style)
    NONE = "none"  # Graph import only


@dataclass(frozen=True)
class ResolvedFirstParty:
    """Result of resolving first-party sources for a KB scan."""

    #: Directory to upload or blind-scan. ``None`` means skip KB.
    scan_root: Optional[str]
    #: If True, caller must delete ``scan_root`` when finished.
    owned: bool
    #: Exclusion names for archive creation (upload path). Empty for staged trees.
    archive_exclusions: Optional[Set[str]] = None


def parse_exclude_names(raw: Optional[object]) -> Set[str]:
    """Parse ``--exclude`` (comma-separated or repeated) into directory names."""
    if raw is None:
        return set()
    if isinstance(raw, (list, tuple)):
        parts: List[str] = []
        for item in raw:
            parts.extend(str(item).split(","))
    else:
        parts = str(raw).split(",")
    return {p.strip() for p in parts if p and str(p).strip()}


def path_exclusion_names(user_excludes: Optional[object] = None) -> Set[str]:
    """Default + build-dir + user excludes for path-strategy KB scans."""
    names = set(UploadArchivePrep.DEFAULT_EXCLUSIONS)
    names.update(PATH_BUILD_EXCLUDES)
    names.update(parse_exclude_names(user_excludes))
    return names


def resolve_first_party(
    *,
    strategy: FirstPartyStrategy,
    project_path: str,
    sources_sidecar: Optional[str],
    user_excludes: Optional[object] = None,
    blind_scan: bool = False,
) -> ResolvedFirstParty:
    """
    Resolve the directory (if any) to KB-scan for the given strategy.

    * ``sidecar`` — load Toolbox list and stage those files (owned temp dir).
    * ``path`` — upload uses ``project_path`` + archive exclusions; blind-scan
      stages a filtered tree so Toolbox hashes only included files.
    * ``none`` — no KB scan.
    """
    if strategy is FirstPartyStrategy.NONE:
        return ResolvedFirstParty(scan_root=None, owned=False)

    if strategy is FirstPartyStrategy.SIDECAR:
        if not sources_sidecar:
            return ResolvedFirstParty(scan_root=None, owned=False)
        files = load_first_party_sources(sources_sidecar)
        if not files:
            return ResolvedFirstParty(scan_root=None, owned=False)
        return ResolvedFirstParty(
            scan_root=stage_sources(project_path, files),
            owned=True,
        )

    # PATH strategy
    if not os.path.isdir(project_path):
        raise ValidationError(
            f"analyze path strategy requires a project directory: {project_path}"
        )
    exclusions = path_exclusion_names(user_excludes)
    if blind_scan:
        staged = stage_filtered_tree(project_path, exclusions)
        if staged is None:
            return ResolvedFirstParty(scan_root=None, owned=False)
        return ResolvedFirstParty(scan_root=staged, owned=True)
    return ResolvedFirstParty(
        scan_root=project_path,
        owned=False,
        archive_exclusions=exclusions,
    )


def stage_filtered_tree(
    project_path: str,
    exclude_names: Sequence[str] | Set[str],
) -> Optional[str]:
    """
    Hardlink/copy files from ``project_path`` into a temp tree, skipping
    excluded directory/file names. Returns ``None`` if nothing was staged.
    """
    exclude = set(exclude_names)
    staging_dir = tempfile.mkdtemp(prefix="workbench_agent_path_")
    linked = 0
    try:
        for root, dirnames, filenames in os.walk(project_path):
            dirnames[:] = [d for d in dirnames if d not in exclude]
            for name in filenames:
                if name in exclude:
                    continue
                src = os.path.join(root, name)
                rel = os.path.relpath(src, project_path)
                if UploadArchivePrep.should_exclude_file(rel, exclude):
                    continue
                dest = os.path.join(staging_dir, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                try:
                    os.link(src, dest)
                except OSError:
                    shutil.copy2(src, dest)
                linked += 1
    except Exception:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    if linked == 0:
        shutil.rmtree(staging_dir, ignore_errors=True)
        logger.info("Path strategy found no files to stage under %s", project_path)
        return None

    logger.info("Staged %d path-strategy file(s) under %s", linked, staging_dir)
    return staging_dir
