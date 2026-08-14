"""Post-analysis summary for the ``analyze`` command."""

import argparse
from typing import TYPE_CHECKING, Dict, Optional

from workbench_agent.utilities.post_scan_summary import print_scan_summary

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient


def print_analysis_summary(
    workbench: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    durations: Optional[Dict[str, float]] = None,
    *,
    kb_performed: bool,
    da_imported: bool,
) -> None:
    """
    Single end-of-run summary for ``analyze``.

    Combines first-party KB scan results and the imported Toolbox DA
    graph so the command does not emit a post-scan summary (which would
    claim DA was skipped) and a post-import summary (duplicate link).
    """
    no_wait = getattr(params, "no_wait", False)
    print_scan_summary(
        workbench,
        params,
        scan_code,
        durations,
        show_summary=(not no_wait) and getattr(params, "show_summary", False),
        scan_operations={
            "run_kb_scan": kb_performed,
            "run_dependency_analysis": True,
            "da_completed": da_imported,
        },
        title="Post-Analysis Summary",
    )
