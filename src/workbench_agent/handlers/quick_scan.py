import argparse
import base64
import json
import logging
from typing import TYPE_CHECKING

from workbench_agent.utilities.error_handling import handler_error_wrapper

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def _format_scan_result(result: dict) -> str:
    component = result.get("component")
    match_type = result.get("type")
    if component:
        artifact = component.get("artifact")
        author = component.get("author")
        if match_type == "file":
            msg = f"This entire file matched to {artifact} by {author}."

            return msg
        if match_type == "partial":
            remote_size = result.get("snippet", {}).get("remote_size")
            msg = (
                f"This file has {remote_size} hits to {artifact} by {author}."
            )

            return msg
        return "Unknown match type."
    return "No matches found."


@handler_error_wrapper
def handle_quick_scan(
    client: "WorkbenchClient",
    params: argparse.Namespace,
) -> bool:
    """
    Handler for the 'quick-scan' command.

    Performs a quick scan of a single file using the FossID quick scan API.
    This is useful for rapidly checking individual files without running a
    full project scan.

    Args:
        client: The Workbench API client instance
        params: Command line parameters including:
            - path: Path to the file to scan
            - limit: Maximum number of results to return (default: 1)
            - sensitivity: Scan sensitivity level (default: 10)
            - raw: If True, output raw JSON response

    Returns:
        bool: True if the operation completed successfully

    Note:
        The quick scan API automatically handles version differences:
        - Workbench < 24.2.0: Response field "classification"
        - Workbench >= 24.2.0: Response field "noise"
        The client normalizes this to "noise" for consistency.
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # Read and encode file content
    logger.debug(f"Reading file: {params.path}")
    with open(params.path, "rb") as f:
        file_content_b64 = base64.b64encode(f.read()).decode("utf-8")

    # Perform quick scan using explicit API
    print("\nPerforming quick scan...")
    logger.info(
        f"Quick scanning file with limit={params.limit}, "
        f"sensitivity={params.sensitivity}"
    )
    results = client.quick_scan.scan_one_file(
        file_content_b64=file_content_b64,
        limit=params.limit,
        sensitivity=params.sensitivity,
    )

    # Format and display results
    if getattr(params, "raw", False):
        # Raw JSON output
        print(json.dumps(results, indent=2))
    else:
        # Human-readable output
        if not results:
            print("No matches found.")
        else:
            for result in results:
                message = _format_scan_result(result)
                print(message)

    logger.info("Quick scan completed successfully")
    return True
