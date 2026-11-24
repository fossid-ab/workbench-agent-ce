import argparse
import base64
import json
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from workbench_agent.services.resolver_service import ResolverService
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.license_policy import LicensePolicy, PolicyStatus
from workbench_agent.utilities.section import print_section

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")

_LABEL_WIDTH = 11  # len("Copyright:") + 1


def _strip(value: Any) -> Optional[str]:
    if value is None:
        return None
    stripped = str(value).strip()
    return stripped or None


def _headline(result: Dict[str, Any]) -> str:
    match_type = result.get("type")
    if match_type == "file":
        return "This entire file matches an open source component."
    if match_type == "partial":
        snippet = result.get("snippet") or {}
        details: List[str] = []
        hits = snippet.get("remote_size")
        if hits is not None:
            details.append(f"{hits} snippet hits")
        coverage = snippet.get("local_coverage")
        if isinstance(coverage, (int, float)):
            details.append(f"{round(coverage * 100)}% of this file")
        suffix = f" ({', '.join(details)})" if details else ""
        return f"This file has a partial match to an open source component{suffix}."
    return "Unknown match type."


def _license_ids(component: Dict[str, Any]) -> List[str]:
    """Distinct license ids: the primary license first, then detected ones."""
    ids: List[str] = []
    candidates: List[Any] = [component.get("license")]
    licenses = component.get("licenses")
    if isinstance(licenses, list):
        candidates.extend(lic.get("id") for lic in licenses if isinstance(lic, dict))
    for candidate in candidates:
        license_id = _strip(candidate)
        if license_id and license_id not in ids:
            ids.append(license_id)
    return ids


def _copyrights(component: Dict[str, Any]) -> List[str]:
    raw = component.get("copyright")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    statements: List[str] = []
    for item in raw:
        text = _strip(item.get("default") if isinstance(item, dict) else item)
        if text and text not in statements:
            statements.append(text)
    return statements


def _field(label: str, value: str) -> str:
    return f"  {label + ':':<{_LABEL_WIDTH}} {value}"


def _policy_lines(license_ids: List[str], policy: LicensePolicy, project_label: str) -> List[str]:
    if not license_ids:
        return ["  ℹ No license detected; the project license policy could not be checked."]
    lines: List[str] = []
    for license_id in license_ids:
        rule = policy.lookup(license_id)
        if rule is None:
            lines.append(
                f"  ℹ {license_id} is not covered by the license policy of project "
                f"'{project_label}'."
            )
            continue
        reason = f" (reason: {rule.reason})" if rule.reason else ""
        if rule.status is PolicyStatus.PROHIBITED:
            lines.append(
                f"  ⚠ Policy violation: {license_id} is prohibited in project "
                f"'{project_label}'{reason}"
            )
        elif rule.status is PolicyStatus.CONDITIONAL:
            lines.append(
                f"  ⚠ Policy warning: {license_id} is conditionally approved in project "
                f"'{project_label}'{reason}"
            )
    return lines


def _format_scan_result(
    result: Dict[str, Any],
    policy: Optional[LicensePolicy] = None,
    project_label: Optional[str] = None,
) -> List[str]:
    """Format one quick-scan result as a block of lines."""
    component = result.get("component")
    if not isinstance(component, dict) or not component:
        return ["No matches found."]

    lines = [_headline(result), ""]

    name = _strip(component.get("artifact")) or _strip(component.get("name"))
    version = _strip(component.get("version"))
    if name:
        lines.append(_field("Component", f"{name} {version}" if version else name))

    author = _strip(component.get("author"))
    if author:
        lines.append(_field("Supplier", author))

    license_ids = _license_ids(component)
    if license_ids:
        license_text = license_ids[0]
        if len(license_ids) > 1:
            license_text += f" (also detected: {', '.join(license_ids[1:])})"
        lines.append(_field("License", license_text))

    for index, statement in enumerate(_copyrights(component)):
        lines.append(_field("Copyright", statement) if index == 0 else _field("", statement))

    purl = _strip(component.get("purl"))
    if purl:
        lines.append(_field("Package", purl))

    remote_file = result.get("file")
    remote_path = _strip(remote_file.get("path")) if isinstance(remote_file, dict) else None
    if remote_path:
        lines.append(_field("Matched", remote_path))

    if policy is not None:
        lines.append("")
        lines.extend(_policy_lines(license_ids, policy, project_label or ""))

    return lines


def _load_project_policy(
    client: "WorkbenchClient", params: argparse.Namespace
) -> Tuple[Optional[LicensePolicy], Optional[str]]:
    """Resolve the policy project (lookup only) and download its license policy."""
    project_name = _strip(getattr(params, "project_name", None))
    project_code = _strip(getattr(params, "project_code", None))
    if not project_name and not project_code:
        return None, None

    project_label = project_name or project_code
    print(f"Loading license policy for project '{project_label}'...")
    resolver = ResolverService(client.projects, client.scans)
    resolved_code = resolver.find_project(name=project_name, code=project_code)
    policy = LicensePolicy.from_workbench_rules(
        client.policy.download_project_policy_json(resolved_code)
    )
    print(f"✓ Loaded {len(policy)} license policy rules")
    return policy, project_label


@handler_error_wrapper
def handle_quick_scan(
    client: "WorkbenchClient",
    params: argparse.Namespace,
) -> bool:
    """
    Handler for the 'quick-scan' command.

    Performs a quick scan of a single file using the FossID quick scan API.
    This is useful for rapidly checking individual files without running a
    full project scan. When a project is given, each match's licenses are
    checked against that project's license policy (lookup only; the project
    is never created).

    Args:
        client: The Workbench API client instance
        params: Command line parameters including:
            - path: Path to the file to scan
            - limit: Maximum number of results to return (default: 1)
            - sensitivity: Scan sensitivity level (default: 10)
            - project_name / project_code: Optional policy project
            - raw: If True, output raw JSON response

    Returns:
        bool: True if the operation completed successfully. Policy findings
        are informational and never change the result.

    Note:
        The quick scan API automatically handles version differences:
        - Workbench < 24.2.0: Response field "classification"
        - Workbench >= 24.2.0: Response field "noise"
        The client normalizes this to "noise" for consistency.
    """
    print_section(f"Running {params.command.upper()} Command")

    # Load the policy first so a bad project fails before spending a scan
    policy, project_label = _load_project_policy(client, params)

    # Read and encode file content
    logger.debug(f"Reading file: {params.path}")
    with open(params.path, "rb") as f:
        file_content_b64 = base64.b64encode(f.read()).decode("utf-8")

    # Perform quick scan using explicit API
    print("Performing quick scan...")
    logger.info(
        f"Quick scanning file with limit={params.limit}, " f"sensitivity={params.sensitivity}"
    )
    results = client.quick_scan.scan_one_file(
        file_content_b64,
        limit=params.limit,
        sensitivity=params.sensitivity,
    )

    # Format and display results
    if getattr(params, "raw", False):
        print(json.dumps(results, indent=2, ensure_ascii=False))
    elif not results:
        print("No matches found.")
    else:
        total = len(results)
        for index, result in enumerate(results, start=1):
            print()
            if total > 1:
                print(f"Match {index} of {total}")
            for line in _format_scan_result(result, policy, project_label):
                print(line)

    logger.info("Quick scan completed successfully")
    return True
