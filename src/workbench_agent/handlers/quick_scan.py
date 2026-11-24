import argparse
import base64
import json
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from workbench_agent.api.exceptions import ProjectNotFoundError, WorkbenchApiError
from workbench_agent.exceptions import WorkbenchAgentError
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
    """The component's license as concluded by Workbench (``component.license``).

    The per-detection ``licenses[]`` list is deliberately ignored.
    """
    license_id = _strip(component.get("license"))
    return [license_id] if license_id else []


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


_CATEGORY_REASON = re.compile(r"Rule Type 'Category' and condition: '([A-Za-z_]+)'")


def _short_reason(reason: str) -> str:
    """Condense Workbench's category-rule boilerplate to the category name."""
    match = _CATEGORY_REASON.search(reason)
    if match:
        return match.group(1).replace("_", " ").lower()
    return reason


@dataclass
class _PolicyFindings:
    prohibited: List[str] = field(default_factory=list)
    conditional: List[str] = field(default_factory=list)
    uncovered: List[str] = field(default_factory=list)


def _policy_findings(license_ids: List[str], policy: LicensePolicy) -> _PolicyFindings:
    findings = _PolicyFindings()
    for license_id in license_ids:
        rule = policy.lookup(license_id)
        if rule is None:
            findings.uncovered.append(license_id)
        elif rule.status is PolicyStatus.PROHIBITED:
            findings.prohibited.append(license_id)
        elif rule.status is PolicyStatus.CONDITIONAL:
            findings.conditional.append(license_id)
    return findings


def _with_reasons(license_ids: List[str], policy: LicensePolicy) -> str:
    parts = []
    for license_id in license_ids:
        rule = policy.lookup(license_id)
        reason = _short_reason(rule.reason) if rule and rule.reason else ""
        parts.append(f"{license_id} ({reason})" if reason else license_id)
    return ", ".join(parts)


def _policy_lines(license_ids: List[str], policy: LicensePolicy) -> List[str]:
    if not license_ids:
        return ["  ℹ No license detected; the license policy could not be checked."]
    findings = _policy_findings(license_ids, policy)
    lines: List[str] = []
    if findings.prohibited:
        lines.append(f"  ⚠ Prohibited by policy: {_with_reasons(findings.prohibited, policy)}")
    if findings.conditional:
        lines.append(f"  ⚠ Conditionally approved: {_with_reasons(findings.conditional, policy)}")
    if findings.uncovered:
        lines.append(f"  ℹ Not in policy: {', '.join(findings.uncovered)}")
    return lines


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}es"


def _policy_summary(
    results: List[Dict[str, Any]], policy: LicensePolicy, project_label: str
) -> List[str]:
    """Summarize policy findings across all matches, citing match numbers."""
    prohibited_matches: List[int] = []
    conditional_matches: List[int] = []
    prohibited_ids: List[str] = []
    conditional_ids: List[str] = []
    for number, result in enumerate(results, start=1):
        component = result.get("component")
        if not isinstance(component, dict) or not component:
            continue
        findings = _policy_findings(_license_ids(component), policy)
        if findings.prohibited:
            prohibited_matches.append(number)
            prohibited_ids.extend(i for i in findings.prohibited if i not in prohibited_ids)
        if findings.conditional:
            conditional_matches.append(number)
            conditional_ids.extend(i for i in findings.conditional if i not in conditional_ids)

    total = len(results)
    prefix = f"Project '{project_label}':"
    if not prohibited_matches and not conditional_matches:
        return [
            f"{prefix} no prohibited or conditionally approved licenses "
            f"in {_plural(total, 'match')}."
        ]

    def line(label: str, numbers: List[int], ids: List[str]) -> str:
        where = ("match " if len(numbers) == 1 else "matches ") + ", ".join(map(str, numbers))
        return (
            f"  ⚠ {len(numbers)} of {total} have {label} licenses: "
            f"{', '.join(sorted(ids))} ({where})"
        )

    lines = [f"{prefix} {_plural(total, 'match')} checked"]
    if prohibited_matches:
        lines.append(line("prohibited", prohibited_matches, prohibited_ids))
    if conditional_matches:
        lines.append(line("conditionally approved", conditional_matches, conditional_ids))
    return lines


def _format_scan_result(
    result: Dict[str, Any],
    policy: Optional[LicensePolicy] = None,
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
        lines.append(_field("License", license_ids[0]))

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
        policy_lines = _policy_lines(license_ids, policy)
        if policy_lines:
            lines.append("")
            lines.extend(policy_lines)

    return lines


def _policy_project(params: argparse.Namespace) -> Tuple[Optional[str], Optional[str]]:
    return (
        _strip(getattr(params, "project_name", None)),
        _strip(getattr(params, "project_code", None)),
    )


def _resolve_policy_project(
    client: "WorkbenchClient", project_name: Optional[str], project_code: Optional[str]
) -> Tuple[Optional[str], Optional[str]]:
    """Resolve the policy project (lookup only).

    Never raises: returns ``(project_code, None)`` on success, or
    ``(None, notice)`` explaining why the policy cannot be checked.
    """
    label = project_name or project_code
    try:
        resolver = ResolverService(client.projects, client.scans)
        return resolver.find_project(name=project_name, code=project_code), None
    except ProjectNotFoundError:
        return None, f"Project '{label}': not found, so the license policy was not checked."
    except (WorkbenchApiError, WorkbenchAgentError) as exc:
        logger.debug("Project lookup failed for '%s'", label, exc_info=True)
        return None, f"Project '{label}': could not be looked up ({exc})."


def _download_policy(
    client: "WorkbenchClient", resolved_code: str, label: str
) -> Tuple[Optional[LicensePolicy], Optional[str]]:
    """Download the project's license policy.

    Never raises: returns ``(policy, None)`` on success, or ``(None, notice)``.
    """
    try:
        policy = LicensePolicy.from_workbench_rules(
            client.policy.download_project_policy_json(resolved_code)
        )
    except (WorkbenchApiError, WorkbenchAgentError) as exc:
        logger.debug("License policy download failed for '%s'", label, exc_info=True)
        return None, f"Project '{label}': could not load the license policy ({exc})."
    if not len(policy):
        return None, f"Project '{label}': no license policy defined."
    return policy, None


@handler_error_wrapper
def handle_quick_scan(
    client: "WorkbenchClient",
    params: argparse.Namespace,
) -> bool:
    """
    Handler for the 'quick-scan' command.

    Performs a quick scan of a single file using the FossID quick scan API.
    This is useful for rapidly checking individual files without running a
    full project scan. When a project is given, it is looked up (never
    created) before the scan, and each match's license is checked against
    that project's license policy, with a summary after the matches. A
    missing project, an empty policy, or a policy download error is reported
    and never fails the command.

    Args:
        client: The Workbench API client instance
        params: Command line parameters including:
            - path: Path to the file to scan
            - limit: Maximum number of results to return (default: 6)
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
    raw = getattr(params, "raw", False)

    # Resolve the policy project up front (lookup only, never fatal)
    project_name, project_code = _policy_project(params)
    project_label = project_name or project_code or ""
    wants_policy = bool(project_label) and not raw
    resolved_code: Optional[str] = None
    notice: Optional[str] = None
    if wants_policy:
        resolved_code, notice = _resolve_policy_project(client, project_name, project_code)
        if resolved_code is not None:
            print(f"Matches will be checked against project '{project_label}' license policy.")

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
    if raw:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    elif not results:
        print("No matches found.")
    else:
        policy: Optional[LicensePolicy] = None
        if resolved_code is not None:
            policy, notice = _download_policy(client, resolved_code, project_label)

        print_section("Matches")
        total = len(results)
        for index, result in enumerate(results, start=1):
            if index > 1:
                print()
            if total > 1:
                print(f"Match {index} of {total}")
            for line in _format_scan_result(result, policy):
                print(line)

        # Policy problems are reported here and never fail the command
        if wants_policy:
            print_section("Policy Evaluation")
            if policy is None:
                print(notice)
            else:
                for line in _policy_summary(results, policy, project_label):
                    print(line)

    logger.info("Quick scan completed successfully")
    return True
