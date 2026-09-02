"""
Legacy CLI compatibility for workbench-agent (underscore flags, no subcommand).

Translates legacy invocations into CE subcommands and orchestrates
scan → show-results pipelines.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from workbench_agent.exceptions import ValidationError

KNOWN_COMMANDS = frozenset(
    {
        "scan",
        "blind-scan",
        "scan-git",
        "analyze",
        "show-results",
        "evaluate-gates",
        "download-reports",
        "import-da",
        "import-sbom",
        "delete-scan",
        "quick-scan",
    }
)

# Legacy flags renamed to CE kebab-case (scan/show shared unless noted).
LEGACY_FLAG_MAP: Dict[str, str] = {
    "--api_url": "--api-url",
    "--api_user": "--api-user",
    "--api_token": "--api-token",
    "--project_code": "--project-code",
    "--scan_code": "--scan-code",
    "--path": "--path",
    "--limit": "--limit",
    "--sensitivity": "--sensitivity",
    "--recursively_extract_archives": "--recursively-extract-archives",
    "--jar_file_extraction": "--jar-file-extraction",
    "--run_dependency_analysis": "--run-dependency-analysis",
    "--run_only_dependency_analysis": "--dependency-analysis-only",
    "--auto_identification_detect_declaration": "--autoid-file-licenses",
    "--auto_identification_detect_copyright": "--autoid-file-copyrights",
    "--auto_identification_resolve_pending_ids": "--autoid-pending-ids",
    "--delta_only": "--delta-scan",
    "--no_advanced_match_scoring": "--no-advanced-match-scoring",
    "--match_filtering_threshold": "--match-filtering-threshold",
    "--use_projectscan": "--use-projectscan",
    "--scan_number_of_tries": "--scan-number-of-tries",
    "--scan_wait_time": "--scan-wait-time",
    "--log": "--log",
}

# store_true-style legacy flags (scan phase only).
LEGACY_BOOLEAN_SCAN_FLAGS = frozenset(
    {
        "--recursively_extract_archives",
        "--jar_file_extraction",
        "--run_dependency_analysis",
        "--run_only_dependency_analysis",
        "--auto_identification_detect_declaration",
        "--auto_identification_detect_copyright",
        "--auto_identification_resolve_pending_ids",
        "--delta_only",
        "--no_advanced_match_scoring",
        "--use_projectscan",
    }
)

# Mutually exclusive result flags (legacy elif chain order).
LEGACY_RESULT_FLAGS: Tuple[Tuple[str, str], ...] = (
    ("--get_scan_identified_components", "--show-components"),
    ("--scans_get_policy_warnings_counter", "--show-policy-warnings"),
    ("--projects_get_policy_warnings_info", "--show-project-policy-warnings"),
    ("--scans_get_results", "--show-matches"),
)

DEFAULT_SHOW_FLAG = "--show-licenses"

# Flags handled specially — not copied verbatim to scan argv.
LEGACY_RESULT_FLAG_NAMES = frozenset(name for name, _ in LEGACY_RESULT_FLAGS)
LEGACY_DROPPED_FLAGS = frozenset({"--chunked_upload", "--blind_scan"})
LEGACY_SPECIAL_FLAGS = LEGACY_RESULT_FLAG_NAMES | LEGACY_DROPPED_FLAGS | {
    "--path-result",
    "--target_path",
    "--reuse_identifications",
    "--identification_reuse_type",
    "--specific_code",
}

LEGACY_MARKERS = frozenset(LEGACY_FLAG_MAP) | frozenset(
    {
        "--api_url",
        "--project_code",
        "--scan_code",
        "--blind_scan",
        "--path-result",
        "--chunked_upload",
        "--target_path",
        "--reuse_identifications",
        "--get_scan_identified_components",
        "--scans_get_policy_warnings_counter",
        "--projects_get_policy_warnings_info",
        "--scans_get_results",
    }
)

SHARED_ARG_FLAGS = frozenset(
    {
        "--api_url",
        "--api_user",
        "--api_token",
        "--project_code",
        "--scan_code",
        "--scan_number_of_tries",
        "--scan_wait_time",
        "--log",
    }
)


@dataclass(frozen=True)
class LegacyPipeline:
    """Translated argv for a legacy scan + show-results run."""

    scan_argv: List[str]
    show_argv: List[str]


def is_legacy_argv(argv: Sequence[str]) -> bool:
    """Return True when argv looks like legacy workbench-agent syntax."""
    tokens = _argv_body(argv)
    if not tokens:
        return False

    first = tokens[0]
    if first in KNOWN_COMMANDS:
        return False
    if first in ("-h", "--help", "--version"):
        return False

    return any(
        _flag_name(token) in LEGACY_MARKERS
        for token in tokens
        if token.startswith("-")
    )


def build_legacy_pipeline(argv: Sequence[str]) -> Optional[LegacyPipeline]:
    """
    Build scan and show-results argv lists from legacy sys.argv.

    Returns None when argv is not legacy syntax.
    """
    if not is_legacy_argv(argv):
        return None

    options = _parse_legacy_options(_argv_body(argv))
    _reject_unsupported(options)

    scan_command = "blind-scan" if options.get("--blind_scan") else "scan"
    if scan_command == "blind-scan" and options.get(
        "--run_only_dependency_analysis"
    ):
        raise ValidationError(
            "--dependency-analysis-only cannot be combined with --blind-scan "
            "(legacy: --run_only_dependency_analysis + --blind_scan)."
        )

    shared = _shared_ce_args(options)
    scan_specific = _scan_ce_args(options)
    show_flag = resolve_legacy_show_flag(options)
    show_specific = [show_flag]
    if "--path-result" in options:
        show_specific.extend(
            [
                "--result-save-path",
                normalize_result_save_path(options["--path-result"]),
            ]
        )

    scan_argv = [scan_command, *shared, *scan_specific]
    show_argv = ["show-results", *shared, *show_specific]
    return LegacyPipeline(scan_argv=scan_argv, show_argv=show_argv)


def resolve_legacy_show_flag(options: Dict[str, str]) -> str:
    """Map legacy result flags to a single CE --show-* flag."""
    for legacy_flag, ce_flag in LEGACY_RESULT_FLAGS:
        if legacy_flag in options:
            return ce_flag
    return DEFAULT_SHOW_FLAG


def normalize_result_save_path(path_result: str) -> str:
    """
    Map legacy --path-result to CE --result-save-path.

    Mirrors legacy save_results() path handling.
    """
    path_result = path_result.strip()
    if os.path.isdir(path_result):
        return os.path.join(path_result, "wb_results.json")

    if os.path.isfile(path_result):
        if path_result.endswith(".json"):
            return path_result
        directory = os.path.dirname(path_result) or "."
        base = os.path.basename(path_result)
        if "." in base:
            stem = base.rsplit(".", 1)[0]
            return os.path.join(directory, f"{stem}.json")
        return os.path.join(directory, "wb_results.json")

    if path_result.endswith(".json"):
        return path_result

    base = os.path.basename(path_result)
    if "." in base:
        directory = os.path.dirname(path_result) or "."
        stem = base.rsplit(".", 1)[0]
        return os.path.join(directory, f"{stem}.json")

    return os.path.join(path_result, "wb_results.json")


def _reject_unsupported(options: Dict[str, str]) -> None:
    if "--target_path" in options:
        raise ValidationError(
            "Legacy --target_path is not supported in Workbench Agent CE. "
            "Use scan or scan-git with --path to upload content, or keep the "
            "legacy agent for server-side target paths. "
            "See: Legacy Migration Guide."
        )


def _shared_ce_args(options: Dict[str, str]) -> List[str]:
    args: List[str] = []
    for legacy_flag in SHARED_ARG_FLAGS:
        if legacy_flag not in options:
            continue
        ce_flag = LEGACY_FLAG_MAP[legacy_flag]
        args.extend([ce_flag, options[legacy_flag]])
    return args


def _scan_ce_args(options: Dict[str, str]) -> List[str]:
    args: List[str] = []

    for legacy_flag, ce_flag in LEGACY_FLAG_MAP.items():
        if legacy_flag in LEGACY_SPECIAL_FLAGS:
            continue
        if legacy_flag in SHARED_ARG_FLAGS:
            continue
        if legacy_flag not in options:
            continue
        if legacy_flag in LEGACY_BOOLEAN_SCAN_FLAGS:
            args.append(ce_flag)
        else:
            args.extend([ce_flag, options[legacy_flag]])

    args.extend(_translate_reuse_flags(options))
    args.extend(_apply_legacy_defaults(options))
    return args


def _translate_reuse_flags(options: Dict[str, str]) -> List[str]:
    if "--reuse_identifications" not in options:
        return []

    reuse_type = options.get("--identification_reuse_type", "any")
    specific_code = options.get("--specific_code")

    if reuse_type == "any":
        return ["--reuse-any-identification"]
    if reuse_type == "only_me":
        return ["--reuse-my-identifications"]
    if reuse_type == "specific_project":
        if not specific_code:
            raise ValidationError(
                "Legacy --specific_code is required when "
                "--identification_reuse_type is specific_project."
            )
        return ["--reuse-project-ids", specific_code]
    if reuse_type == "specific_scan":
        if not specific_code:
            raise ValidationError(
                "Legacy --specific_code is required when "
                "--identification_reuse_type is specific_scan."
            )
        return ["--reuse-scan-ids", specific_code]

    raise ValidationError(
        f"Unsupported legacy --identification_reuse_type value: {reuse_type!r}"
    )


def _apply_legacy_defaults(options: Dict[str, str]) -> List[str]:
    """Inject CE flags so behavior matches legacy defaults."""
    args: List[str] = []

    if "--recursively_extract_archives" not in options:
        args.append("--no-recursively-extract-archives")

    if "--log" not in options:
        args.extend(["--log", "ERROR"])

    if "--match_filtering_threshold" not in options:
        args.extend(["--match-filtering-threshold", "-1"])

    return args


def _parse_legacy_options(tokens: Sequence[str]) -> Dict[str, str]:
    """Parse legacy CLI tokens into ``{legacy_flag: value}``."""
    options: Dict[str, str] = {}
    boolean_flags = LEGACY_BOOLEAN_SCAN_FLAGS | LEGACY_RESULT_FLAG_NAMES | {
        "--blind_scan",
        "--reuse_identifications",
        "--chunked_upload",
    }

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("--"):
            index += 1
            continue

        flag_name = _flag_name(token)
        if "=" in token:
            _, value = token.split("=", 1)
            options[flag_name] = value
            index += 1
            continue

        if flag_name in boolean_flags:
            options[flag_name] = "1"
            index += 1
            continue

        if index + 1 < len(tokens) and not tokens[index + 1].startswith("-"):
            options[flag_name] = tokens[index + 1]
            index += 2
            continue

        options[flag_name] = "1"
        index += 1

    return options


def _argv_body(argv: Sequence[str]) -> List[str]:
    return list(argv[1:] if len(argv) > 1 else [])


def _flag_name(token: str) -> str:
    if "=" in token:
        return token.split("=", 1)[0]
    return token
