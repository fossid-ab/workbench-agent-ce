# workbench_agent/cli/parser.py

import argparse
import logging
from argparse import RawTextHelpFormatter
from typing import TYPE_CHECKING

from workbench_agent import __version__

if TYPE_CHECKING:
    # Import for type checking only to avoid circular imports
    pass

logger = logging.getLogger("workbench-agent")


def parse_cmdline_args():
    """
    Parse modern command-based arguments with dash-separated options.

    Returns:
        argparse.Namespace: Parsed modern arguments

    Raises:
        ValidationError: If validation fails
    """
    # Import here to avoid circular imports
    from .parent_parsers import create_common_parent_parsers
    from .validators import validate_parsed_args

    # Create parent parsers for common argument groups
    parent_parsers = create_common_parent_parsers()

    parser = argparse.ArgumentParser(
        description="Workbench Agent - API-powered Scans, Gates, and Reports",
        formatter_class=RawTextHelpFormatter,
        epilog="""
Environment Variables:
  WORKBENCH_URL    API URL (e.g., https://workbench.example/api.php)
  WORKBENCH_USER   Workbench Username
  WORKBENCH_TOKEN  Workbench API Token

For more information on a specific command, use:
  workbench-agent <COMMAND> --help
""",
    )

    # Add version argument
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"FossID Workbench Agent {__version__}",
    )

    # Subparsers
    subparsers = parser.add_subparsers(
        dest="command",
        help="Command to execute. Use '<COMMAND> --help' for command help.",
        required=True,
        metavar="COMMAND",
    )

    # --- 'scan' Subcommand ---
    scan_parser = subparsers.add_parser(
        "scan",
        help="Upload and scan local code files or directories",
        description="Scan a local directory or file with Workbench.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["archive_operations"],
            parent_parsers["scan_operations"],
            parent_parsers["scan_control"],
            parent_parsers["project_scan_target"],
            parent_parsers["id_assist_control"],
            parent_parsers["identification_control"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Basic scan with dependency analysis
  workbench-agent scan --project-name "MyProject" --scan-name "v1.0.0" \\
      --path ./src --run-dependency-analysis

  # Dependency analysis only (skip KB scan)
  workbench-agent scan --project-name "MyProject" --scan-name "v1.0.0" \\
      --path ./src --dependency-analysis-only

  # Start scan and exit without waiting
  workbench-agent scan --project-name "MyProject" --scan-name "v1.0.0" \\
      --path ./src --no-wait
""",
    )
    scan_parser.add_argument(
        "--path",
        help="Local directory or file to upload and scan",
        required=True,
        metavar="PATH",
    )
    scan_parser.add_argument(
        "--incremental-upload",
        help="Upload files without clearing existing scan content."
        "By default, existing content is cleared before uploading.",
        action="store_true",
        default=False,
    )

    # --- 'blind-scan' Subcommand ---
    blind_scan_parser = subparsers.add_parser(
        "blind-scan",
        help="Run a blind scan with FossID Toolbox or a .fossid file",
        description="Scan by hashing a directory and uploading to Workbench.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["fossid_toolbox"],
            parent_parsers["scan_operations"],
            parent_parsers["scan_control"],
            parent_parsers["id_assist_control"],
            parent_parsers["identification_control"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Basic blind scan
  workbench-agent blind-scan --project-name "MyProject" --scan-name "v1.0.0" \\
      --path ./src

  # Blind scan with dependency analysis
  workbench-agent blind-scan --project-name "MyProject" --scan-name "v1.0.0" \\
      --path ./src --run-dependency-analysis

  # Blind scan with custom fossid-toolbox path and timeout
  workbench-agent blind-scan --project-name "MyProject" --scan-name "v1.0.0" \\
      --path ./src --fossid-toolbox-path /usr/local/bin/fossid-toolbox \\
      --fossid-toolbox-timeout 600

  # Blind scan with a pre-generated .fossid file (skips hashing)
  workbench-agent blind-scan --project-name "MyProject" --scan-name "v1.0.0" \\
      --path ./signatures.fossid
""",
    )
    blind_scan_parser.add_argument(
        "--path",
        help="Local directory to hash, or a pre-generated .fossid file",
        required=True,
        metavar="PATH",
    )

    # --- 'import-da' Subcommand ---
    import_da_parser = subparsers.add_parser(
        "import-da",
        help="Import dependency analysis results from ORT or FossID-DA",
        description="Import a analyzer-result.json from ORT or FossID-DA.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Import analyzer-result.json from ORT
  workbench-agent import-da --project-name "MyProject" --scan-name "v1.0.0" \\
      --path ./ort-output/analyzer-result.json
""",
    )
    import_da_parser.add_argument(
        "--path",
        help="Path to the analyzer-result.json file to import",
        type=str,
        required=True,
        metavar="PATH",
    )

    # --- 'import-sbom' Subcommand ---
    import_sbom_parser = subparsers.add_parser(
        "import-sbom",
        help="Import an SBOM into Workbench.",
        description="Import a CycloneDX 1.4-1.6 or SPDX 2.0-2.3 SBOM.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Import CycloneDX SBOM
  workbench-agent import-sbom --project-name "MyProject" --scan-name "v1.0" \\
      --path ./cyclonedx-bom.json

  # Import SPDX SBOM (JSON; uploaded directly on Workbench 2025.2.0+)
  workbench-agent import-sbom --project-name "MyProject" --scan-name "v1.0" \\
      --path ./spdx-document.json

  # Import SPDX SBOM (RDF format)
  workbench-agent import-sbom --project-name "MyProject" --scan-name "v1.0" \\
      --path ./spdx-document.rdf

On Workbench versions before 2025.2.0, SPDX JSON is automatically converted
to RDF before upload. RDF and XML SPDX files are always uploaded as-is.
""",
    )
    import_sbom_parser.add_argument(
        "--path",
        help=(
            "Path to SBOM to import (CycloneDX JSON or SPDX JSON/RDF/XML; "
            "SPDX JSON is sent directly on Workbench 2025.2.0+)"
        ),
        type=str,
        required=True,
        metavar="PATH",
    )

    # --- 'show-results' Subcommand ---
    subparsers.add_parser(
        "show-results",
        help="Display results from an existing scan",
        description="Fetch scan results for display or saving to JSON.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["monitoring"],
            parent_parsers["result_options"],
        ],
        epilog="""
Examples:
  # Show all available results
  workbench-agent show-results --project-name "MyProject" --scan-name "v1.0" \\
      --show-licenses --show-components --show-dependencies \\
      --show-scan-metrics --show-vulnerabilities --show-policy-warnings

  # Save results to JSON file
  workbench-agent show-results --project-name "MyProject" --scan-name "v1.0" \\
      --show-licenses --show-components --result-save-path ./results.json

""",
    )

    # --- 'delete-scan' Subcommand ---
    delete_scan_parser = subparsers.add_parser(
        "delete-scan",
        help="Permanently delete a scan from Workbench",
        description=(
            "Queue deletion of an existing scan (async job) and wait "
            "until it finishes. Requires permission to delete scans (global "
            "delete permission or scan owner). This is irreversible. "
            "Status polling uses a fixed 2 second interval."
        ),
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Delete a scan (default: keep identifications metadata behavior per API)
  workbench-agent delete-scan --project-name "MyProject" --scan-name "v1.0"

  # Delete scan and request identifications removal per API
  workbench-agent delete-scan --project-name "MyProject" --scan-name "v1.0" \\
      --delete-identifications
""",
    )
    delete_scan_parser.add_argument(
        "--delete-identifications",
        help=(
            "When set, deletes identifications from this scan."
        ),
        action="store_true",
        default=False,
    )

    # --- 'evaluate-gates' Subcommand ---
    evaluate_gates_parser = subparsers.add_parser(
        "evaluate-gates",
        help="Check a scan for pending IDs, policy warnings, or CVEs.",
        description="Default shows pass/fail; adding --fail-on-* fails hard.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Fail on policy violations
  workbench-agent evaluate-gates --project-name "MyProj" --scan-name "v1.0" \\
      --fail-on-policy

  # Fail on pending identifications
  workbench-agent evaluate-gates --project-name "MyProj" --scan-name "v1.0" \\
      --fail-on-pending

  # Fail on critical or high severity vulnerabilities
  workbench-agent evaluate-gates --project-name "MyProj" --scan-name "v1.0" \\
      --fail-on-vuln-severity high

  # Multiple gate conditions
  workbench-agent evaluate-gates --project-name "MyProj" --scan-name "v1.0" \\
      --fail-on-policy --fail-on-pending --fail-on-vuln-severity critical
""",
    )
    evaluate_gates_parser.add_argument(
        "--fail-on-vuln-severity",
        help="Fail if vulnerabilities of this severity OR HIGHER are found.",
        choices=["critical", "high", "medium", "low"],
        default=None,
        metavar="SEVERITY",
    )
    evaluate_gates_parser.add_argument(
        "--fail-on-pending",
        help="Fail the gate if any files are found in the 'Pending ID' state.",
        action="store_true",
    )
    evaluate_gates_parser.add_argument(
        "--fail-on-policy",
        help="Fail the gate if any policy violations are found.",
        action="store_true",
    )

    # --- 'download-reports' Subcommand ---
    download_reports_parser = subparsers.add_parser(
        "download-reports",
        help="Download reports for a scan or project",
        description="Download reports with provided parameters.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Download all scan-level reports
  workbench-agent download-reports --project-name "MyProject" \\
      --scan-name "v1.0.0" --report-scope scan

  # Download specific report types (scan-level)
  workbench-agent download-reports --project-name "MyProject" --scan-name "v1.0.0" \\
      --report-scope scan --report-type xlsx,spdx --report-save-path ./reports/

  # Download project-level reports
  workbench-agent download-reports --project-name "MyProject" \\
      --report-scope project --report-type xlsx,cyclonedx

  # Download reports with license filtering
  workbench-agent download-reports --project-name "MyProject" --scan-name "v1.0.0" \\
      --report-scope scan --report-type xlsx \\
      --selection-type include_foss --selection-view all
""",
    )
    download_reports_parser.add_argument(
        "--project-name",
        help=(
            "The Project to download reports from."
        ),
        metavar="NAME",
    )
    download_reports_parser.add_argument(
        "--scan-name",
        help=(
            "The Scan to download reports from. Required for scan reports."
        ),
        metavar="NAME",
    )
    download_reports_parser.add_argument(
        "--report-scope",
        help="Scope (Default: scan). Use 'project' for project reports.",
        choices=["scan", "project"],
        default="scan",
        metavar="SCOPE",
    )
    download_reports_parser.add_argument(
        "--report-type",
        help="Comma-separated list of reports to download. If blank, all reports are downloaded.",
        required=False,
        default="ALL",
        metavar="TYPE",
    )
    download_reports_parser.add_argument(
        "--report-save-path",
        help="Save directory for reports (Default: current dir).",
        default=".",
        metavar="PATH",
    )

    gen_opts = download_reports_parser.add_argument_group(
        "Report Generation Options"
    )
    gen_opts.add_argument(
        "--selection-type",
        help="Filter licenses included in the report.",
        choices=[
            "include_foss",
            "include_marked_licenses",
            "include_copyleft",
            "include_all_licenses",
        ],
        metavar="TYPE",
    )
    gen_opts.add_argument(
        "--selection-view",
        help="Filter report content by identification view.",
        choices=["pending_identification", "marked_as_identified", "all"],
        metavar="VIEW",
    )
    gen_opts.add_argument(
        "--disclaimer",
        help="Include custom text as a disclaimer in the report.",
        metavar="TEXT",
    )
    gen_opts.add_argument(
        "--include-vex",
        help="Include VEX data in CycloneDX/Excel reports (Default: True).",
        action=argparse.BooleanOptionalAction,
        default=True,
    )

    # --- 'scan-git' Subcommand ---
    subparsers.add_parser(
        "scan-git",
        help="Clone and scan a Git repository",
        description="Scan a Git repository branch, tag, or commit.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["git_options"],
            parent_parsers["scan_operations"],
            parent_parsers["scan_control"],
            parent_parsers["id_assist_control"],
            parent_parsers["identification_control"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Scan a branch
  workbench-agent scan-git --project-name "GitProject" --scan-name "main-branch" \\
      --git-url https://github.com/owner/repo.git --git-branch main

  # Scan a tag
  workbench-agent scan-git --project-name "GitProject" --scan-name "v1.0.0" \\
      --git-url https://github.com/owner/repo.git --git-tag "v1.0.0"

  # Scan a specific commit
  workbench-agent scan-git --project-name "GitProject" --scan-name "commit-abc123" \\
      --git-url https://github.com/owner/repo.git \\
      --git-commit ffac537e6cbbf934b08745a378932722df287a53

  # Scan with dependency analysis and summary
  workbench-agent scan-git --project-name "GitProject" --scan-name "main-branch" \\
      --git-url https://github.com/owner/repo.git --git-branch main \\
      --run-dependency-analysis --show-summary
""",
    )

    # --- 'quick-scan' Subcommand ---
    quick_scan_parser = subparsers.add_parser(
        "quick-scan",
        help="Perform a quick scan of a single local file",
        description="Quickly scan a single file. Useful to check one file.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["scan_control"],
        ],
        epilog="""
Examples:
  # Quick scan a file (positional argument)
  workbench-agent quick-scan ./src/main.py

  # Quick scan a file (using --path)
  workbench-agent quick-scan --path ./src/main.py

  # Quick scan with raw JSON output
  workbench-agent quick-scan --path ./src/main.py --raw
""",
    )
    # Accept either positional FILE or --path
    quick_scan_parser.add_argument(
        "file",
        help="Path to the local file to quick-scan.",
        nargs="?",
        metavar="FILE",
    )
    quick_scan_parser.add_argument(
        "--path",
        help="Path to the local file to quick-scan.",
        required=False,
        metavar="PATH",
    )
    quick_scan_parser.add_argument(
        "--raw",
        help="Display the JSON returned by the Quick Scan API",
        action="store_true",
        default=False,
    )

    args = parser.parse_args()

    # Validate the parsed arguments
    validate_parsed_args(args)

    return args
