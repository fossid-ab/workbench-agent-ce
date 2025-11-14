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
Environment Variables for Credentials:
  WORKBENCH_URL    : API Endpoint URL (e.g., https://workbench.example.com/api.php)
  WORKBENCH_USER   : Workbench Username  
  WORKBENCH_TOKEN  : Workbench API Token

Example Usage:
  # Full scan uploading a directory, show results
  workbench-agent scan --project-name "My Project" --scan-name "v1.0.0" --path ./src --run-dependency-analysis --show-components

  # Blind scan using fossid-toolbox
  workbench-agent blind-scan --project-name "My Project" --scan-name "v1.0.0-blind" --path ./src

  # Import dependency analysis results
  workbench-agent import-da --project-name "My Project" --scan-name "imported-deps" --path ./analyzer-result.json

  # Show results for existing scan
  workbench-agent show-results --project-name "My Project" --scan-name "v1.0.0" --show-licenses --show-components

  # Evaluate policy gates
  workbench-agent evaluate-gates --project-name "My Project" --scan-name "v1.0.0" --fail-on-policy

  # Download reports  
  workbench-agent download-reports --project-name "My Project" --report-scope project --report-type xlsx,spdx

  # Scan from Git repository
  workbench-agent scan-git --project-name "Git Project" --scan-name "main-branch" --git-url https://github.com/owner/repo.git --git-branch main
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
        dest="command", help="Available commands", required=True, metavar="COMMAND"
    )

    # --- 'scan' Subcommand ---
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a standard scan by uploading code.",
        description="Run a standard scan by uploading a local directory or file to Workbench.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["scan_operations"],
            parent_parsers["scan_control"],
            parent_parsers["project_scan_target"],
            parent_parsers["id_assist_control"],
            parent_parsers["identification_control"],
            parent_parsers["monitoring"],
            parent_parsers["result_options"],
        ],
    )
    scan_parser.add_argument(
        "--path", help="Local directory/file to upload and scan.", required=True, metavar="PATH"
    )

    # --- 'blind-scan' Subcommand ---
    blind_scan_parser = subparsers.add_parser(
        "blind-scan",
        help="Run a blind scan using fossid-toolbox to generate hashes.",
        description="Run a blind scan by generating file hashes using fossid-toolbox and uploading hash file.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["scan_operations"],
            parent_parsers["scan_control"],
            parent_parsers["id_assist_control"],
            parent_parsers["identification_control"],
            parent_parsers["monitoring"],
            parent_parsers["result_options"],
        ],
    )
    blind_scan_parser.add_argument(
        "--path",
        help="Local directory to generate hashes from before scanning.",
        required=True,
        metavar="PATH",
    )

    # Toolbox-specific options for blind scan (dash-separated)
    cli_group = blind_scan_parser.add_argument_group(
        "FossID Toolbox Options"
    )
    cli_group.add_argument(
        "--fossid-toolbox-path",
        help=(
            "Path to fossid-toolbox executable "
            "(Default: /usr/bin/fossid-toolbox)"
        ),
        type=str,
        default="/usr/bin/fossid-toolbox",
    )

    # --- 'import-da' Subcommand ---
    import_da_parser = subparsers.add_parser(
        "import-da",
        help="Import Dependency Analysis results from a file.",
        description="Import Dependency Analysis results from an analyzer-result.json file.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["monitoring"],
            parent_parsers["result_options"],
        ],
    )
    import_da_parser.add_argument(
        "--path",
        help="Path to the 'analyzer-result.json' file to be imported.",
        type=str,
        required=True,
    )

    # --- 'import-sbom' Subcommand ---
    import_sbom_parser = subparsers.add_parser(
        "import-sbom",
        help="Import SBOM (Software Bill of Materials) from a file.",
        description="Import SBOM data from CycloneDX JSON (v1.4-1.6) or SPDX (v2.0-2.3) in JSON/RDF/XML formats.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["monitoring"],
            parent_parsers["result_options"],
        ],
    )
    import_sbom_parser.add_argument(
        "--path",
        help="Path to the SBOM file to be imported (supports CycloneDX JSON and SPDX JSON/RDF/XML formats).",
        type=str,
        required=True,
    )

    # --- 'show-results' Subcommand ---
    subparsers.add_parser(
        "show-results",
        help="Fetch and display results for an existing scan.",
        description="Fetch and display results for an existing scan, optionally saving them to a file.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["monitoring"],
            parent_parsers["result_options"],
        ],
    )

    # --- 'evaluate-gates' Subcommand ---
    evaluate_gates_parser = subparsers.add_parser(
        "evaluate-gates",
        help="Check scan status and policy violations.",
        description="Checks scan completion, pending IDs, and policy violations. Sets exit code based on --fail-on options.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["monitoring"],
        ],
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
        help="Fail the gate if any files are found in the 'Pending Identification' state.",
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
        help="Generate and download reports for a scan or project.",
        description="Generate and download reports for a completed scan or project.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["monitoring"],
        ],
    )
    download_reports_parser.add_argument(
        "--project-name",
        help="Name of the Project (required if --report-scope is 'project').",
        metavar="NAME",
    )
    download_reports_parser.add_argument(
        "--scan-name",
        help="Scan Name to generate reports for (required if --report-scope is 'scan').",
        metavar="NAME",
    )
    download_reports_parser.add_argument(
        "--report-scope",
        help="Scope of the report (Default: scan). Use 'project' for project-level reports.",
        choices=["scan", "project"],
        default="scan",
        metavar="SCOPE",
    )
    download_reports_parser.add_argument(
        "--report-type",
        help="Report types to generate and download. Multiple types can be comma-separated. If not specified, all available report types for the chosen scope will be downloaded.",
        required=False,
        default="ALL",
        metavar="TYPE",
    )
    download_reports_parser.add_argument(
        "--report-save-path",
        help="Output directory for reports (Default: current dir).",
        default=".",
        metavar="PATH",
    )

    gen_opts = download_reports_parser.add_argument_group("Report Generation Options")
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
        "--disclaimer", help="Include custom text as a disclaimer in the report.", metavar="TEXT"
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
        help="Run a scan directly from a Git repository.",
        description="Clones a Branch or Tag directly from your Git SCM to the Workbench server and scans it.",
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
            parent_parsers["result_options"],
        ],
    )

    # --- 'quick-scan' Subcommand ---
    quick_scan_parser = subparsers.add_parser(
        "quick-scan",
        help="Perform a quick scan of a single local file.",
        description="Base64-encodes a single local file and sends it to Workbench quick scan endpoint.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["scan_control"],
        ],
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
