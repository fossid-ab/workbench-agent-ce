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
  WORKBENCH_URL    API Endpoint URL (e.g., https://workbench.example.com/api.php)
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
        help="Command to execute. Use '<COMMAND> --help' for command-specific help.",
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
            parent_parsers["result_options"],
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
        "--path", help="Local directory or file to upload and scan", required=True, metavar="PATH"
    )

    # --- 'blind-scan' Subcommand ---
    blind_scan_parser = subparsers.add_parser(
        "blind-scan",
        help="Run a blind scan using fossid-toolbox to generate hashes",
        description="Generate hashes and upload to Workbench for scanning.",
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
        epilog="""
Examples:
  # Basic blind scan
  workbench-agent blind-scan --project-name "MyProject" --scan-name "v1.0.0-blind" \\
      --path ./src

  # Blind scan with dependency analysis
  workbench-agent blind-scan --project-name "MyProject" --scan-name "v1.0.0-blind" \\
      --path ./src --run-dependency-analysis

  # Blind scan with custom fossid-toolbox path
  workbench-agent blind-scan --project-name "MyProject" --scan-name "v1.0.0-blind" \\
      --path ./src --fossid-toolbox-path /usr/local/bin/fossid-toolbox
""",
    )
    blind_scan_parser.add_argument(
        "--path",
        help="Local directory to hash for scanning",
        required=True,
        metavar="PATH",
    )

    # Toolbox-specific options for blind scan (dash-separated)
    cli_group = blind_scan_parser.add_argument_group("FossID Toolbox Options")
    cli_group.add_argument(
        "--fossid-toolbox-path",
        help=("Path to fossid-toolbox executable " "(Default: /usr/bin/fossid-toolbox)"),
        type=str,
        default="/usr/bin/fossid-toolbox",
    )

    # --- 'import-da' Subcommand ---
    import_da_parser = subparsers.add_parser(
        "import-da",
        help="Import dependency analysis results from ORT or FossID-DA",
        description="Import an analyzer-result.json file produced by ORT Analyzer or FossID-DA.",
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
  # Import analyzer-result.json from ORT
  workbench-agent import-da --project-name "MyProject" --scan-name "imported-deps" \\
      --path ./ort-output/analyzer-result.json

  # Import and display dependencies
  workbench-agent import-da --project-name "MyProject" --scan-name "imported-deps" \\
      --path ./analyzer-result.json --show-dependencies

  # Import and save results to file
  workbench-agent import-da --project-name "MyProject" --scan-name "imported-deps" \\
      --path ./analyzer-result.json --show-dependencies --result-save-path ./results.json
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
        description="Import a Software Bill of Materials (SBOM). Supports CycloneDX JSON (v1.4-1.6) and SPDX (v2.0-2.3) in JSON, RDF, or XML formats.",
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
  # Import CycloneDX SBOM
  workbench-agent import-sbom --project-name "MyProject" --scan-name "sbom-import" \\
      --path ./cyclonedx-bom.json

  # Import SPDX SBOM (RDF format)
  workbench-agent import-sbom --project-name "MyProject" --scan-name "sbom-import" \\
      --path ./spdx-document.rdf

  # Import SPDX SBOM (JSON format) and display dependencies
  workbench-agent import-sbom --project-name "MyProject" --scan-name "sbom-import" \\
      --path ./spdx-document.json --show-dependencies
""",
    )
    import_sbom_parser.add_argument(
        "--path",
        help="Path to the SBOM file to import (CycloneDX JSON or SPDX JSON/RDF/XML)",
        type=str,
        required=True,
        metavar="PATH",
    )

    # --- 'show-results' Subcommand ---
    show_results_parser = subparsers.add_parser(
        "show-results",
        help="Display results from an existing scan",
        description="Fetch and display various results from a completed scan, including licenses, components, dependencies, vulnerabilities, and scan metrics. Results can be saved to a JSON file.",
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
  workbench-agent show-results --project-name "MyProject" --scan-name "v1.0.0" \\
      --show-licenses --show-components --show-dependencies --show-vulnerabilities \\
      --show-scan-metrics

  # Show only licenses and components
  workbench-agent show-results --project-name "MyProject" --scan-name "v1.0.0" \\
      --show-licenses --show-components

  # Save results to JSON file
  workbench-agent show-results --project-name "MyProject" --scan-name "v1.0.0" \\
      --show-licenses --show-components --result-save-path ./results.json

  # Show policy warnings
  workbench-agent show-results --project-name "MyProject" --scan-name "v1.0.0" \\
      --show-policy-warnings
""",
    )

    # --- 'evaluate-gates' Subcommand ---
    evaluate_gates_parser = subparsers.add_parser(
        "evaluate-gates",
        help="Evaluate policy gates and scan status",
        description="Check scan completion status, pending identifications, policy violations, and vulnerabilities. Use --fail-on-* options to control exit codes for CI/CD pipelines. Exits with code 0 if gates pass, 1 if they fail.",
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
  workbench-agent evaluate-gates --project-name "MyProject" --scan-name "v1.0.0" \\
      --fail-on-policy

  # Fail on pending identifications
  workbench-agent evaluate-gates --project-name "MyProject" --scan-name "v1.0.0" \\
      --fail-on-pending

  # Fail on critical or high severity vulnerabilities
  workbench-agent evaluate-gates --project-name "MyProject" --scan-name "v1.0.0" \\
      --fail-on-vuln-severity high

  # Multiple gate conditions
  workbench-agent evaluate-gates --project-name "MyProject" --scan-name "v1.0.0" \\
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
        help="Generate and download reports for a scan or project",
        description="Generate and download reports for a completed scan or entire project. Supports multiple report formats including Excel, SPDX, CycloneDX, and more. Reports can be filtered by license type and identification view.",
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Download all scan-level reports
  workbench-agent download-reports --project-name "MyProject" --scan-name "v1.0.0" \\
      --report-scope scan

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
    scan_git_parser = subparsers.add_parser(
        "scan-git",
        help="Clone and scan a Git repository",
        description="Workbench clones a Git repository branch, tag, or commit to scan it.",
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

  # Scan with dependency analysis
  workbench-agent scan-git --project-name "GitProject" --scan-name "main-branch" \\
      --git-url https://github.com/owner/repo.git --git-branch main \\
      --run-dependency-analysis --show-dependencies
""",
    )

    # --- 'quick-scan' Subcommand ---
    quick_scan_parser = subparsers.add_parser(
        "quick-scan",
        help="Perform a quick scan of a single local file",
        description="Quickly scan a single local file. Useful for quick checks of individual files.",
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
