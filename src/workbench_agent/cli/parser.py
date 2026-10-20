# workbench_agent/cli/parser.py

import argparse
from argparse import RawTextHelpFormatter

from workbench_agent import __version__


def parse_cmdline_args(argv=None):
    """
    Parse modern command-based arguments with dash-separated options.

    Args:
        argv: Optional argument list (excluding program name). Defaults to sys.argv.

    Returns:
        argparse.Namespace: Parsed modern arguments

    Raises:
        ValidationError: If validation fails
    """
    # Import here to avoid circular imports
    from workbench_agent.utilities.analyze.ecosystem import (
        register_ecosystem_cli_arguments,
        supported_ecosystems,
    )

    from .parent_parsers import create_common_parent_parsers, create_projectscan_parser
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
            parent_parsers["projectscan"],
            parent_parsers["scan_control"],
            parent_parsers["project_scan_target"],
            parent_parsers["id_assist_control"],
            parent_parsers["identification_control"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Basic scan with dependency analysis
  workbench-agent scan --project "MyProject" --scan "v1.0.0" \\
      --path ./src --run-dependency-analysis

  # Dependency analysis only (skip KB scan)
  workbench-agent scan --project "MyProject" --scan "v1.0.0" \\
      --path ./src --dependency-analysis-only

  # Start scan and exit without waiting
  workbench-agent scan --project "MyProject" --scan "v1.0.0" \\
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
            parent_parsers["projectscan"],
            parent_parsers["scan_control"],
            parent_parsers["id_assist_control"],
            parent_parsers["identification_control"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Basic blind scan
  workbench-agent blind-scan --project "MyProject" --scan "v1.0.0" \\
      --path ./src

  # Blind scan with dependency analysis
  workbench-agent blind-scan --project "MyProject" --scan "v1.0.0" \\
      --path ./src --run-dependency-analysis

  # Blind scan with custom fossid-toolbox path and timeout
  workbench-agent blind-scan --project "MyProject" --scan "v1.0.0" \\
      --path ./src --fossid-toolbox-path /usr/local/bin/fossid-toolbox \\
      --fossid-toolbox-timeout 600

  # Blind scan with a pre-generated .fossid file (skips hashing)
  workbench-agent blind-scan --project "MyProject" --scan "v1.0.0" \\
      --path ./signatures.fossid
""",
    )
    blind_scan_parser.add_argument(
        "--path",
        help="Local directory to hash, or a pre-generated .fossid file",
        required=True,
        metavar="PATH",
    )

    # --- 'analyze' Subcommand ---
    analyze_parser = subparsers.add_parser(
        "analyze",
        help=(
            "Run FossID Toolbox DA pipeline and import results into "
            "Workbench (with first-party KB scan)"
        ),
        description=(
            "Analyze a build-tool project with FossID Toolbox DA pipeline "
            "mode (fossid-toolbox da) and import the dependency graph into "
            "a Workbench scan.\n\n"
            "Requires FossID Toolbox 1.7.11 or later.\n\n"
            "Managed packages come from the Toolbox graph. First-party "
            "sources are KB-scanned into the same Project/Scan:\n"
            "  - Bazel: Toolbox lists sources for --bazel-target "
            "(--emit-source-files)\n"
            "  - Maven: the tree under --path is KB-scanned "
            "(use --path to scope monorepos; --exclude for noise)\n\n"
            "By default those sources are uploaded (regular scan). Pass "
            "--blind-scan to hash with FossID Toolbox instead.\n\n"
            "Supported ecosystems: "
            + ", ".join(supported_ecosystems())
            + "."
        ),
        formatter_class=RawTextHelpFormatter,
        parents=[
            parent_parsers["cli_behaviors"],
            parent_parsers["workbench_connection"],
            parent_parsers["project_scan_target"],
            parent_parsers["archive_operations"],
            parent_parsers["fossid_toolbox"],
            parent_parsers["scan_control"],
            create_projectscan_parser(default_use_projectscan=True),
            parent_parsers["id_assist_control"],
            parent_parsers["identification_control"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Bazel — target-scoped sources + dependency graph
  workbench-agent analyze \\
      -e bazel --bazel-target //myapp:app \\
      --project "MyApp" --scan "myapp@1.0.0"

  # Maven — project tree under --path + dependency graph
  # (uses ./mvnw when present; point --path at a module in monorepos)
  workbench-agent analyze \\
      -e maven --path ./services/payments \\
      --project "Payments" --scan "payments@1.0.0"

  # Maven from repo root with extra KB excludes
  workbench-agent analyze \\
      -e maven --exclude node_modules,.git \\
      --project "MyApp" --scan "main@HEAD"

  # Blind-scan first-party sources (hashes only)
  workbench-agent analyze \\
      -e bazel --bazel-target //myapp:app \\
      --project "MyApp" --scan "myapp@1.0.0" \\
      --blind-scan

  # Dependency graph only (no first-party KB scan)
  workbench-agent analyze \\
      -e maven --dependency-analysis-only \\
      --project "MyApp" --scan "myapp@1.0.0"
""",
    )
    analyze_parser.add_argument(
        "--path",
        dest="path",
        help="Project / workspace directory to analyze (Default: current working directory)",
        required=False,
        default=".",
        metavar="PATH",
    )
    analyze_parser.add_argument(
        "-e",
        "--ecosystem",
        dest="ecosystem",
        help=(
            "Build-tool ecosystem for Toolbox DA pipeline mode "
            f"({', '.join(supported_ecosystems())})"
        ),
        required=True,
        choices=list(supported_ecosystems()),
        metavar="ECOSYSTEM",
    )
    analyze_parser.add_argument(
        "--exclude",
        dest="exclude",
        help=(
            "Comma-separated directory/file names to exclude from the "
            "first-party KB scan when using path strategy (e.g. Maven). "
            "Merged with defaults (.git, node_modules, target, …)"
        ),
        required=False,
        metavar="NAMES",
    )
    analyze_parser.add_argument(
        "-c",
        "--fossid-conf-path",
        dest="fossid_conf_path",
        help=(
            "Path to fossid.conf passed through to fossid-toolbox da "
            "(writable da_logs_path, KB host, …)"
        ),
        required=False,
        metavar="PATH",
    )
    register_ecosystem_cli_arguments(analyze_parser)
    analyze_parser.add_argument(
        "--da-timeout",
        dest="da_timeout",
        help=(
            "Maximum seconds to wait for fossid-toolbox da --pipeline "
            "(Default: 3600)"
        ),
        type=int,
        default=3600,
        metavar="SECONDS",
    )
    analyze_parser.add_argument(
        "--blind-scan",
        dest="blind_scan",
        help=(
            "Hash first-party sources with FossID Toolbox instead of "
            "uploading source content (default: upload)."
        ),
        action="store_true",
        default=False,
    )
    analyze_parser.add_argument(
        "--dependency-analysis-only",
        dest="dependency_analysis_only",
        help=(
            "Skip first-party source discovery and the KB scan. "
            "Runs Toolbox DA pipeline without --emit-source-files "
            "and imports the dependency graph only."
        ),
        action="store_true",
        default=False,
    )
    analyze_parser.add_argument(
        "--run-dependency-analysis",
        dest="run_dependency_analysis",
        help=(
            "Accepted for compatibility with scan commands and ignored. "
            "analyze always imports the Toolbox DA graph."
        ),
        action="store_true",
        default=False,
    )
    analyze_parser.add_argument(
        "--no-wait",
        help="Exit after starting scans/imports instead of waiting.",
        action="store_true",
        default=False,
    )
    # Defaults expected by execute_scan_workflow / start_scan / upload path.
    analyze_parser.set_defaults(
        run_dependency_analysis=False,
        dependency_analysis_only=False,
        delta_scan=False,
        scan_failed_only=False,
        full_file_only=False,
        replace_existing_identifications=False,
        incremental_upload=False,
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
  workbench-agent import-da --project "MyProject" --scan "v1.0.0" \\
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
  workbench-agent import-sbom --project "MyProject" --scan "v1.0" \\
      --path ./cyclonedx-bom.json

  # Import SPDX SBOM (JSON; uploaded directly on Workbench 2025.2.0+)
  workbench-agent import-sbom --project "MyProject" --scan "v1.0" \\
      --path ./spdx-document.json

  # Import SPDX SBOM (RDF format)
  workbench-agent import-sbom --project "MyProject" --scan "v1.0" \\
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
  workbench-agent show-results --project "MyProject" --scan "v1.0" \\
      --show-licenses --show-components --show-dependencies \\
      --show-scan-metrics --show-vulnerabilities --show-policy-warnings

  # Save results to JSON file
  workbench-agent show-results --project "MyProject" --scan "v1.0" \\
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
  workbench-agent delete-scan --project "MyProject" --scan "v1.0"

  # Delete scan and request identifications removal per API
  workbench-agent delete-scan --project "MyProject" --scan "v1.0" \\
      --delete-identifications
""",
    )
    delete_scan_parser.add_argument(
        "--delete-identifications",
        help=("When set, deletes identifications from this scan."),
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
  workbench-agent evaluate-gates --project "MyProj" --scan "v1.0" \\
      --fail-on-policy

  # Fail on pending identifications
  workbench-agent evaluate-gates --project "MyProj" --scan "v1.0" \\
      --fail-on-pending

  # Fail on critical or high severity vulnerabilities
  workbench-agent evaluate-gates --project "MyProj" --scan "v1.0" \\
      --fail-on-vuln-severity high

  # Multiple gate conditions
  workbench-agent evaluate-gates --project "MyProj" --scan "v1.0" \\
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
  workbench-agent download-reports --project "MyProject" \\
      --scan "v1.0.0" --report-scope scan

  # Target by internal codes (lookup-only)
  workbench-agent download-reports --project-code PROJ123 \\
      --scan-code BUILD_42 --report-scope scan

  # Download specific report types (scan-level)
  workbench-agent download-reports --project "MyProject" --scan "v1.0.0" \\
      --report-scope scan --report-type xlsx,spdx --report-save-path ./reports/

  # Download project-level reports
  workbench-agent download-reports --project "MyProject" \\
      --report-scope project --report-type xlsx,cyclonedx

  # Download reports with license filtering
  workbench-agent download-reports --project "MyProject" --scan "v1.0.0" \\
      --report-scope scan --report-type xlsx \\
      --selection-type include_foss --selection-view all
""",
    )
    download_reports_parser.add_argument(
        "--project-name",
        "--project",
        dest="project_name",
        help=("The Project to download reports from."),
        metavar="NAME",
    )
    download_reports_parser.add_argument(
        "--project-code",
        help=("Internal Workbench project code (bypasses name resolution)."),
        metavar="CODE",
    )
    download_reports_parser.add_argument(
        "--scan-name",
        "--scan",
        dest="scan_name",
        help=("The Scan to download reports from. Required for scan reports."),
        metavar="NAME",
    )
    download_reports_parser.add_argument(
        "--scan-code",
        help=("Internal Workbench scan code (requires --project-code)."),
        metavar="CODE",
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
            parent_parsers["projectscan"],
            parent_parsers["scan_control"],
            parent_parsers["id_assist_control"],
            parent_parsers["identification_control"],
            parent_parsers["monitoring"],
        ],
        epilog="""
Examples:
  # Scan a branch
  workbench-agent scan-git --project "GitProject" --scan "main-branch" \\
      --git-url https://github.com/owner/repo.git --git-branch main

  # Scan a tag
  workbench-agent scan-git --project "GitProject" --scan "v1.0.0" \\
      --git-url https://github.com/owner/repo.git --git-tag "v1.0.0"

  # Scan a specific commit
  workbench-agent scan-git --project "GitProject" --scan "commit-abc123" \\
      --git-url https://github.com/owner/repo.git \\
      --git-commit ffac537e6cbbf934b08745a378932722df287a53

  # Scan with dependency analysis and summary
  workbench-agent scan-git --project "GitProject" --scan "main-branch" \\
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

    args = parser.parse_args(argv)

    # Validate the parsed arguments
    validate_parsed_args(args)

    return args
