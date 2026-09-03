import logging
import sys
from typing import Optional

from workbench_agent.api.exceptions import (
    ApiError,
    AuthenticationError,
    CompatibilityError,
    NetworkError,
    ProcessError,
)
from workbench_agent.api.workbench_client import WorkbenchClient
from workbench_agent.cli import parse_cmdline_args
from workbench_agent.cli.legacy_compat import LegacyPipeline, build_legacy_pipeline
from workbench_agent.exceptions import (
    ConfigurationError,
    FileSystemError,
    ValidationError,
    WorkbenchAgentError,
)
from workbench_agent.handlers import (
    handle_analyze,
    handle_blind_scan,
    handle_delete_scan,
    handle_download_reports,
    handle_evaluate_gates,
    handle_import_da,
    handle_import_sbom,
    handle_quick_scan,
    handle_scan,
    handle_scan_git,
    handle_show_results,
)
from workbench_agent.utilities.config_display import print_configuration
from workbench_agent.utilities.error_handling import format_and_print_error
from workbench_agent.utilities.redaction import redact_cli_args_for_logging

COMMAND_HANDLERS = {
    "analyze": handle_analyze,
    "scan": handle_scan,
    "blind-scan": handle_blind_scan,
    "scan-git": handle_scan_git,
    "delete-scan": handle_delete_scan,
    "show-results": handle_show_results,
    "import-da": handle_import_da,
    "evaluate-gates": handle_evaluate_gates,
    "import-sbom": handle_import_sbom,
    "download-reports": handle_download_reports,
    "quick-scan": handle_quick_scan,
}


def setup_logging(log_level: str) -> logging.Logger:
    """
    Set up logging configuration with file and console handlers.

    The log file always records at DEBUG so runs leave a full audit trail.
    ``log_level`` controls console verbosity only.

    Args:
        log_level: Console logging level (DEBUG, INFO, WARNING, ERROR)

    Returns:
        Configured logger instance
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    file_handler = logging.FileHandler("workbench-agent-log.txt", mode="w", encoding="utf-8")
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - " "%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(numeric_level)
    root_logger.addHandler(console_handler)

    app_logger = logging.getLogger("workbench-agent")
    app_logger.setLevel(logging.DEBUG)

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    return app_logger


def _dispatch_command(args, logger: logging.Logger, workbench: WorkbenchClient) -> int:
    """Run a parsed command and return its exit code."""
    if getattr(args, "show_config", False):
        print_configuration(args, workbench)

    command_key = args.command
    handler = COMMAND_HANDLERS.get(command_key)
    if not handler:
        print(f"Error: Unknown command '{command_key}'.")
        logger.error("Unknown command '%s' encountered in main dispatch.", command_key)
        raise ValidationError(f"Unknown command/scan type: {command_key}")

    logger.info("Executing %s command...", command_key)
    result = handler(workbench, args)

    if command_key == "evaluate-gates":
        exit_code = 0 if result else 1
        if exit_code == 0:
            print("\nWorkbench Agent finished successfully (Gates Passed).")
        else:
            print("\nWorkbench Agent finished (Gates FAILED).")
        return exit_code

    if result:
        return 0

    logger.error("Handler reported failure")
    print("\nWorkbench Agent finished with errors.")
    return 1


def _run_parsed_command(
    argv: Optional[list],
    *,
    logger: Optional[logging.Logger] = None,
    workbench: Optional[WorkbenchClient] = None,
    announce_success: bool = True,
) -> int:
    """Parse argv, initialize client if needed, and dispatch one command."""
    args = parse_cmdline_args(argv)

    if logger is None:
        logger = setup_logging(args.log)
        logger.info("Workbench Agent starting...")
        logger.debug("Command line arguments: %s", redact_cli_args_for_logging(args))

    if workbench is None:
        logger.info("Initializing WorkbenchClient...")
        workbench = WorkbenchClient(
            api_url=args.api_url,
            api_user=args.api_user,
            api_token=args.api_token,
        )
        logger.info("WorkbenchClient initialized.")

    exit_code = _dispatch_command(args, logger, workbench)
    if announce_success and exit_code == 0 and args.command != "evaluate-gates":
        print("\nWorkbench Agent finished successfully.")
    return exit_code


def _run_legacy_pipeline(pipeline: LegacyPipeline) -> int:
    """Execute legacy scan → show-results pipeline."""
    scan_args = parse_cmdline_args(pipeline.scan_argv)
    logger = setup_logging(scan_args.log)
    logger.info("Workbench Agent starting (legacy compatibility mode)...")
    logger.debug("Legacy scan argv: %s", pipeline.scan_argv)

    logger.info("Initializing WorkbenchClient...")
    workbench = WorkbenchClient(
        api_url=scan_args.api_url,
        api_user=scan_args.api_user,
        api_token=scan_args.api_token,
    )
    logger.info("WorkbenchClient initialized.")

    exit_code = _dispatch_command(scan_args, logger, workbench)
    if exit_code != 0:
        return exit_code

    return _run_parsed_command(
        pipeline.show_argv,
        logger=logger,
        workbench=workbench,
    )


def main() -> int:
    """
    Main entrypoint for the Workbench Agent.

    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    args = None
    try:
        pipeline = build_legacy_pipeline(sys.argv)
        if pipeline is not None:
            return _run_legacy_pipeline(pipeline)
        return _run_parsed_command(None)

    except (ValidationError, ConfigurationError, AuthenticationError) as e:
        try:
            logger = logging.getLogger("workbench-agent")
            logger.error("Configuration error: %s", e)
        except Exception:
            pass
        try:
            context = getattr(args, "command", "cli")
            format_and_print_error(e, context, args)
        except NameError:
            print(f"Error: {getattr(e, 'message', str(e))}")
        return 2

    except (
        ApiError,
        NetworkError,
        ProcessError,
        FileSystemError,
        CompatibilityError,
    ) as e:
        try:
            logging.getLogger("workbench-agent").error("Runtime error: %s", e)
        except Exception:
            pass
        try:
            context = getattr(args, "command", "init")
            format_and_print_error(e, context, args)
        except NameError:
            print(f"Error: {getattr(e, 'message', str(e))}")
        return 1

    except WorkbenchAgentError as e:
        try:
            logging.getLogger("workbench-agent").error("Workbench Agent error: %s", e)
        except Exception:
            pass
        try:
            context = getattr(args, "command", "unknown")
            format_and_print_error(e, context, args)
        except NameError:
            print(f"Error: {getattr(e, 'message', str(e))}")
        return 1

    except Exception as e:
        try:
            logging.getLogger("workbench-agent").error("Unexpected error: %s", e, exc_info=True)
        except Exception:
            pass
        try:
            context = getattr(args, "command", "unknown")
            format_and_print_error(e, context, args)
        except NameError:
            print(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
