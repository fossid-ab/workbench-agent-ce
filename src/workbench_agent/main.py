import importlib
import logging
import sys
from typing import Callable, Optional

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
from workbench_agent.utilities.config_display import print_configuration
from workbench_agent.utilities.error_handling import format_and_print_error
from workbench_agent.utilities.redaction import redact_cli_args_for_logging

# Values are ``module:attr`` import specs. Tests may replace entries with
# callables; ``_resolve_handler`` accepts both.
COMMAND_HANDLERS = {
    "analyze": "workbench_agent.handlers.analyze:handle_analyze",
    "scan": "workbench_agent.handlers.scan:handle_scan",
    "blind-scan": "workbench_agent.handlers.blind_scan:handle_blind_scan",
    "scan-git": "workbench_agent.handlers.scan_git:handle_scan_git",
    "delete-scan": "workbench_agent.handlers.delete_scan:handle_delete_scan",
    "show-results": "workbench_agent.handlers.show_results:handle_show_results",
    "import-da": "workbench_agent.handlers.import_da:handle_import_da",
    "evaluate-gates": "workbench_agent.handlers.evaluate_gates:handle_evaluate_gates",
    "import-sbom": "workbench_agent.handlers.import_sbom:handle_import_sbom",
    "download-reports": "workbench_agent.handlers.download_reports:handle_download_reports",
    "quick-scan": "workbench_agent.handlers.quick_scan:handle_quick_scan",
}


def _resolve_handler(command_key: str) -> Optional[Callable]:
    """Return the handler for ``command_key``, importing it on first use."""
    spec = COMMAND_HANDLERS.get(command_key)
    if spec is None:
        return None
    if callable(spec):
        return spec
    module_name, _, attr_name = spec.partition(":")
    module = importlib.import_module(module_name)
    return getattr(module, attr_name)


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
    handler = _resolve_handler(command_key)
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
    captured_args: Optional[list] = None,
) -> int:
    """Parse argv, initialize client if needed, and dispatch one command."""
    args = parse_cmdline_args(argv)
    if captured_args is not None:
        captured_args.clear()
        captured_args.append(args)

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


def _run_legacy_pipeline(
    pipeline: LegacyPipeline,
    captured_args: Optional[list] = None,
) -> int:
    """Execute legacy scan → show-results pipeline."""
    scan_args = parse_cmdline_args(pipeline.scan_argv)
    if captured_args is not None:
        captured_args.clear()
        captured_args.append(scan_args)
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
        captured_args=captured_args,
    )


def _report_failure(
    error: Exception,
    args,
    *,
    log_message: str,
    default_context: str,
    exc_info: bool = False,
) -> None:
    logging.getLogger("workbench-agent").error(
        log_message,
        error,
        exc_info=exc_info,
    )
    context = getattr(args, "command", default_context)
    format_and_print_error(error, context, args)


def main() -> int:
    """
    Main entrypoint for the Workbench Agent.

    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    captured_args: list = []
    try:
        pipeline = build_legacy_pipeline(sys.argv)
        if pipeline is not None:
            return _run_legacy_pipeline(pipeline, captured_args)
        return _run_parsed_command(None, captured_args=captured_args)

    except (ValidationError, ConfigurationError, AuthenticationError) as e:
        args = captured_args[0] if captured_args else None
        _report_failure(
            e,
            args,
            log_message="Configuration error: %s",
            default_context="cli",
        )
        return 2

    except (
        ApiError,
        NetworkError,
        ProcessError,
        FileSystemError,
        CompatibilityError,
    ) as e:
        args = captured_args[0] if captured_args else None
        _report_failure(
            e,
            args,
            log_message="Runtime error: %s",
            default_context="init",
        )
        return 1

    except WorkbenchAgentError as e:
        args = captured_args[0] if captured_args else None
        _report_failure(
            e,
            args,
            log_message="Workbench Agent error: %s",
            default_context="unknown",
        )
        return 1

    except Exception as e:
        args = captured_args[0] if captured_args else None
        _report_failure(
            e,
            args,
            log_message="Unexpected error: %s",
            default_context="unknown",
            exc_info=True,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
