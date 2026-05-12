"""Test main() function orchestration and exception handling."""

import logging
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Add src to path
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src")
)

from workbench_agent.api.exceptions import (
    ApiError,
    AuthenticationError,
    CompatibilityError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
)
from workbench_agent.exceptions import (
    ConfigurationError,
    FileSystemError,
    ValidationError,
)
from workbench_agent.main import main, redact_cli_args_for_logging, setup_logging


class TestMainFunctionSuccess:
    """Test successful main() function execution."""

    def test_main_success_with_scan_handler(self, mock_main_dependencies):
        """Test successful main() execution with scan handler."""
        mock_args = MagicMock(command="scan", log="INFO")
        mock_main_dependencies["handle_scan"].return_value = True

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_scan"].assert_called_once()
        mock_main_dependencies["workbench_client"].assert_called_once_with(
            api_url=mock_args.api_url,
            api_user=mock_args.api_user,
            api_token=mock_args.api_token,
        )

    def test_main_success_with_scan_git_handler(
        self, mock_main_dependencies
    ):
        """Test successful main() execution with scan-git handler."""
        mock_args = MagicMock(command="scan-git", log="INFO")
        mock_main_dependencies["handle_scan_git"].return_value = True

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_scan_git"].assert_called_once()

    def test_main_success_with_import_da_handler(
        self, mock_main_dependencies
    ):
        """Test successful main() execution with import-da handler."""
        mock_args = MagicMock(command="import-da", log="INFO")
        mock_main_dependencies["handle_import_da"].return_value = True

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_import_da"].assert_called_once()

    def test_main_success_with_import_sbom_handler(
        self, mock_main_dependencies
    ):
        """Test successful main() execution with import-sbom handler."""
        mock_args = MagicMock(command="import-sbom", log="INFO")
        mock_main_dependencies["handle_import_sbom"].return_value = True

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_import_sbom"].assert_called_once()

    def test_main_success_with_show_results_handler(
        self, mock_main_dependencies
    ):
        """Test successful main() execution with show-results handler."""
        mock_args = MagicMock(command="show-results", log="INFO")
        mock_args.result_save_path = (
            None  # Don't trigger save functionality
        )
        mock_main_dependencies["handle_show_results"].return_value = True

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_show_results"].assert_called_once()

    def test_main_success_with_download_reports_handler(
        self, mock_main_dependencies
    ):
        """Test successful main() execution with download-reports handler."""
        mock_args = MagicMock(command="download-reports", log="INFO")
        mock_main_dependencies["handle_download_reports"].return_value = (
            True
        )

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 0
        mock_main_dependencies[
            "handle_download_reports"
        ].assert_called_once()


class TestMainFunctionExceptionHandling:
    """Test main() function exception handling."""

    def test_main_validation_error_during_parsing(self):
        """Test main() handling validation error during argument parsing."""
        with patch(
            "workbench_agent.main.parse_cmdline_args"
        ) as mock_parse:
            mock_parse.side_effect = ValidationError(
                "Test validation error"
            )

            result = main()

            assert result == 2  # Validation error exit code

    def test_main_configuration_error_during_api_init(self):
        """Test main() handling configuration error during API initialization."""
        mock_args = MagicMock(command="scan", log="INFO")

        with (
            patch(
                "workbench_agent.main.parse_cmdline_args",
                return_value=mock_args,
            ),
            patch("workbench_agent.main.WorkbenchClient") as mock_client,
        ):
            mock_client.side_effect = ConfigurationError(
                "Test config error"
            )

            result = main()

            assert result == 2

    def test_main_authentication_error_during_api_init(self):
        """Test main() handling authentication error during API initialization."""
        mock_args = MagicMock(command="scan", log="INFO")

        with (
            patch(
                "workbench_agent.main.parse_cmdline_args",
                return_value=mock_args,
            ),
            patch("workbench_agent.main.WorkbenchClient") as mock_client,
        ):
            mock_client.side_effect = AuthenticationError("Auth error")

            result = main()

            assert result == 2

    @pytest.mark.parametrize(
        "exception_class,exception_msg",
        [
            (ApiError, "API error"),
            (NetworkError, "Network error"),
            (ProcessError, "Process error"),
            (ProcessTimeoutError, "Timeout error"),
            (FileSystemError, "FS error"),
            (CompatibilityError, "Compatibility error"),
            (ProjectNotFoundError, "Project not found"),
            (ScanNotFoundError, "Scan not found"),
        ],
    )
    def test_main_specific_exception_handling(
        self, exception_class, exception_msg, mock_main_dependencies
    ):
        """Test main() handling specific exception types in handlers."""
        mock_args = MagicMock(command="scan", log="INFO")
        mock_main_dependencies["handle_scan"].side_effect = (
            exception_class(exception_msg)
        )

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 1  # Handler error exit code

    def test_main_unexpected_exception_handling(
        self, mock_main_dependencies
    ):
        """Test main() handling unexpected exceptions."""
        mock_args = MagicMock(command="scan", log="INFO")
        mock_main_dependencies["handle_scan"].side_effect = ValueError(
            "Unexpected error"
        )

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 1  # Unexpected error exit code


class TestEvaluateGatesSpecialHandling:
    """Test special exit code handling for evaluate-gates command."""

    def test_evaluate_gates_success_returns_0(
        self, mock_main_dependencies
    ):
        """Test evaluate-gates command returns 0 on success (gates pass)."""
        mock_args = MagicMock(command="evaluate-gates", log="INFO")
        mock_main_dependencies["handle_evaluate_gates"].return_value = (
            True  # Gates pass
        )

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 0

    def test_evaluate_gates_failure_returns_1(
        self, mock_main_dependencies
    ):
        """Test evaluate-gates command returns 1 on failure (gates fail)."""
        mock_args = MagicMock(command="evaluate-gates", log="INFO")
        mock_main_dependencies["handle_evaluate_gates"].return_value = (
            False  # Gates fail
        )

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 1


class TestHandlerReturnValues:
    """Test that different command handlers properly handle return values."""

    @pytest.mark.parametrize(
        "command,handler_name",
        [
            ("scan", "handle_scan"),
            ("scan-git", "handle_scan_git"),
            ("import-da", "handle_import_da"),
            ("show-results", "handle_show_results"),
            ("delete-scan", "handle_delete_scan"),
            ("download-reports", "handle_download_reports"),
        ],
    )
    def test_non_evaluate_gates_handlers_ignore_return_value(
        self, command, handler_name, mock_main_dependencies
    ):
        """Test that non-evaluate-gates handlers return 0 regardless of return value."""
        mock_args = MagicMock(command=command, log="INFO")
        mock_main_dependencies[handler_name].return_value = (
            True  # Handler succeeds
        )

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 0


class TestRedactCliArgsForLogging:
    """Tests for secret redaction in CLI args debug logs."""

    def test_redacts_api_token(self):
        ns = SimpleNamespace(
            command="scan",
            api_token="secret-value",
            api_user="user@example.com",
        )
        out = redact_cli_args_for_logging(ns)
        assert out["api_token"] == "***REDACTED***"
        assert out["api_user"] == "user@example.com"
        assert out["command"] == "scan"

    def test_redacts_suffix_style_secrets(self):
        ns = SimpleNamespace(oauth_refresh_token="x", normal_field="ok")
        out = redact_cli_args_for_logging(ns)
        assert out["oauth_refresh_token"] == "***REDACTED***"
        assert out["normal_field"] == "ok"

    def test_leaves_none_values_unchanged(self):
        ns = SimpleNamespace(api_token=None, other="v")
        out = redact_cli_args_for_logging(ns)
        assert out["api_token"] is None


class TestLoggingConfiguration:
    """Test proper logging configuration."""

    def test_setup_logging_downgrades_http_client_loggers(self):
        """urllib3/requests should not spam DEBUG when root accepts DEBUG."""
        setup_logging("DEBUG")
        assert logging.getLogger("urllib3").level == logging.WARNING
        assert (
            logging.getLogger("urllib3.connectionpool").level
            == logging.WARNING
        )
        assert logging.getLogger("requests").level == logging.WARNING

    def test_main_handles_log_level(self, mock_main_dependencies):
        """Test that main() properly handles different log levels."""
        mock_args = MagicMock(command="scan", log="DEBUG")
        mock_main_dependencies["handle_scan"].return_value = True

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 0


class TestMainIntegration:
    """Integration tests for main function behavior."""

    def test_main_full_success_flow(self, mock_main_dependencies):
        """Test a complete success flow."""
        mock_args = MagicMock()
        mock_args.command = "scan"

        mock_args.api_url = "https://test.com/api.php"
        mock_args.api_user = "testuser"
        mock_args.api_token = "****"
        mock_args.log = "INFO"

        mock_main_dependencies["handle_scan"].return_value = True

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        assert result == 0
        mock_main_dependencies["handle_scan"].assert_called_once()

    @pytest.mark.parametrize(
        "command,handler_name",
        [
            ("scan", "handle_scan"),
            ("scan-git", "handle_scan_git"),
            ("import-da", "handle_import_da"),
            ("show-results", "handle_show_results"),
            ("delete-scan", "handle_delete_scan"),
            ("download-reports", "handle_download_reports"),
            ("evaluate-gates", "handle_evaluate_gates"),
        ],
    )
    def test_main_command_dispatch_logic(
        self, command, handler_name, mock_main_dependencies
    ):
        """Test that commands are properly dispatched to their handlers."""
        mock_args = MagicMock(command=command, log="INFO")
        mock_main_dependencies[handler_name].return_value = True

        with patch(
            "workbench_agent.main.parse_cmdline_args",
            return_value=mock_args,
        ):
            result = main()

        # All commands should succeed
        assert (
            result == 0
            if command != "evaluate-gates"
            else result in [0, 1]
        )
        mock_main_dependencies[handler_name].assert_called_once()

