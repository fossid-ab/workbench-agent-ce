"""Tests for legacy two-phase main() orchestration."""

from unittest.mock import MagicMock, patch

from workbench_agent.main import COMMAND_HANDLERS, main


@patch("workbench_agent.main.WorkbenchClient")
@patch("workbench_agent.main.setup_logging")
def test_legacy_pipeline_invokes_scan_then_show(
    mock_setup_logging,
    mock_client_cls,
):
    mock_setup_logging.return_value = MagicMock()
    mock_client_cls.return_value = MagicMock()

    mock_scan = MagicMock(return_value=True)
    mock_show = MagicMock(return_value=True)

    argv = [
        "workbench-agent",
        "--api_url",
        "https://wb.example/api.php",
        "--api_user",
        "user",
        "--api_token",
        "token",
        "--project_code",
        "PRJ",
        "--scan_code",
        "SCN",
        "--path",
        ".",
    ]

    with patch.dict(
        COMMAND_HANDLERS,
        {"scan": mock_scan, "show-results": mock_show},
    ):
        with patch("workbench_agent.main.sys.argv", argv):
            exit_code = main()

    assert exit_code == 0
    mock_scan.assert_called_once()
    mock_show.assert_called_once()

    scan_args = mock_scan.call_args[0][1]
    show_args = mock_show.call_args[0][1]
    assert scan_args.command == "scan"
    assert show_args.command == "show-results"
    assert scan_args.project_code == "PRJ"
    assert show_args.project_code == "PRJ"
    assert show_args.show_licenses is True
