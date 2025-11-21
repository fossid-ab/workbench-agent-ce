"""
Unit tests for config_display module.

Tests cover parameter categorization, section printing, connection info display,
and the main configuration printing function.
"""

import argparse
from unittest.mock import patch

import pytest

from workbench_agent.utilities.config_display import (
    _categorize_parameters,
    _print_cli_parameters,
    _print_connection_info,
    _print_section,
    print_configuration,
)

# ===== Fixtures =====


@pytest.fixture
def mock_params(mocker):
    """Create a mock params object with various parameter types."""
    params = mocker.MagicMock(spec=argparse.Namespace)
    # Connection params (should be skipped in categorization)
    params.api_url = "https://api.example.com"
    params.api_user = "testuser"
    params.api_token = "secret_token"
    params.command = "scan"

    # Agent config params
    params.log = "INFO"
    params.fossid_cli_path = "/usr/bin/fossid"
    params.scan_number_of_tries = 60
    params.scan_wait_time = 5
    params.no_wait = False
    params.show_config = True

    # Result display params
    params.show_licenses = True
    params.show_components = False
    params.show_dependencies = True
    params.show_scan_metrics = False
    params.show_policy_warnings = True
    params.show_vulnerabilities = False
    params.result_save_path = "/tmp/results"

    # Identification params
    params.autoid_file_copyrights = True
    params.autoid_file_licenses = False
    params.autoid_pending_ids = True
    params.reuse_any_identification = False
    params.reuse_my_identifications = True
    params.reuse_project_ids = False
    params.reuse_scan_ids = True
    params.replace_existing_identifications = False

    # Scan operation params
    params.limit = 10
    params.sensitivity = 6
    params.full_file_only = False
    params.advanced_match_scoring = True
    params.match_filtering_threshold = 0.5
    params.delta_scan = False
    params.run_dependency_analysis = True
    params.dependency_analysis_only = False
    params.scan_failed_only = False

    # Scan target params
    params.project_name = "test_project"
    params.scan_name = "test_scan"
    params.path = "/path/to/source"
    params.jar_file_extraction = True
    params.recursively_extract_archives = False
    params.git_url = None
    params.git_branch = None
    params.git_commit = None
    params.git_tag = None
    params.git_depth = None

    # Report generation params
    params.report_scope = "scan"
    params.report_type = "spdx,cyclone_dx"
    params.disclaimer = None
    params.report_save_path = "./reports"
    params.selection_type = None
    params.selection_view = None
    params.include_vex = True

    # Other params
    params.unknown_param = "unknown_value"
    params.another_unknown = 42

    return params


@pytest.fixture
def mock_workbench_client(mocker):
    """Create a mock WorkbenchClient instance."""
    mock_client = mocker.MagicMock()
    mock_client.internal = mocker.MagicMock()
    mock_client.internal.get_config = mocker.MagicMock()
    return mock_client


# ===== Tests for _categorize_parameters =====


def test_categorize_parameters_all_categories(mock_params):
    """Test that parameters are correctly categorized into all groups."""
    (
        agent_config,
        result_display,
        identification_settings,
        scan_operation_settings,
        scan_target,
        report_generation,
        other_params,
    ) = _categorize_parameters(mock_params)

    # Check agent config
    assert "log" in agent_config
    assert "fossid_cli_path" in agent_config
    assert "scan_number_of_tries" in agent_config
    assert "scan_wait_time" in agent_config
    assert "no_wait" in agent_config
    assert "show_config" in agent_config
    assert agent_config["log"] == "INFO"
    assert agent_config["fossid_cli_path"] == "/usr/bin/fossid"

    # Check result display
    assert "show_licenses" in result_display
    assert "show_components" in result_display
    assert "show_dependencies" in result_display
    assert "show_scan_metrics" in result_display
    assert "show_policy_warnings" in result_display
    assert "show_vulnerabilities" in result_display
    assert "result_save_path" in result_display
    assert result_display["show_licenses"] is True
    assert result_display["result_save_path"] == "/tmp/results"

    # Check identification settings
    assert "autoid_file_copyrights" in identification_settings
    assert "autoid_file_licenses" in identification_settings
    assert "autoid_pending_ids" in identification_settings
    assert "reuse_any_identification" in identification_settings
    assert "reuse_my_identifications" in identification_settings
    assert "reuse_project_ids" in identification_settings
    assert "reuse_scan_ids" in identification_settings
    assert "replace_existing_identifications" in identification_settings

    # Check scan operation settings
    assert "limit" in scan_operation_settings
    assert "sensitivity" in scan_operation_settings
    assert "full_file_only" in scan_operation_settings
    assert "advanced_match_scoring" in scan_operation_settings
    assert "match_filtering_threshold" in scan_operation_settings
    assert "delta_scan" in scan_operation_settings
    assert "run_dependency_analysis" in scan_operation_settings
    assert "dependency_analysis_only" in scan_operation_settings
    assert "scan_failed_only" in scan_operation_settings
    assert scan_operation_settings["limit"] == 10
    assert scan_operation_settings["sensitivity"] == 6

    # Check scan target
    assert "project_name" in scan_target
    assert "scan_name" in scan_target
    assert "path" in scan_target
    assert "jar_file_extraction" in scan_target
    assert "recursively_extract_archives" in scan_target
    assert "git_url" in scan_target
    assert "git_branch" in scan_target
    assert "git_commit" in scan_target
    assert "git_tag" in scan_target
    assert "git_depth" in scan_target
    assert scan_target["project_name"] == "test_project"
    assert scan_target["path"] == "/path/to/source"

    # Check report generation
    assert "report_scope" in report_generation
    assert "report_type" in report_generation
    assert "disclaimer" in report_generation
    assert "report_save_path" in report_generation
    assert "selection_type" in report_generation
    assert "selection_view" in report_generation
    assert "include_vex" in report_generation
    assert report_generation["report_scope"] == "scan"
    assert report_generation["report_type"] == "spdx,cyclone_dx"
    assert report_generation["report_save_path"] == "./reports"
    assert report_generation["include_vex"] is True

    # Check other params
    assert "unknown_param" in other_params
    assert "another_unknown" in other_params
    assert other_params["unknown_param"] == "unknown_value"
    assert other_params["another_unknown"] == 42


def test_categorize_parameters_skips_connection_params(mock_params):
    """Test that connection params and command are skipped."""
    (
        agent_config,
        result_display,
        identification_settings,
        scan_operation_settings,
        scan_target,
        report_generation,
        other_params,
    ) = _categorize_parameters(mock_params)

    # Connection params should not appear in any category
    all_params = {
        **agent_config,
        **result_display,
        **identification_settings,
        **scan_operation_settings,
        **scan_target,
        **report_generation,
        **other_params,
    }
    assert "api_url" not in all_params
    assert "api_user" not in all_params
    assert "api_token" not in all_params
    assert "command" not in all_params


def test_categorize_parameters_empty_params():
    """Test categorization with minimal params object."""
    # Use argparse.Namespace directly instead of MagicMock to avoid mock attributes
    params = argparse.Namespace()
    params.command = "scan"
    params.api_url = "https://api.example.com"
    params.api_user = "user"
    params.api_token = "token"

    (
        agent_config,
        result_display,
        identification_settings,
        scan_operation_settings,
        scan_target,
        report_generation,
        other_params,
    ) = _categorize_parameters(params)

    # All categories should be empty (only connection params and command)
    assert agent_config == {}
    assert result_display == {}
    assert identification_settings == {}
    assert scan_operation_settings == {}
    assert scan_target == {}
    assert report_generation == {}
    assert other_params == {}


def test_categorize_parameters_partial_params():
    """Test categorization with only some parameter types."""
    # Use argparse.Namespace directly instead of MagicMock to avoid mock attributes
    params = argparse.Namespace()
    params.command = "scan"
    params.api_url = "https://api.example.com"
    params.api_user = "user"
    params.api_token = "token"
    # Only agent config params
    params.log = "DEBUG"
    params.scan_number_of_tries = 30
    # Only scan target params
    params.project_name = "my_project"
    params.scan_name = "my_scan"

    (
        agent_config,
        result_display,
        identification_settings,
        scan_operation_settings,
        scan_target,
        report_generation,
        other_params,
    ) = _categorize_parameters(params)

    assert len(agent_config) == 2
    assert len(scan_target) == 2
    assert result_display == {}
    assert report_generation == {}
    assert identification_settings == {}
    assert scan_operation_settings == {}
    assert other_params == {}


# ===== Tests for _print_section =====


@patch("builtins.print")
def test_print_section_with_params(mock_print):
    """Test printing a section with parameters."""
    params_dict = {
        "param1": "value1",
        "param2": 42,
        "param3": True,
    }

    _print_section("Test Section", params_dict)

    # Verify print was called
    assert mock_print.call_count == 4  # Title + 3 params

    # Check title was printed
    assert mock_print.call_args_list[0][0][0] == "\nTest Section"

    # Check params were printed (sorted)
    printed_lines = [call[0][0] for call in mock_print.call_args_list[1:]]
    assert "  param1" in printed_lines[0]
    assert "  param2" in printed_lines[1]
    assert "  param3" in printed_lines[2]


@patch("builtins.print")
def test_print_section_empty_dict(mock_print):
    """Test printing a section with empty dict (should not print)."""
    _print_section("Empty Section", {})

    # Should not print anything
    mock_print.assert_not_called()


@patch("builtins.print")
def test_print_section_sorted_output(mock_print):
    """Test that parameters are printed in sorted order."""
    params_dict = {
        "zebra": "z_value",
        "alpha": "a_value",
        "beta": "b_value",
    }

    _print_section("Sorted Section", params_dict)

    # Get printed lines (skip title)
    printed_lines = [call[0][0] for call in mock_print.call_args_list[1:]]

    # Verify sorted order
    assert "alpha" in printed_lines[0]
    assert "beta" in printed_lines[1]
    assert "zebra" in printed_lines[2]


# ===== Tests for _print_connection_info =====


@patch("builtins.print")
def test_print_connection_info_success(
    mock_print, mock_params, mock_workbench_client
):
    """Test printing connection info with successful server info retrieval."""
    mock_workbench_client.internal.get_config.return_value = {
        "server_name": "Test Server",
        "version": "24.3.0",
        "default_language": "en",
    }

    _print_connection_info(mock_params, mock_workbench_client)

    # Verify print calls
    assert mock_print.call_count >= 4

    # Get printed lines
    printed_lines = [call[0][0] for call in mock_print.call_args_list]

    # Check connection info header
    assert any(
        "🔗 Workbench Connection Info:" in line for line in printed_lines
    )

    # Check that URL is NOT displayed (security improvement)
    assert not any(
        "https://api.example.com" in line for line in printed_lines
    )
    assert not any("API URL" in line for line in printed_lines)

    # Check connection parameters (API User should still be shown)
    assert any("API User" in line for line in printed_lines)
    assert any("testuser" in line for line in printed_lines)

    # Check server info
    assert any("Server Name" in line for line in printed_lines)
    assert any("Test Server" in line for line in printed_lines)
    assert any("Workbench Version" in line for line in printed_lines)
    assert any("24.3.0" in line for line in printed_lines)
    assert any("✓ Connected" in line for line in printed_lines)

    # Verify get_config was called
    mock_workbench_client.internal.get_config.assert_called_once()


@patch("builtins.print")
def test_print_connection_info_empty_server_info(
    mock_print, mock_params, mock_workbench_client
):
    """Test connection info when server info is empty."""
    mock_workbench_client.internal.get_config.return_value = {}

    _print_connection_info(mock_params, mock_workbench_client)

    printed_lines = [call[0][0] for call in mock_print.call_args_list]

    # Should show Unknown for server info
    assert any(
        "Server Name" in line and "Unknown" in line
        for line in printed_lines
    )
    assert any(
        "Workbench Version" in line and "Unknown" in line
        for line in printed_lines
    )
    assert any(
        "⚠ Could not retrieve server info" in line
        for line in printed_lines
    )


@patch("builtins.print")
def test_print_connection_info_exception_handling(
    mock_print, mock_params, mock_workbench_client
):
    """Test connection info when get_config raises an exception."""
    mock_workbench_client.internal.get_config.side_effect = Exception(
        "Connection failed"
    )

    _print_connection_info(mock_params, mock_workbench_client)

    printed_lines = [call[0][0] for call in mock_print.call_args_list]

    # Should show Unknown and error status
    assert any(
        "Server Name" in line and "Unknown" in line
        for line in printed_lines
    )
    assert any(
        "Workbench Version" in line and "Unknown" in line
        for line in printed_lines
    )
    assert any(
        "⚠ Could not retrieve server info" in line
        for line in printed_lines
    )


@patch("builtins.print")
def test_print_connection_info_partial_server_info(
    mock_print, mock_params, mock_workbench_client
):
    """Test connection info with partial server info (missing some fields)."""
    mock_workbench_client.internal.get_config.return_value = {
        "version": "24.3.0",
        # server_name missing
    }

    _print_connection_info(mock_params, mock_workbench_client)

    printed_lines = [call[0][0] for call in mock_print.call_args_list]

    # Should show Unknown for missing fields
    assert any(
        "Server Name" in line and "Unknown" in line
        for line in printed_lines
    )
    assert any("24.3.0" in line for line in printed_lines)


# ===== Tests for _print_cli_parameters =====


@patch("workbench_agent.utilities.config_display._print_section")
def test_print_cli_parameters_calls_all_sections(
    mock_print_section, mock_params
):
    """Test that _print_cli_parameters calls all section print functions."""
    _print_cli_parameters(mock_params)

    # Should be called 7 times (6 sections + other params)
    assert mock_print_section.call_count == 7

    # Get section titles
    section_titles = [
        call[0][0] for call in mock_print_section.call_args_list
    ]

    assert "⚙️  Agent Configuration:" in section_titles
    assert "🎯 Scan Target:" in section_titles
    assert "🔬 Scan Operation Settings:" in section_titles
    assert "🔍 Identification Settings:" in section_titles
    assert "📊 Result Display:" in section_titles
    assert "📄 Report Generation:" in section_titles
    assert "📋 Other Parameters:" in section_titles


@patch("workbench_agent.utilities.config_display._print_section")
def test_print_cli_parameters_empty_params(mock_print_section, mocker):
    """Test _print_cli_parameters with minimal params."""
    params = mocker.MagicMock(spec=argparse.Namespace)
    params.command = "scan"
    params.api_url = "https://api.example.com"
    params.api_user = "user"
    params.api_token = "token"

    _print_cli_parameters(params)

    # Should still call all sections, but some will be empty
    assert mock_print_section.call_count == 7

    # Check that empty sections are not printed (handled by _print_section)
    section_calls = mock_print_section.call_args_list
    for call in section_calls:
        # Each call should have a title and a dict
        assert len(call[0]) == 2
        assert isinstance(call[0][1], dict)


# ===== Tests for print_configuration =====


@patch("workbench_agent.utilities.config_display._print_cli_parameters")
@patch("workbench_agent.utilities.config_display._print_connection_info")
@patch("builtins.print")
def test_print_configuration_full(
    mock_print,
    mock_print_conn,
    mock_print_cli,
    mock_params,
    mock_workbench_client,
):
    """Test print_configuration calls all sub-functions."""
    print_configuration(mock_params, mock_workbench_client)

    # Check header was printed
    assert mock_print.call_count >= 2
    printed_lines = [call[0][0] for call in mock_print.call_args_list]
    assert any(
        "--- Workbench Agent Configuration ---" in line
        for line in printed_lines
    )
    assert any("Command: scan" in line for line in printed_lines)

    # Check sub-functions were called
    mock_print_cli.assert_called_once_with(mock_params)
    mock_print_conn.assert_called_once_with(
        mock_params, mock_workbench_client
    )

    # Check footer
    assert any(
        "------------------------------------" in line
        for line in printed_lines
    )


@patch("workbench_agent.utilities.config_display._print_cli_parameters")
@patch("workbench_agent.utilities.config_display._print_connection_info")
@patch("builtins.print")
def test_print_configuration_different_command(
    mock_print, mock_params, mock_workbench_client
):
    """Test print_configuration with different command."""
    mock_params.command = "show-results"

    print_configuration(mock_params, mock_workbench_client)

    printed_lines = [call[0][0] for call in mock_print.call_args_list]
    assert any("Command: show-results" in line for line in printed_lines)


@patch("builtins.print")
def test_print_configuration_integration(
    mock_print, mock_params, mock_workbench_client
):
    """Test print_configuration integration without mocking sub-functions."""
    mock_workbench_client.internal.get_config.return_value = {
        "server_name": "Integration Server",
        "version": "24.4.0",
    }

    print_configuration(mock_params, mock_workbench_client)

    # Verify header and footer
    printed_lines = [call[0][0] for call in mock_print.call_args_list]
    assert any(
        "--- Workbench Agent Configuration ---" in line
        for line in printed_lines
    )
    assert any("Command: scan" in line for line in printed_lines)
    assert any(
        "------------------------------------" in line
        for line in printed_lines
    )

    # Verify connection info was printed
    assert any(
        "🔗 Workbench Connection Info:" in line for line in printed_lines
    )

    # Verify sections were printed
    assert any("⚙️  Agent Configuration:" in line for line in printed_lines)
    assert any("🎯 Scan Target:" in line for line in printed_lines)
