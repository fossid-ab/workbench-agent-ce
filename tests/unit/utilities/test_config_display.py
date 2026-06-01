"""
Unit tests for config_display module.

Covers:
- ``_user_params`` filtering
- ``_print_section`` rendering primitive
- Each per-group ``_print_*`` renderer (correct title + correct param subset)
- ``_print_connection_info`` (custom layout)
- ``print_configuration`` orchestration + end-to-end smoke
"""

import argparse
from unittest.mock import patch

import pytest

from workbench_agent.utilities.config_display import (
    _print_agent_config,
    _print_connection_info,
    _print_identification_settings,
    _print_other_parameters,
    _print_report_generation,
    _print_result_display,
    _print_scan_operation_settings,
    _print_scan_target,
    _print_section,
    _user_params,
    print_configuration,
)

# ===== Fixtures =====
#
# Fixtures are declared as ``fixture_<name>`` and registered to pytest
# under the bare ``<name>`` via ``@pytest.fixture(name=...)``. This avoids
# pylint's ``redefined-outer-name`` warnings on every test parameter
# (the function name at module scope no longer collides with the test
# parameter name pytest injects).


@pytest.fixture(name="mock_params")
def fixture_mock_params(mocker):
    """A params namespace with at least one value in every group."""
    params = mocker.MagicMock(spec=argparse.Namespace)
    # Connection params (filtered out of every group)
    params.api_url = "https://api.example.com"
    params.api_user = "testuser"
    params.api_token = "secret_token"
    params.command = "scan"

    # Agent config
    params.log = "INFO"
    params.fossid_toolbox_path = "/usr/bin/fossid"
    params.scan_number_of_tries = 60
    params.scan_wait_time = 5
    params.no_wait = False
    params.show_config = True

    # Result display
    params.show_licenses = True
    params.show_components = False
    params.show_dependencies = True
    params.show_scan_metrics = False
    params.show_policy_warnings = True
    params.show_vulnerabilities = False
    params.result_save_path = "/tmp/results"

    # Identification
    params.autoid_file_copyrights = True
    params.autoid_file_licenses = False
    params.autoid_pending_ids = True
    params.reuse_any_identification = False
    params.reuse_my_identifications = True
    params.reuse_project_ids = False
    params.reuse_scan_ids = True
    params.replace_existing_identifications = False

    # Scan operation
    params.limit = 10
    params.sensitivity = 6
    params.full_file_only = False
    params.advanced_match_scoring = True
    params.match_filtering_threshold = 0.5
    params.delta_scan = False
    params.run_dependency_analysis = True
    params.dependency_analysis_only = False
    params.scan_failed_only = False

    # Scan target
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

    # Report generation
    params.report_scope = "scan"
    params.report_type = "spdx,cyclone_dx"
    params.disclaimer = None
    params.report_save_path = "./reports"
    params.selection_type = None
    params.selection_view = None
    params.include_vex = True

    # Catch-all (Other Parameters)
    params.unknown_param = "unknown_value"
    params.another_unknown = 42

    return params


@pytest.fixture(name="mock_workbench_client")
def fixture_mock_workbench_client(mocker):
    """A WorkbenchClient mock with a stubbable ``get_workbench_config()``."""
    mock_client = mocker.MagicMock()
    mock_client.get_workbench_config = mocker.MagicMock()
    return mock_client


# ===== Tests for _user_params =====


def test_user_params_skips_connection_and_command():
    """Connection params and command are filtered out."""
    ns = argparse.Namespace()
    ns.command = "scan"
    ns.api_url = "https://api.example.com"
    ns.api_user = "user"
    ns.api_token = "token"
    ns.log = "INFO"

    result = _user_params(ns)

    assert "command" not in result
    assert "api_url" not in result
    assert "api_user" not in result
    assert "api_token" not in result
    assert result == {"log": "INFO"}


def test_user_params_skips_private_attributes():
    """Attributes starting with underscore are filtered out."""
    ns = argparse.Namespace()
    ns.command = "scan"
    ns.api_url = "u"
    ns.api_user = "u"
    ns.api_token = "t"
    ns.log = "INFO"
    ns._internal = "hidden"

    result = _user_params(ns)

    assert "_internal" not in result
    assert result == {"log": "INFO"}


def test_user_params_returns_empty_for_minimal_params():
    """With only skipped keys, the result is empty."""
    ns = argparse.Namespace()
    ns.command = "scan"
    ns.api_url = "u"
    ns.api_user = "u"
    ns.api_token = "t"

    assert _user_params(ns) == {}


# ===== Tests for _print_section =====


@patch("builtins.print")
def test_print_section_with_params(mock_print):
    """Test printing a section with parameters."""
    items = {"param1": "value1", "param2": 42, "param3": True}

    _print_section("Test Section", items)

    assert mock_print.call_count == 4  # Title + 3 params
    assert mock_print.call_args_list[0][0][0] == "\nTest Section"

    printed = [call[0][0] for call in mock_print.call_args_list[1:]]
    assert "  param1" in printed[0]
    assert "  param2" in printed[1]
    assert "  param3" in printed[2]


@patch("builtins.print")
def test_print_section_empty_dict(mock_print):
    """Empty dict prints nothing."""
    _print_section("Empty Section", {})
    mock_print.assert_not_called()


@patch("builtins.print")
def test_print_section_sorted_output(mock_print):
    """Parameters are printed in sorted order."""
    items = {
        "zebra": "z_value",
        "alpha": "a_value",
        "beta": "b_value",
    }

    _print_section("Sorted Section", items)

    printed = [call[0][0] for call in mock_print.call_args_list[1:]]
    assert "alpha" in printed[0]
    assert "beta" in printed[1]
    assert "zebra" in printed[2]


# ===== Tests for per-group renderers =====
#
# Each per-group renderer should:
# 1. Print its own title (verifies the right group method is wired up)
# 2. Print only the params it owns (no leakage from other groups)
# 3. Skip command/connection/private params (covered by _user_params)
# 4. Be a no-op when none of its params are set


def _printed(mock_print) -> str:
    """Concatenated print output for substring assertions."""
    return "\n".join(call[0][0] for call in mock_print.call_args_list)


@patch("builtins.print")
def test_print_agent_config(mock_print, mock_params):
    """Agent Configuration prints its title and only its keys."""
    _print_agent_config(mock_params)
    out = _printed(mock_print)

    assert "⚙️  Agent Configuration:" in out
    for k in ("log", "fossid_toolbox_path", "scan_number_of_tries"):
        assert k in out
    for k in ("project_name", "show_licenses", "limit", "report_scope"):
        assert k not in out
    for k in ("api_url", "api_user", "api_token", "command"):
        assert k not in out


@patch("builtins.print")
def test_print_scan_target(mock_print, mock_params):
    """Scan Target prints its title and only its keys."""
    _print_scan_target(mock_params)
    out = _printed(mock_print)

    assert "🎯 Scan Target:" in out
    for k in ("project_name", "scan_name", "path", "git_url"):
        assert k in out
    for k in ("log", "show_licenses", "limit", "report_scope"):
        assert k not in out


@patch("builtins.print")
def test_print_scan_operation_settings(mock_print, mock_params):
    """Scan Operation Settings prints its title and only its keys."""
    _print_scan_operation_settings(mock_params)
    out = _printed(mock_print)

    assert "🔬 Scan Operation Settings:" in out
    for k in ("limit", "sensitivity", "delta_scan"):
        assert k in out
    for k in ("log", "project_name", "show_licenses", "report_scope"):
        assert k not in out


@patch("builtins.print")
def test_print_identification_settings(mock_print, mock_params):
    """Identification Settings prints its title and only its keys."""
    _print_identification_settings(mock_params)
    out = _printed(mock_print)

    assert "🔍 Identification Settings:" in out
    for k in (
        "autoid_file_copyrights",
        "reuse_my_identifications",
        "replace_existing_identifications",
    ):
        assert k in out
    for k in ("log", "project_name", "limit", "report_scope"):
        assert k not in out


@patch("builtins.print")
def test_print_result_display(mock_print, mock_params):
    """Result Display prints its title and only its keys."""
    _print_result_display(mock_params)
    out = _printed(mock_print)

    assert "📊 Result Display:" in out
    for k in ("show_licenses", "show_components", "result_save_path"):
        assert k in out
    for k in ("log", "project_name", "limit", "report_scope"):
        assert k not in out


@patch("builtins.print")
def test_print_report_generation(mock_print, mock_params):
    """Report Generation prints its title and only its keys."""
    _print_report_generation(mock_params)
    out = _printed(mock_print)

    assert "📄 Report Generation:" in out
    for k in ("report_scope", "report_type", "include_vex"):
        assert k in out
    for k in ("log", "project_name", "limit", "show_licenses"):
        assert k not in out


@patch("builtins.print")
def test_print_other_parameters_renders_unclaimed_keys(
    mock_print, mock_params
):
    """Other Parameters prints any key not owned by a named group."""
    _print_other_parameters(mock_params)
    out = _printed(mock_print)

    assert "📋 Other Parameters:" in out
    assert "unknown_param" in out
    assert "another_unknown" in out
    for k in ("log", "project_name", "limit", "report_scope"):
        assert k not in out


@patch("builtins.print")
def test_print_other_parameters_noop_when_all_known(mock_print):
    """Other Parameters prints nothing when no unclaimed keys exist."""
    ns = argparse.Namespace()
    ns.command = "scan"
    ns.api_url = "u"
    ns.api_user = "u"
    ns.api_token = "t"
    ns.log = "INFO"
    ns.project_name = "p"

    _print_other_parameters(ns)

    mock_print.assert_not_called()


@patch("builtins.print")
def test_per_group_method_noop_when_no_owned_params(mock_print):
    """A group method prints nothing when none of its params are set."""
    ns = argparse.Namespace()
    ns.command = "scan"
    ns.api_url = "u"
    ns.api_user = "u"
    ns.api_token = "t"
    ns.unknown_param = "x"  # Only an "other" param

    _print_agent_config(ns)

    mock_print.assert_not_called()


# ===== Tests for _print_connection_info =====


@patch("builtins.print")
def test_print_connection_info_success(
    mock_print, mock_params, mock_workbench_client
):
    """Test printing connection info with successful server info retrieval."""
    mock_workbench_client.get_workbench_config.return_value = {
        "server_name": "Test Server",
        "version": "24.3.0",
        "default_language": "en",
    }

    _print_connection_info(mock_params, mock_workbench_client)

    assert mock_print.call_count >= 4
    printed_lines = [call[0][0] for call in mock_print.call_args_list]

    assert any(
        "🔗 Workbench Connection Info:" in line for line in printed_lines
    )
    # API URL is intentionally not displayed (security)
    assert not any(
        "https://api.example.com" in line for line in printed_lines
    )
    assert not any("API URL" in line for line in printed_lines)

    assert any("API User" in line for line in printed_lines)
    assert any("testuser" in line for line in printed_lines)
    assert any("Server Name" in line for line in printed_lines)
    assert any("Test Server" in line for line in printed_lines)
    assert any("Workbench Version" in line for line in printed_lines)
    assert any("24.3.0" in line for line in printed_lines)
    assert any("✓ Connected" in line for line in printed_lines)

    mock_workbench_client.get_workbench_config.assert_called_once()


@patch("builtins.print")
def test_print_connection_info_empty_server_info(
    mock_print, mock_params, mock_workbench_client
):
    """Test connection info when server info is empty."""
    mock_workbench_client.get_workbench_config.return_value = {}

    _print_connection_info(mock_params, mock_workbench_client)

    printed_lines = [call[0][0] for call in mock_print.call_args_list]

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
    mock_workbench_client.get_workbench_config.side_effect = Exception(
        "Connection failed"
    )

    _print_connection_info(mock_params, mock_workbench_client)

    printed_lines = [call[0][0] for call in mock_print.call_args_list]

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
    mock_workbench_client.get_workbench_config.return_value = {
        "version": "24.3.0",
    }

    _print_connection_info(mock_params, mock_workbench_client)

    printed_lines = [call[0][0] for call in mock_print.call_args_list]

    assert any(
        "Server Name" in line and "Unknown" in line
        for line in printed_lines
    )
    assert any("24.3.0" in line for line in printed_lines)


# ===== Tests for print_configuration =====


def test_print_configuration_calls_all_section_renderers(
    mock_params, mock_workbench_client
):
    """print_configuration delegates to every section renderer in order."""
    with patch(
        "workbench_agent.utilities.config_display._print_connection_info"
    ) as m_conn, patch(
        "workbench_agent.utilities.config_display._print_agent_config"
    ) as m_agent, patch(
        "workbench_agent.utilities.config_display._print_scan_target"
    ) as m_target, patch(
        "workbench_agent.utilities.config_display"
        "._print_scan_operation_settings"
    ) as m_ops, patch(
        "workbench_agent.utilities.config_display"
        "._print_identification_settings"
    ) as m_ident, patch(
        "workbench_agent.utilities.config_display._print_result_display"
    ) as m_results, patch(
        "workbench_agent.utilities.config_display._print_report_generation"
    ) as m_reports, patch(
        "workbench_agent.utilities.config_display._print_other_parameters"
    ) as m_other:
        print_configuration(mock_params, mock_workbench_client)

    m_conn.assert_called_once_with(mock_params, mock_workbench_client)
    for m in (
        m_agent,
        m_target,
        m_ops,
        m_ident,
        m_results,
        m_reports,
        m_other,
    ):
        m.assert_called_once_with(mock_params)


@patch("workbench_agent.utilities.config_display._print_other_parameters")
@patch("workbench_agent.utilities.config_display._print_report_generation")
@patch("workbench_agent.utilities.config_display._print_result_display")
@patch(
    "workbench_agent.utilities.config_display"
    "._print_identification_settings"
)
@patch(
    "workbench_agent.utilities.config_display"
    "._print_scan_operation_settings"
)
@patch("workbench_agent.utilities.config_display._print_scan_target")
@patch("workbench_agent.utilities.config_display._print_agent_config")
@patch("workbench_agent.utilities.config_display._print_connection_info")
@patch("builtins.print")
def test_print_configuration_prints_header_and_command(
    mock_print,
    _m_conn,
    _m_agent,
    _m_target,
    _m_ops,
    _m_ident,
    _m_results,
    _m_reports,
    _m_other,
    mock_params,
    mock_workbench_client,
):
    """The header line, command echo, and footer are emitted."""
    mock_params.command = "show-results"

    print_configuration(mock_params, mock_workbench_client)

    printed_lines = [call[0][0] for call in mock_print.call_args_list]
    assert any(
        "--- Workbench Agent Configuration ---" in line
        for line in printed_lines
    )
    assert any("Command: show-results" in line for line in printed_lines)
    assert any(
        "------------------------------------" in line
        for line in printed_lines
    )


@patch("builtins.print")
def test_print_configuration_integration(
    mock_print, mock_params, mock_workbench_client
):
    """End-to-end smoke test without mocking sub-functions."""
    mock_workbench_client.get_workbench_config.return_value = {
        "server_name": "Integration Server",
        "version": "24.4.0",
    }

    print_configuration(mock_params, mock_workbench_client)

    out = _printed(mock_print)
    assert "--- Workbench Agent Configuration ---" in out
    assert "Command: scan" in out
    assert "------------------------------------" in out

    # All eight sections render their titles.
    for title in (
        "🔗 Workbench Connection Info:",
        "⚙️  Agent Configuration:",
        "🎯 Scan Target:",
        "🔬 Scan Operation Settings:",
        "🔍 Identification Settings:",
        "📊 Result Display:",
        "📄 Report Generation:",
        "📋 Other Parameters:",
    ):
        assert title in out
