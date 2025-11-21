"""
Test suite for post_scan_summary.py utilities.

This module contains tests for post-scan summary and result handling functions
including result fetching, display, formatting, and file operations.
"""

# mypy: disable-error-code=import-not-found,import-untyped

import argparse
import json
from typing import Dict, Optional
from unittest.mock import MagicMock, mock_open, patch

import pytest

from workbench_agent.api.exceptions import ApiError
from workbench_agent.utilities.post_scan_summary import (
    display_results,
    fetch_display_save_results,
    fetch_results,
    format_duration,
    print_operation_summary,
    save_results_to_file,
)

# ============================================================================
# TEST CONSTANTS
# ============================================================================

# Common test data
TEST_SCAN_CODE = "TEST_SCAN_12345"
TEST_PROJECT_CODE = "TEST_PROJECT_67890"
TEST_SCAN_ID = 123456

# Sample test data
SAMPLE_VULNERABILITY_DATA = {
    "cve": "CVE-2021-1234",
    "severity": "HIGH",
    "component_name": "test_component",
    "component_version": "1.0.0",
}

SAMPLE_LICENSE_DATA = {"identifier": "MIT", "name": "MIT License"}

SAMPLE_DEPENDENCY_DATA = {
    "name": "test_dependency",
    "version": "2.1.0",
    "license_identifier": "Apache-2.0",
}

# Duration test cases
DURATION_TEST_CASES = [
    (0, "0 seconds"),
    (1, "1 second"),
    (59, "59 seconds"),
    (60, "1 minutes"),
    (61, "1 minutes, 1 seconds"),
    (119, "1 minutes, 59 seconds"),
    (120, "2 minutes"),
    (121, "2 minutes, 1 seconds"),
    (3600, "60 minutes"),
    (3661, "61 minutes, 1 seconds"),
    (7322.5, "122 minutes, 2 seconds"),  # rounding
    (None, "N/A"),
    ("invalid", "Invalid Duration"),
]

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def mock_workbench(mocker):
    """Create a mock WorkbenchClient instance."""
    workbench = mocker.MagicMock()

    # Data retrieval used by fetch_results (via results service)
    workbench.results.get_dependencies = mocker.MagicMock()
    workbench.results.get_identified_licenses = mocker.MagicMock()
    workbench.results.get_identified_components = mocker.MagicMock()
    workbench.results.get_scan_metrics = mocker.MagicMock()
    workbench.results.get_policy_warnings = mocker.MagicMock()
    workbench.results.get_vulnerabilities = mocker.MagicMock()

    return workbench


@pytest.fixture
def mock_params(mocker):
    """Create a mock argparse.Namespace with common default values."""
    params = mocker.MagicMock(spec=argparse.Namespace)

    # Scan configuration
    params.scan_number_of_tries = 60
    params.scan_wait_time = 5
    params.command = "scan"

    # Project and scan identification
    params.project_name = "test_project"
    params.scan_name = "test_scan"

    # Display flags - all False by default
    params.show_licenses = False
    params.show_components = False
    params.show_dependencies = False
    params.show_scan_metrics = False
    params.show_policy_warnings = False
    params.show_vulnerabilities = False

    # Output settings
    params.result_save_path = None

    # Analysis flags
    params.run_dependency_analysis = False
    params.dependency_analysis_only = False

    return params


@pytest.fixture
def sample_results_data():
    """Provide sample results data for testing."""
    return {
        "dependency_analysis": [SAMPLE_DEPENDENCY_DATA],
        "vulnerabilities": [SAMPLE_VULNERABILITY_DATA],
        "kb_licenses": [SAMPLE_LICENSE_DATA],
    }


# ============================================================================
# DURATION FORMATTING TESTS
# ============================================================================


class TestFormatDuration:
    """Test cases for the format_duration function."""

    @pytest.mark.parametrize("seconds, expected", DURATION_TEST_CASES)
    def test_format_duration_variations(self, seconds, expected):
        """Test format_duration with various input types and values."""
        assert format_duration(seconds) == expected

    def test_format_duration_edge_cases(self):
        """Test format_duration with edge cases."""
        # Test very large numbers
        assert format_duration(86400) == "1440 minutes"  # 24 hours

        # Test zero and negative (though negative shouldn't happen in practice)
        assert format_duration(0) == "0 seconds"


# ============================================================================
# FILE OPERATIONS TESTS
# ============================================================================


class TestSaveResultsToFile:
    """Test cases for the save_results_to_file function."""

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.makedirs")
    def test_save_success(self, mock_makedirs, mock_open_file):
        """Test successful file saving."""
        filepath = "output/results.json"
        results = {"scan_id": TEST_SCAN_ID, "status": "completed"}

        save_results_to_file(filepath, results)

        mock_makedirs.assert_called_once_with("output", exist_ok=True)
        mock_open_file.assert_any_call(filepath, "w", encoding="utf-8")

        # Verify JSON content
        handle = mock_open_file()
        written = "".join(arg[0][0] for arg in handle.write.call_args_list)
        assert json.loads(written) == results

    @patch("os.makedirs", side_effect=OSError("Permission denied"))
    def test_save_makedirs_failure(self, mock_makedirs):
        """Test handling of directory creation failure."""
        filepath = "restricted/results.json"
        results = {"test": "data"}

        # Should not raise exception
        save_results_to_file(filepath, results)
        mock_makedirs.assert_called_once_with("restricted", exist_ok=True)

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.makedirs")
    def test_save_write_failure(self, mock_makedirs, mock_open_file):
        """Test handling of file write failure."""
        filepath = "output/results.json"
        results = {"test": "data"}

        # Simulate write error
        handle = mock_open_file()
        handle.write.side_effect = IOError("Disk full")

        # Should not raise exception
        save_results_to_file(filepath, results)
        mock_makedirs.assert_called_once_with("output", exist_ok=True)


# ============================================================================
# RESULTS PROCESSING TESTS
# ============================================================================


class TestFetchResults:
    """Test cases for the fetch_results function."""

    def test_no_flags_set(self, mock_workbench, mock_params):
        """Test when no result flags are set."""
        result = fetch_results(mock_workbench, mock_params, TEST_SCAN_CODE)
        assert result == {}

    def test_fetch_license_results(self, mock_workbench, mock_params):
        """Test fetching license results."""
        mock_params.show_licenses = True
        mock_workbench.results.get_dependencies.return_value = [
            SAMPLE_DEPENDENCY_DATA
        ]
        mock_workbench.results.get_identified_licenses.return_value = [
            SAMPLE_LICENSE_DATA
        ]

        result = fetch_results(mock_workbench, mock_params, TEST_SCAN_CODE)

        assert "dependency_analysis" in result
        assert "kb_licenses" in result
        mock_workbench.results.get_dependencies.assert_called_once_with(
            TEST_SCAN_CODE
        )
        mock_workbench.results.get_identified_licenses.assert_called_once_with(
            TEST_SCAN_CODE
        )

    def test_fetch_vulnerabilities(self, mock_workbench, mock_params):
        """Test fetching vulnerability results."""
        mock_params.show_vulnerabilities = True
        mock_workbench.results.get_vulnerabilities.return_value = [
            SAMPLE_VULNERABILITY_DATA
        ]

        result = fetch_results(mock_workbench, mock_params, TEST_SCAN_CODE)

        assert "vulnerabilities" in result
        mock_workbench.results.get_vulnerabilities.assert_called_once_with(
            TEST_SCAN_CODE
        )

    def test_api_error_handling(self, mock_workbench, mock_params):
        """Test graceful handling of API errors during result fetching."""
        mock_params.show_licenses = True
        mock_workbench.results.get_dependencies.side_effect = ApiError(
            "Service unavailable"
        )
        mock_workbench.results.get_identified_licenses.return_value = [
            SAMPLE_LICENSE_DATA
        ]

        # Should not raise, should return partial results
        result = fetch_results(mock_workbench, mock_params, TEST_SCAN_CODE)

        # Should return kb_licenses since that call succeeded
        assert "kb_licenses" in result


class TestDisplayResults:
    """Test cases for the display_results function."""

    def test_empty_results(self, mock_params):
        """Test displaying empty results."""
        result = display_results({}, mock_params)
        assert result is False  # No results to display

    def test_display_with_data(self, mock_params, sample_results_data):
        """Test displaying results with actual data."""
        mock_params.show_dependencies = True
        mock_params.show_vulnerabilities = True

        result = display_results(sample_results_data, mock_params)
        assert result is True


class TestFetchDisplaySaveResults:
    """Test cases for the fetch_display_save_results orchestration function."""

    @patch("workbench_agent.utilities.post_scan_summary.fetch_results")
    @patch("workbench_agent.utilities.post_scan_summary.display_results")
    @patch("workbench_agent.utilities.post_scan_summary.save_results_to_file")
    def test_complete_workflow(
        self, mock_save, mock_display, mock_fetch, mock_workbench, mock_params
    ):
        """Test complete fetch, display, and save workflow."""
        mock_params.result_save_path = "output.json"
        mock_params.show_licenses = True
        mock_fetch.return_value = {"test": "data"}
        mock_display.return_value = True

        fetch_display_save_results(mock_workbench, mock_params, TEST_SCAN_CODE)

        mock_fetch.assert_called_once_with(
            mock_workbench, mock_params, TEST_SCAN_CODE
        )
        mock_display.assert_called_once_with({"test": "data"}, mock_params)
        mock_save.assert_called_once_with("output.json", {"test": "data"})

    @patch("workbench_agent.utilities.post_scan_summary.fetch_results")
    @patch("workbench_agent.utilities.post_scan_summary.display_results")
    def test_no_save_specified(
        self, mock_display, mock_fetch, mock_workbench, mock_params
    ):
        """Test fetch and display without saving."""
        mock_params.result_save_path = None
        mock_params.show_licenses = True
        mock_fetch.return_value = {"test": "data"}
        mock_display.return_value = True

        fetch_display_save_results(mock_workbench, mock_params, TEST_SCAN_CODE)

        mock_fetch.assert_called_once_with(
            mock_workbench, mock_params, TEST_SCAN_CODE
        )
        mock_display.assert_called_once_with({"test": "data"}, mock_params)


# ============================================================================
# OPERATION SUMMARY TESTS
# ============================================================================


class TestPrintOperationSummary:
    """Test cases for the print_operation_summary function."""

    def test_basic_summary(self, mock_params):
        """Test basic operation summary."""
        mock_params.command = "scan"

        # Should complete without errors
        print_operation_summary(mock_params, True)

    def test_summary_with_durations(self, mock_params):
        """Test operation summary with timing information."""
        mock_params.command = "scan"
        durations = {"kb_scan": 120.5, "dependency_analysis": 60.0}

        # Should complete without errors
        print_operation_summary(
            mock_params,
            True,
            durations,
        )

    def test_summary_when_da_failed(self, mock_params):
        """Test operation summary when dependency analysis failed."""
        mock_params.command = "scan"

        # Should complete without errors
        print_operation_summary(mock_params, False)
