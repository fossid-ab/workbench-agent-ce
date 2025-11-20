"""
Test suite for scan_workflows.py utilities.

This module contains tests for scan workflow configuration functions.
"""

import argparse

import pytest

from workbench_agent.utilities.scan_workflows import (
    determine_scans_to_run,
)

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def mock_params(mocker):
    """Create a mock argparse.Namespace with common default values."""
    params = mocker.MagicMock(spec=argparse.Namespace)

    # Analysis flags
    params.run_dependency_analysis = False
    params.dependency_analysis_only = False

    return params


# ============================================================================
# SCAN CONFIGURATION TESTS
# ============================================================================


class TestDetermineScansToRun:
    """Test cases for the determine_scans_to_run function."""

    def test_default_configuration(self, mock_params):
        """Test default behavior - only KB scan."""
        mock_params.run_dependency_analysis = False
        mock_params.dependency_analysis_only = False

        result = determine_scans_to_run(mock_params)

        assert result == {
            "run_kb_scan": True,
            "run_dependency_analysis": False,
        }

    def test_with_dependency_analysis(self, mock_params):
        """Test with dependency analysis enabled."""
        mock_params.run_dependency_analysis = True
        mock_params.dependency_analysis_only = False

        result = determine_scans_to_run(mock_params)
        assert result == {
            "run_kb_scan": True,
            "run_dependency_analysis": True,
        }

    def test_dependency_analysis_only(self, mock_params):
        """Test with dependency analysis only."""
        mock_params.run_dependency_analysis = False
        mock_params.dependency_analysis_only = True

        result = determine_scans_to_run(mock_params)
        assert result == {
            "run_kb_scan": False,
            "run_dependency_analysis": True,
        }

    def test_conflicting_flags_resolved(self, mock_params):
        """Test that conflicting flags are resolved (DA only takes precedence)."""
        mock_params.run_dependency_analysis = True
        mock_params.dependency_analysis_only = True

        result = determine_scans_to_run(mock_params)
        assert result == {
            "run_kb_scan": False,
            "run_dependency_analysis": True,
        }
