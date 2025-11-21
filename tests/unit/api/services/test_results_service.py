"""
Test suite for ResultsService.

This module contains tests for the ResultsService class including
WorkbenchLinks generation and URL formatting.
"""

from typing import Dict, Optional
from unittest.mock import MagicMock

import pytest

from workbench_agent.api.services.results_service import ResultsService

# ============================================================================
# TEST CONSTANTS
# ============================================================================

TEST_SCAN_ID = 123456
TEST_API_URL = "https://workbench.example.com/api.php"
TEST_BASE_URL = "https://workbench.example.com"

# API URL variants for testing
API_URL_VARIANTS = [
    "https://example.com/api.php",
    "https://example.com/api.php/",
    "https://example.com/",
    "https://example.com",
    "http://localhost:8080/api.php",
    "http://localhost:8080/fossid/api.php",
]

# Expected link messages
EXPECTED_MESSAGES = {
    "scan": "View this Scan in Workbench",
    "pending": "Review Pending IDs in Workbench",
    "policy": "Review policy warnings in Workbench",
    "identified": "View Identified Components in Workbench",
    "dependencies": "View Dependencies in Workbench",
    "vulnerabilities": "Review Vulnerable Components in Workbench",
}

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def mock_results_service():
    """Create a ResultsService with mocked clients."""
    mock_scans_client = MagicMock()
    mock_vulns_client = MagicMock()

    # Mock the _api attribute on scans_client to provide api_url
    mock_base_api = MagicMock()
    mock_base_api.api_url = TEST_API_URL
    mock_scans_client._api = mock_base_api

    return ResultsService(mock_scans_client, mock_vulns_client)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def assert_url_structure(
    url: str,
    scan_id: int,
    view_param: Optional[str] = None,
):
    """Assert that a URL has the correct Workbench structure."""
    assert "index.html" in url
    assert "form=main_interface" in url
    assert "action=scanview" in url
    assert f"sid={scan_id}" in url

    if view_param:
        assert f"current_view={view_param}" in url

    # Should not contain /api.php
    assert "/api.php" not in url


def assert_link_data_structure(link_data: Dict[str, str]):
    """Assert that link data has the correct structure."""
    assert isinstance(link_data, dict)
    assert len(link_data) == 2
    assert set(link_data.keys()) == {"url", "message"}

    # Values should be non-empty strings
    assert isinstance(link_data["url"], str)
    assert isinstance(link_data["message"], str)
    assert len(link_data["url"]) > 0
    assert len(link_data["message"]) > 0


# ============================================================================
# WORKBENCH LINKS TESTS
# ============================================================================


class TestWorkbenchLinks:
    """Comprehensive test cases for the WorkbenchLinks class."""

    def test_basic_link_generation(self, mock_results_service):
        """Test basic link generation with standard API URL."""
        links = mock_results_service.links(TEST_SCAN_ID)

        # Should have all expected link properties
        assert hasattr(links, "scan")
        assert hasattr(links, "pending")
        assert hasattr(links, "policy")
        assert hasattr(links, "identified")
        assert hasattr(links, "dependencies")
        assert hasattr(links, "vulnerabilities")

        # Each link should have correct structure
        assert_link_data_structure(links.scan)
        assert_link_data_structure(links.pending)
        assert_link_data_structure(links.policy)

    def test_url_structure_correctness(self, mock_results_service):
        """Test that generated URLs have correct structure."""
        links = mock_results_service.links(TEST_SCAN_ID)

        # Test scan link (with current_view=all_items)
        scan_url = links.scan["url"]
        expected_base = (
            f"{TEST_BASE_URL}/index.html?form=main_interface&action="
            f"scanview&sid={TEST_SCAN_ID}&current_view=all_items"
        )
        assert scan_url == expected_base

        # Test pending link (with current_view=pending_items)
        pending_url = links.pending["url"]
        expected_pending = (
            f"{TEST_BASE_URL}/index.html?form=main_interface&action="
            f"scanview&sid={TEST_SCAN_ID}&current_view=pending_items"
        )
        assert pending_url == expected_pending

        # Test policy link (with current_view=mark_as_identified)
        policy_url = links.policy["url"]
        expected_policy = (
            f"{TEST_BASE_URL}/index.html?form=main_interface&action="
            f"scanview&sid={TEST_SCAN_ID}&current_view=mark_as_identified"
        )
        assert policy_url == expected_policy

    def test_message_correctness(self, mock_results_service):
        """Test that generated messages match expectations."""
        links = mock_results_service.links(TEST_SCAN_ID)

        assert links.scan["message"] == EXPECTED_MESSAGES["scan"]
        assert links.pending["message"] == EXPECTED_MESSAGES["pending"]
        assert links.policy["message"] == EXPECTED_MESSAGES["policy"]
        assert links.identified["message"] == EXPECTED_MESSAGES["identified"]
        assert (
            links.dependencies["message"] == EXPECTED_MESSAGES["dependencies"]
        )
        assert (
            links.vulnerabilities["message"]
            == EXPECTED_MESSAGES["vulnerabilities"]
        )

    @pytest.mark.parametrize("api_url", API_URL_VARIANTS)
    def test_api_url_variants(self, api_url):
        """Test that function handles various API URL formats correctly."""
        mock_scans_client = MagicMock()
        mock_vulns_client = MagicMock()
        mock_base_api = MagicMock()
        mock_base_api.api_url = api_url
        mock_scans_client._api = mock_base_api

        results_service = ResultsService(mock_scans_client, mock_vulns_client)
        links = results_service.links(TEST_SCAN_ID)

        # All URLs should be properly formatted regardless of input
        for prop_name in ["scan", "pending", "policy"]:
            link_data = getattr(links, prop_name)
            url = link_data["url"]
            assert_url_structure(url, TEST_SCAN_ID)

    def test_scan_id_type_handling(self, mock_results_service):
        """Test that function handles different scan_id types."""
        # Test with integer
        links_int = mock_results_service.links(123)
        assert "sid=123" in links_int.scan["url"]

        # Test with string (should work, gets converted in URL)
        links_str = mock_results_service.links(456)
        assert "sid=456" in links_str.scan["url"]

    def test_result_consistency(self, mock_results_service):
        """Test that multiple calls return consistent results."""
        links1 = mock_results_service.links(TEST_SCAN_ID)
        links2 = mock_results_service.links(TEST_SCAN_ID)

        # Compare URLs and messages
        assert links1.scan["url"] == links2.scan["url"]
        assert links1.pending["url"] == links2.pending["url"]
        assert links1.policy["url"] == links2.policy["url"]

    def test_base_url_stripping_variations(self):
        """Test that /api.php is properly stripped from various URL formats."""
        test_cases = [
            ("https://example.com/api.php", "https://example.com"),
            ("https://example.com/api.php/", "https://example.com"),
            (
                "https://example.com/fossid/api.php",
                "https://example.com/fossid",
            ),
            (
                "https://example.com/path/to/api.php",
                "https://example.com/path/to",
            ),
        ]

        for input_url, expected_base in test_cases:
            mock_scans_client = MagicMock()
            mock_vulns_client = MagicMock()
            mock_base_api = MagicMock()
            mock_base_api.api_url = input_url
            mock_scans_client._api = mock_base_api

            results_service = ResultsService(
                mock_scans_client, mock_vulns_client
            )
            links = results_service.links(TEST_SCAN_ID)
            scan_url = links.scan["url"]
            assert scan_url.startswith(f"{expected_base}/index.html")

    def test_required_url_elements_present(self, mock_results_service):
        """Test that all links contain required URL elements."""
        links = mock_results_service.links(TEST_SCAN_ID)

        required_params = [
            "form=main_interface",
            "action=scanview",
            f"sid={TEST_SCAN_ID}",
        ]

        # All links should contain these base parameters
        for prop_name in [
            "scan",
            "pending",
            "policy",
            "identified",
            "dependencies",
            "vulnerabilities",
        ]:
            link_data = getattr(links, prop_name)
            url = link_data["url"]
            for param in required_params:
                assert param in url, f"Missing '{param}' in link URL: {url}"

    def test_view_parameters_correctness(self, mock_results_service):
        """Test that view parameters are correctly added to URLs."""
        links = mock_results_service.links(TEST_SCAN_ID)

        # Scan link should have current_view=all_items
        assert "current_view=all_items" in links.scan["url"]

        # Pending link should have current_view=pending_items
        assert "current_view=pending_items" in links.pending["url"]

        # Policy link should have current_view=mark_as_identified
        assert "current_view=mark_as_identified" in links.policy["url"]

        # Dependencies link should have current_view=dependency_analysis
        assert "current_view=dependency_analysis" in links.dependencies["url"]

    def test_direct_method_access(self, mock_results_service):
        """Test direct method access like link_to_pending."""
        pending_link = mock_results_service.link_to_pending(TEST_SCAN_ID)
        assert_link_data_structure(pending_link)
        assert "current_view=pending_items" in pending_link["url"]

        scan_link = mock_results_service.link_to_scan(TEST_SCAN_ID)
        assert_link_data_structure(scan_link)
        assert "current_view=all_items" in scan_link["url"]

        policy_link = mock_results_service.link_to_policy(TEST_SCAN_ID)
        assert_link_data_structure(policy_link)
        assert "current_view=mark_as_identified" in policy_link["url"]
