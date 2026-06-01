"""
Test suite for LinksService and WorkbenchLinks.
"""

from typing import Dict, Optional
from unittest.mock import MagicMock

import pytest

from workbench_agent.api.exceptions import ApiError
from workbench_agent.api.services.links_service import (
    LinksService,
    WorkbenchLinks,
)

TEST_SCAN_ID = 123456
TEST_API_URL = "https://workbench.example.com/api.php"
TEST_BASE_URL = "https://workbench.example.com"

API_URL_VARIANTS = [
    "https://example.com/api.php",
    "https://example.com/api.php/",
    "https://example.com/",
    "https://example.com",
    "http://localhost:8080/api.php",
    "http://localhost:8080/fossid/api.php",
]

EXPECTED_MESSAGES = {
    "scan": "View this Scan in Workbench",
    "pending": "Review Pending IDs in Workbench",
    "policy": "Review policy warnings in Workbench",
    "identified": "View Identified Components in Workbench",
    "dependencies": "View Dependencies in Workbench",
    "vulnerabilities": "Review Vulnerable Components in Workbench",
}


@pytest.fixture
def mock_links_service():
    mock_scans_client = MagicMock()
    return LinksService(
        mock_scans_client,
        api_url=TEST_API_URL,
    )


def assert_url_structure(
    url: str,
    scan_id: int,
    view_param: Optional[str] = None,
):
    assert "index.html" in url
    assert "form=main_interface" in url
    assert "action=scanview" in url
    assert f"sid={scan_id}" in url
    if view_param:
        assert f"current_view={view_param}" in url
    assert "/api.php" not in url


def assert_link_data_structure(link_data: Dict[str, str]):
    assert isinstance(link_data, dict)
    assert len(link_data) == 2
    assert set(link_data.keys()) == {"url", "message"}
    assert isinstance(link_data["url"], str)
    assert isinstance(link_data["message"], str)
    assert len(link_data["url"]) > 0
    assert len(link_data["message"]) > 0


class TestWorkbenchLinks:
    def test_basic_link_generation(self, mock_links_service):
        links = mock_links_service.workbench_links(TEST_SCAN_ID)
        for prop in (
            "scan",
            "pending",
            "policy",
            "identified",
            "dependencies",
            "vulnerabilities",
        ):
            assert hasattr(links, prop)
            assert_link_data_structure(getattr(links, prop))

    def test_url_structure_correctness(self, mock_links_service):
        links = mock_links_service.workbench_links(TEST_SCAN_ID)
        assert links.scan["url"] == (
            f"{TEST_BASE_URL}/index.html?form=main_interface&action="
            f"scanview&sid={TEST_SCAN_ID}&current_view=all_items"
        )
        assert links.pending["url"] == (
            f"{TEST_BASE_URL}/index.html?form=main_interface&action="
            f"scanview&sid={TEST_SCAN_ID}&current_view=pending_items"
        )

    def test_message_correctness(self, mock_links_service):
        links = mock_links_service.workbench_links(TEST_SCAN_ID)
        assert links.scan["message"] == EXPECTED_MESSAGES["scan"]
        assert links.pending["message"] == EXPECTED_MESSAGES["pending"]
        assert links.policy["message"] == EXPECTED_MESSAGES["policy"]

    @pytest.mark.parametrize("api_url", API_URL_VARIANTS)
    def test_api_url_variants(self, api_url):
        service = LinksService(MagicMock(), api_url=api_url)
        links = service.workbench_links(TEST_SCAN_ID)
        for prop_name in ["scan", "pending", "policy"]:
            assert_url_structure(
                getattr(links, prop_name)["url"], TEST_SCAN_ID
            )

    def test_no_version_uses_legacy_format(self):
        links = WorkbenchLinks(TEST_API_URL, TEST_SCAN_ID)
        assert "index.html" in links.scan["url"]
        assert "/nui/" not in links.scan["url"]

    def test_old_version_uses_legacy_format(self):
        links = WorkbenchLinks(
            TEST_API_URL, TEST_SCAN_ID, workbench_version="2025.2.0"
        )
        assert "index.html" in links.scan["url"]
        assert "/nui/" not in links.scan["url"]


EXPECTED_NUI_PATHS = {
    "scan": "audit/all",
    "pending": "audit/pending",
    "identified": "audit/identified",
    "dependencies": "audit/dependencies",
    "policy": "risk-review/license-review",
    "vulnerabilities": "risk-review/security-review",
}

NUI_VERSIONS = ["2026.1.0", "2026.2.0", "2026.1.1"]
LEGACY_VERSIONS = ["", "2025.2.0", "2024.3.0"]


class TestWorkbenchLinksNui:
    def test_nui_url_structure(self):
        links = WorkbenchLinks(
            TEST_API_URL, TEST_SCAN_ID, workbench_version="2026.1.0"
        )
        for prop_name, expected_path in EXPECTED_NUI_PATHS.items():
            link_data = getattr(links, prop_name)
            expected_url = (
                f"{TEST_BASE_URL}/nui/scans/"
                f"{TEST_SCAN_ID}/{expected_path}"
            )
            assert link_data["url"] == expected_url

    @pytest.mark.parametrize("version", NUI_VERSIONS)
    def test_nui_version_triggers_nui_format(self, version):
        links = WorkbenchLinks(
            TEST_API_URL, TEST_SCAN_ID, workbench_version=version
        )
        assert "/nui/scans/" in links.scan["url"]

    @pytest.mark.parametrize("version", LEGACY_VERSIONS)
    def test_legacy_version_keeps_legacy_format(self, version):
        links = WorkbenchLinks(
            TEST_API_URL, TEST_SCAN_ID, workbench_version=version
        )
        assert "index.html" in links.scan["url"]

    def test_nui_via_links_service(self):
        service = LinksService(
            MagicMock(),
            api_url=TEST_API_URL,
            workbench_version="2026.1.0",
        )
        links = service.workbench_links(TEST_SCAN_ID)
        assert "/nui/scans/" in links.scan["url"]


class TestLinksServiceResolution:
    def test_get_workbench_links_resolves_scan_id(self):
        scans = MagicMock()
        scans.get_information.return_value = {"id": 42}
        service = LinksService(scans, api_url=TEST_API_URL)
        links = service.get_workbench_links("SCAN1")
        assert f"sid=42" in links.scan["url"] or "/nui/scans/42/" in links.scan["url"]
        scans.get_information.assert_called_once_with("SCAN1")

    def test_get_workbench_links_raises_without_id(self):
        scans = MagicMock()
        scans.get_information.return_value = {}
        service = LinksService(scans, api_url=TEST_API_URL)
        with pytest.raises(ApiError, match="has no ID"):
            service.get_workbench_links("SCAN1")
