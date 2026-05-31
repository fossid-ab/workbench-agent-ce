"""Tests for QuickScanService."""

from unittest.mock import MagicMock

import pytest

from workbench_agent.api.services.quick_scan_service import QuickScanService


@pytest.fixture
def quick_scan_service():
    client = MagicMock()
    return QuickScanService(quick_scan_client=client)


def test_scan_one_file_delegates(quick_scan_service):
    quick_scan_service._quick_scan.scan_one_file.return_value = [{"a": 1}]
    out = quick_scan_service.scan_one_file("YmFzZTY0", limit=2, sensitivity=6)
    assert out == [{"a": 1}]
    quick_scan_service._quick_scan.scan_one_file.assert_called_once_with(
        "YmFzZTY0", limit=2, sensitivity=6
    )
