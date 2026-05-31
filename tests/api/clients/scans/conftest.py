"""Scans live-test fixtures (timeouts, shared error probes)."""

import os
import uuid
from typing import Any, Dict

import pytest

from workbench_agent.api.exceptions import ApiError

# BaseAPI defaults to 1800s; some servers can take minutes on scan row_not_found paths.
_DEFAULT_LIVE_TIMEOUT = 120


@pytest.fixture(autouse=True)
def cap_scans_live_request_timeout(request):
    """
    Cap HTTP timeout for scans live tests so a hung request fails in minutes,
    not up to BaseAPI's 30-minute default.
    """
    if request.node.get_closest_marker("requires_workbench") is None:
        yield
        return

    workbench_client = request.getfixturevalue("workbench_client")
    timeout = int(
        os.environ.get(
            "WORKBENCH_LIVE_API_TIMEOUT",
            str(_DEFAULT_LIVE_TIMEOUT),
        )
    )
    api = workbench_client._base_api
    original = api._send_request

    def capped_send_request(payload: dict, timeout: int = timeout) -> dict:
        return original(payload, timeout=timeout)

    api._send_request = capped_send_request  # type: ignore[method-assign]
    yield
    api._send_request = original  # type: ignore[method-assign]


@pytest.fixture(scope="session")
def unknown_scan_code() -> str:
    return f"INVALID_SCAN_{uuid.uuid4().hex[:16].upper()}"


@pytest.fixture(scope="session")
def unknown_scan_row_not_found_probe(
    workbench_client, unknown_scan_code
) -> Dict[str, Any]:
    """
    One live ``get_information`` for a missing scan.

    On some Workbench servers this call alone can take 1–3 minutes; other error tests should
    reuse this fixture instead of repeating the slow request.
    """
    with pytest.raises(ApiError) as exc_info:
        workbench_client.scans.get_information(unknown_scan_code)
    err = exc_info.value
    return {
        "scan_code": unknown_scan_code,
        "message": str(err),
        "details": err.details,
    }
