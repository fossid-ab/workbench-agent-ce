"""Scans live-test fixtures (timeouts)."""

import os

import pytest

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
