"""Shared API test fixtures (credentials and Workbench client)."""

import os

import pytest

from workbench_agent.api import WorkbenchClient
from workbench_agent.api.utils.version import normalize_workbench_version


@pytest.fixture(scope="session")
def workbench_config():
    """Workbench credentials from environment; skips if missing."""
    config = {
        "url": os.environ.get("WORKBENCH_URL"),
        "user": os.environ.get("WORKBENCH_USER"),
        "token": os.environ.get("WORKBENCH_TOKEN"),
    }
    missing = [k for k, v in config.items() if not v]
    if missing:
        missing_vars = ", ".join(f"WORKBENCH_{k.upper()}" for k in missing)
        pytest.skip(
            f"Missing required environment variables: {missing_vars}. "
            "Set WORKBENCH_URL, WORKBENCH_USER, and WORKBENCH_TOKEN."
        )
    return config


@pytest.fixture(scope="session")
def workbench_client(workbench_config):
    """Real WorkbenchClient connected to the configured server."""
    return WorkbenchClient(
        api_url=workbench_config["url"],
        api_user=workbench_config["user"],
        api_token=workbench_config["token"],
    )


@pytest.fixture(scope="session")
def workbench_version_raw(workbench_client):
    """Raw version string from getConfig (e.g. ``2026.1.0#25559481630``)."""
    return workbench_client.internal.get_config().get("version", "Unknown")


@pytest.fixture(scope="session")
def workbench_version(workbench_client, workbench_version_raw):
    """
    Normalized MAJOR.MINOR.PATCH used for contracts and fixtures.

    Matches :meth:`WorkbenchClient.get_workbench_version` /
    :func:`workbench_agent.api.utils.version.normalize_workbench_version`.
    """
    cached = getattr(workbench_client, "_workbench_version", "") or ""
    if cached:
        return cached
    normalized = normalize_workbench_version(str(workbench_version_raw))
    return normalized or "unknown"
