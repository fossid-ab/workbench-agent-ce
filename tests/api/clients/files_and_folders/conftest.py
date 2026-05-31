"""Files and folders live-test fixtures."""

import pytest

pytest_plugins = ["tests.api.clients.conftest"]


@pytest.fixture
def auditor_target_path(pending_paths):
    """
    Pending file path for auditor workflow mutations.

    Prefer the fourth pending path when available so parallel read-only and
    legacy mutation tests can keep using earlier entries on Test Scan.
    """
    for idx in (3, 2, 1, 0):
        if len(pending_paths) > idx:
            return pending_paths[idx]
    return pending_paths[0]
