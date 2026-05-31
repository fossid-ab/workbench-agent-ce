"""Scan deletion service live tests — reuse client fixtures."""

pytest_plugins = [
    "tests.api.clients.conftest",
    "tests.api.clients.scans.conftest",
]
