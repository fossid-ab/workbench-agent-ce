"""Fixtures for projects API live tests."""

import uuid

import pytest


@pytest.fixture
def unique_project_name():
    """Unique display name for ephemeral project create/update tests."""
    return f"api-test-project-{uuid.uuid4().hex[:12]}"
