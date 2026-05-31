"""Identification service live tests."""

import pytest

from workbench_agent.api.services.identification_service import (
    IdentificationService,
)


@pytest.fixture
def identification_service(workbench_client):
    """Build IdentificationService from a WorkbenchClient instance."""
    return IdentificationService(
        workbench_client.files_and_folders,
        workbench_client.components,
    )
