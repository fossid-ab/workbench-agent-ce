"""Tests for ComponentService."""

from unittest.mock import MagicMock

import pytest

from workbench_agent.api.services.component_service import ComponentService


@pytest.fixture
def component_service():
    components = MagicMock()
    return ComponentService(components)


def test_find_delegates(component_service):
    component_service._components.get_information.return_value = {"name": "ofp"}
    result = component_service.find("ofp", "1.1")
    assert result["name"] == "ofp"
    component_service._components.get_information.assert_called_once_with("ofp", "1.1")


def test_exists_true_when_found(component_service):
    component_service._components.get_information.return_value = {"name": "ofp"}
    assert component_service.exists("ofp", "1.1") is True


def test_exists_false_when_missing(component_service):
    component_service._components.get_information.return_value = None
    assert component_service.exists("ofp", "1.1") is False


def test_resolve_skips_create_when_exists(component_service):
    component_service._components.get_information.return_value = {
        "name": "ofp",
        "supplier_name": "OpenFastPath",
    }
    result = component_service.resolve("ofp", "1.1", "BSD-3-Clause", supplier_name="Fallback")
    assert result["created"] is False
    assert result["supplier_name"] == "OpenFastPath"
    component_service._components.create.assert_not_called()


def test_resolve_creates_when_missing(component_service):
    component_service._components.get_information.return_value = None
    component_service._components.create.return_value = {"data": {"component_id": 1}}
    result = component_service.resolve(
        "ofp",
        "1.1",
        "MIT",
        supplier_name="OpenFastPath",
        purl="pkg:generic/ofp@1.1",
    )
    assert result["created"] is True
    component_service._components.create.assert_called_once_with(
        name="ofp",
        version="1.1",
        license_identifier="MIT",
        sup_com_name="OpenFastPath",
        purl="pkg:generic/ofp@1.1",
    )


def test_resolve_requires_license(component_service):
    with pytest.raises(ValueError, match="license_identifier is required"):
        component_service.resolve("ofp", "1.1", "")


def test_resolve_requires_name_and_version(component_service):
    with pytest.raises(ValueError, match="component_name and component_version"):
        component_service.resolve("", "1.1", "MIT")
