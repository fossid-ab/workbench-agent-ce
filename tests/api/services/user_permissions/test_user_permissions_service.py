"""Tests for UserPermissionsService."""

from unittest.mock import MagicMock

import pytest

from workbench_agent.api.exceptions import ScanNotFoundError
from workbench_agent.api.services.user_permissions import (
    PERMISSION_SCAN_DELETE_ANY,
    UserPermissionsService,
)


def _row(code: str) -> dict:
    return {
        "id": 1,
        "group": "Scans",
        "code": code,
        "name": "x",
        "description": "",
        "created": "",
        "updated": "",
        "role_id": 1,
        "status": None,
    }


def test_can_delete_scan_true_when_global_permission_not_owner():
    """Non-owner delete still works with ``SCAN_DELETE_ANY`` (after scan fetch)."""
    users = MagicMock()
    users.get_user_permissions_list.return_value = [
        _row("SCAN_ACCESS"),
        _row(PERMISSION_SCAN_DELETE_ANY),
    ]
    scans = MagicMock()
    scans.get_information.return_value = {"username": "other@example.com"}
    svc = UserPermissionsService(users, scans, api_user="u@example.com")

    assert svc.can_delete_scan("SCN-1") is True
    scans.get_information.assert_called_once_with("SCN-1")
    users.get_user_permissions_list.assert_called_once()


def test_can_delete_scan_false_without_global_or_creator():
    users = MagicMock()
    users.get_user_permissions_list.return_value = [_row("SCAN_ACCESS")]
    scans = MagicMock()
    scans.get_information.return_value = {"username": "other@example.com"}
    svc = UserPermissionsService(users, scans, api_user="u@example.com")

    assert svc.can_delete_scan("SCN-1") is False
    scans.get_information.assert_called_once_with("SCN-1")
    users.get_user_permissions_list.assert_called_once()


def test_can_delete_scan_true_when_scan_username_matches():
    """``scans/get_information`` exposes the owning user as ``username``."""
    users = MagicMock()
    users.get_user_permissions_list.return_value = [_row("SCAN_ACCESS")]
    scans = MagicMock()
    scans.get_information.return_value = {
        "username": "u@example.com",
    }
    svc = UserPermissionsService(users, scans, api_user="u@example.com")

    assert svc.can_delete_scan("SCN-1") is True
    scans.get_information.assert_called_once_with("SCN-1")
    users.get_user_permissions_list.assert_not_called()


def test_can_delete_scan_scan_not_found_propagates():
    users = MagicMock()
    users.get_user_permissions_list.return_value = [_row("SCAN_ACCESS")]
    scans = MagicMock()
    scans.get_information.side_effect = ScanNotFoundError("missing")

    svc = UserPermissionsService(users, scans, api_user="u@example.com")
    with pytest.raises(ScanNotFoundError):
        svc.can_delete_scan("nope")


def test_permissions_cached():
    users = MagicMock()
    users.get_user_permissions_list.return_value = [
        _row(PERMISSION_SCAN_DELETE_ANY),
    ]
    scans = MagicMock()
    svc = UserPermissionsService(users, scans, api_user="u@example.com")

    assert svc.can_delete_scan("a") is True
    assert svc.can_delete_scan("b") is True
    users.get_user_permissions_list.assert_called_once()


def test_invalidate_cache_refetches():
    users = MagicMock()
    users.get_user_permissions_list.return_value = [_row("SCAN_ACCESS")]
    scans = MagicMock()
    scans.get_information.return_value = {"username": "other@example.com"}
    svc = UserPermissionsService(users, scans, api_user="u@example.com")
    assert svc.can_delete_scan("x") is False

    users.get_user_permissions_list.return_value = [
        _row(PERMISSION_SCAN_DELETE_ANY),
    ]
    svc.invalidate_cache()
    assert svc.can_delete_scan("x") is True
    assert users.get_user_permissions_list.call_count == 2


def test_has_permission_code_and_permission_codes():
    users = MagicMock()
    users.get_user_permissions_list.return_value = [_row("PROJECT_ACCESS_ANY")]
    svc = UserPermissionsService(users, MagicMock(), api_user="a")

    assert svc.has_permission_code("PROJECT_ACCESS_ANY") is True
    assert svc.has_permission_code("OTHER") is False
    assert svc.permission_codes() == {"PROJECT_ACCESS_ANY"}


def test_api_user_property():
    svc = UserPermissionsService(MagicMock(), MagicMock(), api_user="me@test")
    assert svc.api_user == "me@test"


def test_get_user_permissions_list_propagates():
    users = MagicMock()
    users.get_user_permissions_list.side_effect = ValueError("exactly one")
    svc = UserPermissionsService(users, MagicMock(), api_user="a")

    with pytest.raises(ValueError, match="exactly one"):
        svc.can_delete_scan("sc")
