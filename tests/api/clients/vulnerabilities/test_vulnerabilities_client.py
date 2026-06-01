# tests/api/clients/vulnerabilities/test_vulnerabilities_client.py

from unittest.mock import patch

import pytest
import requests

from workbench_agent.api.clients.vulnerabilities import VulnerabilitiesClient
from workbench_agent.api.exceptions import ApiError
from workbench_agent.api.base_api import BaseAPI


@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch("requests.Session", return_value=mock_sess)
    return mock_sess


@pytest.fixture
def base_api(mock_session):
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return api


@pytest.fixture
def vulnerabilities_client(base_api):
    return VulnerabilitiesClient(base_api)


@patch.object(BaseAPI, "_send_request")
def test_list_vulnerabilities_returns_page_data(
    mock_send, vulnerabilities_client
):
    mock_send.return_value = {
        "status": "1",
        "data": {
            "list": [
                {"id": 1, "severity": "HIGH", "component": "libxml2"},
                {"id": 2, "severity": "MEDIUM", "component": "openssl"},
            ]
        },
    }

    data = vulnerabilities_client.list_vulnerabilities(
        scan_code="scan1",
        page=1,
    )

    assert data["list"][0]["id"] == 1
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "vulnerabilities"
    assert payload["action"] == "list_vulnerabilities"
    assert payload["data"]["scan_code"] == "scan1"
    assert payload["data"]["page"] == "1"


@patch.object(BaseAPI, "_send_request")
def test_list_vulnerabilities_count_shape(mock_send, vulnerabilities_client):
    mock_send.return_value = {"status": "1", "data": {"count_results": 42}}

    data = vulnerabilities_client.list_vulnerabilities(
        scan_code="scan1",
        count_results=True,
    )

    assert data == {"count_results": 42}
    assert mock_send.call_args[0][0]["data"]["count_results"] == "1"


@patch.object(BaseAPI, "_send_request")
def test_list_vulnerabilities_project_scope(mock_send, vulnerabilities_client):
    mock_send.return_value = {"status": "1", "data": {"count_results": 0}}

    data = vulnerabilities_client.list_vulnerabilities(
        project_code="proj1",
        count_results=True,
    )

    assert data["count_results"] == 0
    assert mock_send.call_args[0][0]["data"]["project_code"] == "proj1"
    assert "scan_code" not in mock_send.call_args[0][0]["data"]


@patch.object(BaseAPI, "_send_request")
def test_list_vulnerabilities_with_search_value(
    mock_send, vulnerabilities_client
):
    mock_send.return_value = {
        "status": "1",
        "data": {"list": [{"cve": "CVE-2020-1"}]},
    }

    data = vulnerabilities_client.list_vulnerabilities(
        scan_code="scan1",
        search_value="openssl,1.1.1",
    )

    assert data["list"][0]["cve"] == "CVE-2020-1"
    assert mock_send.call_args[0][0]["data"]["search_value"] == "openssl,1.1.1"


@patch.object(BaseAPI, "_send_request")
def test_list_vulnerabilities_api_error(mock_send, vulnerabilities_client):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}

    with pytest.raises(ApiError, match="Failed to list vulnerabilities"):
        vulnerabilities_client.list_vulnerabilities(scan_code="scan1")


@patch.object(BaseAPI, "_send_request")
def test_get_information(mock_send, vulnerabilities_client):
    mock_send.return_value = {
        "status": "1",
        "data": {
            "cve": [{"id": "CVE-2020-1234"}],
            "component_vulnerability_in_scans": [],
        },
    }

    info = vulnerabilities_client.get_information("CVE-2020-1234")

    assert info["cve"]
    payload = mock_send.call_args[0][0]
    assert payload["action"] == "get_information"
    assert payload["data"]["cve"] == "CVE-2020-1234"


@patch.object(BaseAPI, "_send_request")
def test_create_vulnerability_exploitability(mock_send, vulnerabilities_client):
    mock_send.return_value = {"status": "1", "data": {"id": 99}}

    result = vulnerabilities_client.create_vulnerability_exploitability(
        scan_code="scan1",
        component_id=1,
        cve="CVE-2020-1234",
        vuln_exp_status="not_affected",
        vuln_exp_justification="code_not_present",
    )

    assert result["id"] == 99
    payload = mock_send.call_args[0][0]
    assert payload["action"] == "vulnerability_exploitability_create"


@patch.object(BaseAPI, "_send_request")
def test_update_vulnerability_exploitability(mock_send, vulnerabilities_client):
    mock_send.return_value = {"status": "1", "data": None, "message": "ok"}

    result = vulnerabilities_client.update_vulnerability_exploitability(
        42,
        vuln_exp_status="exploitable",
    )

    assert result["message"] == "ok"
    payload = mock_send.call_args[0][0]
    assert payload["action"] == "vulnerability_exploitability_update"
    assert payload["data"]["vuln_exp_id"] == 42


@patch.object(BaseAPI, "_send_request")
def test_import_vulnerability_exploitability_from_scan(
    mock_send, vulnerabilities_client
):
    mock_send.return_value = {
        "status": "1",
        "data": [{"id": 1}],
        "message": "done",
    }

    result = (
        vulnerabilities_client.import_vulnerability_exploitability_from_scan(
            "source",
            "target",
            override_vex=False,
        )
    )

    assert result["data"] == [{"id": 1}]
    assert result["message"] == "done"
