"""Unit tests: VulnerabilitiesClient raises ApiError on API failures."""

from unittest.mock import patch

import pytest

from tests.api.support.error_assertions import assert_api_error
from workbench_agent.api.base_api import BaseAPI
from workbench_agent.api.clients.vulnerabilities import VulnerabilitiesClient


@pytest.fixture
def vulnerabilities_client(mock_session):
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return VulnerabilitiesClient(api)


ERROR_RESPONSE = {
    "status": "0",
    "error": "CVE not found",
    "operation": "vulnerabilities_get_information",
}


@patch.object(BaseAPI, "_send_request")
@pytest.mark.parametrize(
    "method_name,kwargs",
    [
        ("get_information", {"cve": "CVE-1999-0001"}),
        (
            "create_vulnerability_exploitability",
            {
                "scan_code": "scan1",
                "component_id": 1,
                "cve": "CVE-1999-0001",
            },
        ),
        ("update_vulnerability_exploitability", {"vuln_exp_id": 1}),
        (
            "import_vulnerability_exploitability_from_scan",
            {"scan_code_from": "a", "scan_code_to": "b"},
        ),
    ],
)
def test_api_errors_raise(mock_send, vulnerabilities_client, method_name, kwargs):
    mock_send.return_value = ERROR_RESPONSE
    assert_api_error(
        lambda: getattr(vulnerabilities_client, method_name)(**kwargs),
    )
