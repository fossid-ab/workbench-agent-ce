"""Live contract tests for VulnerabilitiesClient."""

import pytest

from tests.api.support.contract import assert_contract

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


def _cve_from_row(row: dict) -> str | None:
    for key in ("cve", "CVE", "cve_id"):
        value = row.get(key)
        if value:
            return str(value)
    return None


def _component_id_from_row(row: dict):
    for key in ("component_id", "componentId", "id"):
        value = row.get(key)
        if key == "id" and "cve" in row:
            continue
        if value is not None:
            return int(value)
    return None


@pytest.mark.usefixtures("scan_has_vulnerabilities")
class TestVulnerabilitiesLiveReadOnly:
    def test_list_vulnerabilities_contract(
        self,
        workbench_client,
        workbench_version,
        scan_has_vulnerabilities,
    ):
        scan_code = scan_has_vulnerabilities["scan_code"]
        response = workbench_client.vulnerabilities._api._send_request(
            {
                "group": "vulnerabilities",
                "action": "list_vulnerabilities",
                "data": {"scan_code": scan_code, "page": 1},
            }
        )
        assert_contract(
            "vulnerabilities.list_vulnerabilities",
            response,
            workbench_version=workbench_version,
        )
        listed = workbench_client.vulnerability.list_scan_vulnerabilities(scan_code)
        assert listed == scan_has_vulnerabilities["vulnerabilities"]
        assert len(listed) >= 1

    def test_list_on_identified_scan(
        self,
        workbench_client,
        identified_test_scan_code,
        scan_has_identified,
    ):
        vulns = workbench_client.vulnerability.list_scan_vulnerabilities(identified_test_scan_code)
        if not vulns:
            pytest.skip(
                "Identified Test Scan has no vulnerabilities "
                "(KB/DA CVE data may be absent on this Workbench)"
            )
        assert _cve_from_row(vulns[0])

    def test_list_on_dependency_analysis_scan(
        self,
        workbench_client,
        dependency_analysis_test_scan_code,
        scan_has_da_results,
    ):
        vulns = workbench_client.vulnerability.list_scan_vulnerabilities(
            dependency_analysis_test_scan_code
        )
        if not vulns:
            pytest.skip(
                "Dependency Analysis Test Scan has no vulnerabilities "
                "(CVE feed may not match DA components on this Workbench)"
            )
        assert _cve_from_row(vulns[0])

    def test_list_vulnerabilities_count_results_shape(
        self,
        workbench_client,
        workbench_version,
        scan_has_vulnerabilities,
    ):
        scan_code = scan_has_vulnerabilities["scan_code"]
        response = workbench_client.vulnerabilities._api._send_request(
            {
                "group": "vulnerabilities",
                "action": "list_vulnerabilities",
                "data": {"scan_code": scan_code, "count_results": "1"},
            }
        )
        assert_contract(
            "vulnerabilities.list_vulnerabilities",
            response,
            workbench_version=workbench_version,
        )
        data = response["data"]
        assert isinstance(data, dict)
        assert isinstance(data["count_results"], int)

        client_data = workbench_client.vulnerabilities.list_vulnerabilities(
            scan_code=scan_code,
            count_results=True,
        )
        assert client_data == data

        count = workbench_client.vulnerability.count_scan_vulnerabilities(scan_code)
        assert count == data["count_results"]
        assert count == len(scan_has_vulnerabilities["vulnerabilities"])

    def test_get_information_for_listed_cve(
        self,
        workbench_client,
        workbench_version,
        scan_has_vulnerabilities,
    ):
        row = scan_has_vulnerabilities["vulnerabilities"][0]
        cve = _cve_from_row(row)
        assert cve

        response = workbench_client.vulnerabilities._api._send_request(
            {
                "group": "vulnerabilities",
                "action": "get_information",
                "data": {"cve": cve},
            }
        )
        assert_contract(
            "vulnerabilities.get_information",
            response,
            workbench_version=workbench_version,
        )

        data = workbench_client.vulnerabilities.get_information(cve)
        assert isinstance(data.get("cve"), list)
        assert isinstance(data.get("component_vulnerability_in_scans"), list)
