"""Live VulnerabilitiesClient mutation tests (VEX create/update)."""

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
    for key in ("component_id", "componentId"):
        value = row.get(key)
        if value is not None:
            return int(value)
    return None


@pytest.mark.usefixtures("allow_mutations", "scan_has_vulnerabilities")
class TestVulnerabilitiesLiveMutations:
    def test_create_and_update_vex(
        self,
        workbench_client,
        workbench_version,
        scan_has_vulnerabilities,
    ):
        scan_code = scan_has_vulnerabilities["scan_code"]
        row = scan_has_vulnerabilities["vulnerabilities"][0]
        cve = _cve_from_row(row)
        component_id = _component_id_from_row(row)
        assert cve
        assert component_id is not None

        info = workbench_client.vulnerabilities.get_information(cve)
        vex_rows = info.get("component_vulnerability_in_scans") or []
        existing = [
            r
            for r in vex_rows
            if str(r.get("cve")) == cve
            and int(r.get("component_id", 0)) == component_id
            and r.get("code") == scan_code
        ]
        if existing:
            vuln_exp_id = int(existing[0]["id"])
        else:
            create_response = workbench_client.vulnerabilities._api._send_request(
                {
                    "group": "vulnerabilities",
                    "action": "vulnerability_exploitability_create",
                    "data": {
                        "scan_code": scan_code,
                        "component_id": component_id,
                        "cve": cve,
                        "vuln_exp_status": "not_affected",
                        "vuln_exp_justification": "code_not_reachable",
                        "vuln_exp_response": "will_not_fix",
                        "vuln_exp_details": "api live test",
                    },
                }
            )
            assert_contract(
                "vulnerabilities.vulnerability_exploitability_create",
                create_response,
                workbench_version=workbench_version,
            )
            vuln_exp_id = create_response["data"]["id"]

        try:
            update_response = workbench_client.vulnerabilities._api._send_request(
                {
                    "group": "vulnerabilities",
                    "action": "vulnerability_exploitability_update",
                    "data": {
                        "vuln_exp_id": vuln_exp_id,
                        "vuln_exp_status": "not_affected",
                        "vuln_exp_details": "api live test updated",
                    },
                }
            )
            assert_contract(
                "vulnerabilities.vulnerability_exploitability_update",
                update_response,
                workbench_version=workbench_version,
            )

            info = workbench_client.vulnerabilities.get_information(cve)
            vex_rows = info.get("component_vulnerability_in_scans") or []
            matching = [
                r
                for r in vex_rows
                if str(r.get("cve")) == cve and int(r.get("component_id", 0)) == component_id
            ]
            assert matching, "Expected VEX row after create/update"
        finally:
            workbench_client.vulnerabilities.update_vulnerability_exploitability(
                vuln_exp_id,
                vuln_exp_status="not_affected",
                vuln_exp_details="api live test cleanup",
            )

    def test_import_vex_from_identified_to_da_scan(
        self,
        workbench_client,
        workbench_version,
        identified_test_scan_code,
        dependency_analysis_test_scan_code,
        scan_has_vulnerabilities,
    ):
        if scan_has_vulnerabilities["scan_code"] != identified_test_scan_code:
            pytest.skip("VEX import probe requires vulnerabilities on Identified Test Scan")

        response = workbench_client.vulnerabilities._api._send_request(
            {
                "group": "vulnerabilities",
                "action": "import_vulnerability_exploitability_from_scan",
                "data": {
                    "scan_code_from": identified_test_scan_code,
                    "scan_code_to": dependency_analysis_test_scan_code,
                    "override_vex": "0",
                },
            }
        )
        assert_contract(
            "vulnerabilities.import_vulnerability_exploitability_from_scan",
            response,
            workbench_version=workbench_version,
        )
        result = workbench_client.vulnerabilities.import_vulnerability_exploitability_from_scan(
            identified_test_scan_code,
            dependency_analysis_test_scan_code,
            override_vex=False,
        )
        assert isinstance(result["data"], list)
        assert result.get("message")
