"""Tests for the quick-scan handler."""

import argparse
import copy
import json
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.api.exceptions import ProjectNotFoundError
from workbench_agent.handlers.quick_scan import _format_scan_result, handle_quick_scan
from workbench_agent.utilities.license_policy import LicensePolicy

# Trimmed from a live Workbench response: one snippet matching two components.
NCLICK = {
    "type": "partial",
    "component": {
        "author": "copypaste",
        "artifact": "nclick",
        "version": "0.0.0",
        "purl": "pkg:pypi/nclick@0.0.0",
        "license": "MIT",
        "licenses": [
            {"id": "MIT", "source": "kb", "type": "DECLARED"},
            {"id": "MIT", "name": "MIT License", "type": "REFERENCE"},
        ],
    },
    "snippet": {"remote_size": 35, "local_coverage": 0.8974},
    "file": {"path": "nclick/model/cv.py"},
}
RUMBOOST = {
    "type": "partial",
    "component": {
        "author": "Nicolas Salvadé, Tim Hillel",
        "artifact": "rumboost",
        "version": "1.0.0",
        "purl": "pkg:pypi/rumboost@1.0.0",
        "license": "MIT",
        "licenses": [{"id": "MIT", "name": "MIT License", "type": "LICENSE"}],
        "copyright": [{"default": "Copyright 2023 Nicolas Salvadé", "name": "Nicolas Salvadé"}],
    },
    "snippet": {"remote_size": 35, "local_coverage": 0.8974},
    "file": {"path": "rumboost/utils.py"},
}


@pytest.fixture
def scan_file(tmp_path):
    path = tmp_path / "runner.py"
    path.write_text("print('hello')\n")
    return str(path)


@pytest.fixture
def params(scan_file):
    ns = argparse.Namespace()
    ns.command = "quick-scan"
    ns.path = scan_file
    ns.limit = 1
    ns.sensitivity = 10
    ns.raw = False
    ns.project_name = None
    ns.project_code = None
    return ns


@pytest.fixture
def client():
    mock = MagicMock()
    mock.quick_scan.scan_one_file.return_value = [copy.deepcopy(NCLICK), copy.deepcopy(RUMBOOST)]
    mock.policy.download_project_policy_json.return_value = []
    return mock


@pytest.mark.unit
class TestFormatScanResult:
    def test_partial_match_block(self):
        text = "\n".join(_format_scan_result(NCLICK))
        assert (
            "This file has a partial match to an open source component "
            "(35 snippet hits, 90% of this file)." in text
        )
        assert "Component:  nclick 0.0.0" in text
        assert "Supplier:   copypaste" in text
        assert "License:    MIT" in text
        assert "also detected" not in text  # duplicate MIT ids collapse
        assert "Package:    pkg:pypi/nclick@0.0.0" in text
        assert "Matched:    nclick/model/cv.py" in text

    def test_missing_copyright_line_is_omitted(self):
        assert not any("Copyright" in line for line in _format_scan_result(NCLICK))

    def test_copyright_is_shown_when_present(self):
        text = "\n".join(_format_scan_result(RUMBOOST))
        assert "Copyright:  Copyright 2023 Nicolas Salvadé" in text

    def test_full_file_match(self):
        result = {"type": "file", "component": {"artifact": "libfoo", "author": "Foo"}}
        lines = _format_scan_result(result)
        assert lines[0] == "This entire file matches an open source component."
        assert any("Component:  libfoo" in line for line in lines)
        assert not any("License" in line for line in lines)

    def test_unknown_type_and_missing_component(self):
        assert _format_scan_result({"type": "weird", "component": {"artifact": "x"}})[0] == (
            "Unknown match type."
        )
        assert _format_scan_result({"type": "file"}) == ["No matches found."]

    def test_secondary_license_listed_and_checked(self):
        result = copy.deepcopy(NCLICK)
        result["component"]["licenses"].append({"id": "GPL-3.0-only", "type": "LICENSE"})
        policy = LicensePolicy.from_workbench_rules(
            [
                {"id": "MIT", "blocked": False, "reason": ""},
                {"id": "GPL-3.0-only", "blocked": True, "reason": "Strong copyleft"},
            ]
        )
        text = "\n".join(_format_scan_result(result, policy, "acme"))
        assert "License:    MIT (also detected: GPL-3.0-only)" in text
        assert (
            "⚠ Policy violation: GPL-3.0-only is prohibited in project 'acme' "
            "(reason: Strong copyleft)" in text
        )
        assert "MIT is" not in text  # allowed licenses produce no line

    def test_conditional_warning(self):
        policy = LicensePolicy.from_workbench_rules(
            [{"id": "MIT", "blocked": True, "reason": "Conditionally approved: attribution"}]
        )
        text = "\n".join(_format_scan_result(NCLICK, policy, "acme"))
        assert "⚠ Policy warning: MIT is conditionally approved in project 'acme'" in text
        assert "violation" not in text

    def test_uncovered_license_note(self):
        text = "\n".join(_format_scan_result(NCLICK, LicensePolicy(), "acme"))
        assert "MIT is not covered by the license policy of project 'acme'." in text

    def test_no_license_with_policy(self):
        result = {"type": "file", "component": {"artifact": "libfoo"}}
        text = "\n".join(_format_scan_result(result, LicensePolicy(), "acme"))
        assert "No license detected" in text


@pytest.mark.unit
class TestHandleQuickScan:
    def test_without_project_does_not_resolve_or_download(self, client, params, capsys):
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            assert handle_quick_scan(client, params) is True
        resolver_cls.assert_not_called()
        client.policy.download_project_policy_json.assert_not_called()
        out = capsys.readouterr().out
        assert "Match 1 of 2" in out and "Match 2 of 2" in out
        assert "Policy" not in out

    def test_single_result_has_no_match_header(self, client, params, capsys):
        client.quick_scan.scan_one_file.return_value = [copy.deepcopy(NCLICK)]
        assert handle_quick_scan(client, params) is True
        assert "Match 1 of" not in capsys.readouterr().out

    def test_no_matches(self, client, params, capsys):
        client.quick_scan.scan_one_file.return_value = []
        assert handle_quick_scan(client, params) is True
        assert "No matches found." in capsys.readouterr().out

    def test_project_policy_violation_still_succeeds(self, client, params, capsys):
        params.project_name = "acme"
        client.policy.download_project_policy_json.return_value = [
            {"id": "MIT", "blocked": True, "reason": "Not allowed here"}
        ]
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.return_value = "PRJ-1"
            assert handle_quick_scan(client, params) is True

        resolver_cls.return_value.find_project.assert_called_once_with(name="acme", code=None)
        client.policy.download_project_policy_json.assert_called_once_with("PRJ-1")
        client.projects.create.assert_not_called()
        out = capsys.readouterr().out
        assert out.count("⚠ Policy violation: MIT is prohibited in project 'acme'") == 2

    def test_project_code_used_as_label(self, client, params, capsys):
        params.project_code = "PRJ-9"
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.return_value = "PRJ-9"
            handle_quick_scan(client, params)
        resolver_cls.return_value.find_project.assert_called_once_with(name=None, code="PRJ-9")
        assert "project 'PRJ-9'" in capsys.readouterr().out

    def test_project_not_found_fails_before_scan(self, client, params):
        params.project_name = "missing"
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.side_effect = ProjectNotFoundError("nope")
            with pytest.raises(ProjectNotFoundError):
                handle_quick_scan(client, params)
        client.quick_scan.scan_one_file.assert_not_called()
        client.policy.download_project_policy_json.assert_not_called()
        client.projects.create.assert_not_called()

    def test_raw_output_preserves_unicode_and_skips_blocks(self, client, params, capsys):
        params.raw = True
        params.project_name = "acme"
        client.policy.download_project_policy_json.return_value = [{"id": "MIT", "blocked": True}]
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.return_value = "PRJ-1"
            assert handle_quick_scan(client, params) is True
        out = capsys.readouterr().out
        assert "Salvadé" in out
        assert "\\u00e9" not in out
        assert "Component:" not in out
        assert "Policy violation" not in out
        payload = out[out.index("[") : out.rindex("]") + 1]
        assert json.loads(payload)[1]["component"]["artifact"] == "rumboost"
