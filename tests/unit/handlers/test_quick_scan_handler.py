"""Tests for the quick-scan handler."""

import argparse
import copy
import json
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.api.exceptions import ApiError, ProjectNotFoundError
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

    def test_detected_licenses_are_ignored(self):
        result = copy.deepcopy(NCLICK)
        result["component"]["licenses"].append({"id": "GPL-3.0-only", "type": "LICENSE"})
        policy = LicensePolicy.from_workbench_rules(
            [
                {"id": "MIT", "blocked": False, "reason": ""},
                {"id": "GPL-3.0-only", "blocked": True, "reason": "Strong copyleft"},
            ]
        )
        lines = _format_scan_result(result, policy)
        assert "  License:    MIT" in lines
        assert not any("GPL-3.0-only" in line for line in lines)

    def test_no_primary_license_ignores_detected(self):
        result = copy.deepcopy(NCLICK)
        del result["component"]["license"]
        text = "\n".join(_format_scan_result(result, LicensePolicy()))
        assert "License:" not in text
        assert "No license detected" in text

    def test_conditional_warning(self):
        policy = LicensePolicy.from_workbench_rules(
            [{"id": "MIT", "blocked": True, "reason": "Conditionally approved: attribution"}]
        )
        text = "\n".join(_format_scan_result(NCLICK, policy))
        assert "  ⚠ Conditionally approved: MIT (Conditionally approved: attribution)" in text
        assert "Prohibited" not in text

    def test_uncovered_license_note(self):
        text = "\n".join(_format_scan_result(NCLICK, LicensePolicy()))
        assert "  ℹ Not in policy: MIT" in text

    def test_category_reason_is_condensed(self):
        policy = LicensePolicy.from_workbench_rules(
            [
                {
                    "id": "MIT",
                    "blocked": True,
                    "reason": "A Workbench policy with Rule Type 'Category' and condition: "
                    "'STRONG_COPYLEFT' is prohibiting this license",
                }
            ]
        )
        text = "\n".join(_format_scan_result(NCLICK, policy))
        assert "  ⚠ Prohibited by policy: MIT (strong copyleft)" in text
        assert "Rule Type" not in text

    def test_allowed_only_has_no_trailing_blank_line(self):
        policy = LicensePolicy.from_workbench_rules([{"id": "MIT", "blocked": False}])
        lines = _format_scan_result(NCLICK, policy)
        assert lines[-1].strip() != ""
        assert not any("⚠" in line or "ℹ" in line for line in lines)

    def test_no_license_with_policy(self):
        result = {"type": "file", "component": {"artifact": "libfoo"}}
        text = "\n".join(_format_scan_result(result, LicensePolicy()))
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
        assert "--- Matches ---" in out

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
        assert out.count("⚠ Prohibited by policy: MIT (Not allowed here)") == 2
        assert "⚠ 2 of 2 have prohibited licenses: MIT (matches 1, 2)" in out
        # Policy evaluation is its own section, printed before the matches
        # Resolution note first, then matches, then the policy evaluation section
        assert (
            out.index("Matches will be checked against project 'acme' license policy.")
            < out.index("Performing quick scan...")
            < out.index("--- Matches ---")
            < out.index("Match 2 of 2")
            < out.index("--- Policy Evaluation ---")
            < out.index("Project 'acme': 2 matches checked")
        )

    def test_summary_when_no_policy_issues(self, client, params, capsys):
        params.project_name = "acme"
        client.policy.download_project_policy_json.return_value = [{"id": "MIT", "blocked": False}]
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.return_value = "PRJ-1"
            assert handle_quick_scan(client, params) is True
        out = capsys.readouterr().out
        assert (
            "Project 'acme': no prohibited or conditionally approved licenses in 2 matches." in out
        )

    def test_summary_for_single_match(self, client, params, capsys):
        params.project_name = "acme"
        client.quick_scan.scan_one_file.return_value = [copy.deepcopy(NCLICK)]
        client.policy.download_project_policy_json.return_value = [{"id": "MIT", "blocked": True}]
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.return_value = "PRJ-1"
            handle_quick_scan(client, params)
        out = capsys.readouterr().out
        assert "⚠ Prohibited by policy: MIT" in out
        assert "⚠ 1 of 1 have prohibited licenses: MIT (match 1)" in out
        assert "Project 'acme': 1 match checked" in out

    def test_conditional_summary_cites_matches(self, client, params, capsys):
        params.project_name = "acme"
        client.quick_scan.scan_one_file.return_value = [
            copy.deepcopy(NCLICK),
            {"type": "file", "component": {"artifact": "x", "license": "LGPL-2.1-only"}},
        ]
        client.policy.download_project_policy_json.return_value = [
            {"id": "LGPL-2.1-only", "blocked": True, "reason": "Conditionally approved: linking"}
        ]
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.return_value = "PRJ-1"
            handle_quick_scan(client, params)
        out = capsys.readouterr().out
        assert "⚠ 1 of 2 have conditionally approved licenses: LGPL-2.1-only (match 2)" in out
        assert "prohibited licenses" not in out

    def test_project_code_used_as_label(self, client, params, capsys):
        params.project_code = "PRJ-9"
        client.policy.download_project_policy_json.return_value = [{"id": "MIT", "blocked": False}]
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.return_value = "PRJ-9"
            handle_quick_scan(client, params)
        resolver_cls.return_value.find_project.assert_called_once_with(name=None, code="PRJ-9")
        out = capsys.readouterr().out
        assert "Loading license policy" not in out
        assert "Project 'PRJ-9': no prohibited" in out

    def test_resolve_before_scan_download_after(self, client, params):
        params.project_name = "acme"
        calls = []
        client.quick_scan.scan_one_file.side_effect = lambda *a, **k: calls.append("scan") or [
            copy.deepcopy(NCLICK)
        ]
        client.policy.download_project_policy_json.side_effect = (
            lambda code: calls.append("download") or []
        )
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.side_effect = (
                lambda **k: calls.append("resolve") or "PRJ-1"
            )
            handle_quick_scan(client, params)
        assert calls == ["resolve", "scan", "download"]

    def test_project_lookup_error_is_reported(self, client, params, capsys):
        params.project_name = "acme"
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.side_effect = ApiError("timeout")
            assert handle_quick_scan(client, params) is True
        out = capsys.readouterr().out
        assert "Project 'acme': could not be looked up (timeout)." in out
        assert "Matches will be checked" not in out
        client.policy.download_project_policy_json.assert_not_called()

    def test_project_not_found_is_reported_not_raised(self, client, params, capsys):
        params.project_name = "missing"
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.side_effect = ProjectNotFoundError("nope")
            assert handle_quick_scan(client, params) is True
        client.policy.download_project_policy_json.assert_not_called()
        client.projects.create.assert_not_called()
        out = capsys.readouterr().out
        assert "Project 'missing': not found, so the license policy was not checked." in out
        assert "Matches will be checked" not in out
        assert "Component:  nclick 0.0.0" in out
        assert "⚠" not in out and "ℹ" not in out

    def test_empty_policy_is_reported(self, client, params, capsys):
        params.project_name = "acme"
        client.policy.download_project_policy_json.return_value = []
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.return_value = "PRJ-1"
            assert handle_quick_scan(client, params) is True
        out = capsys.readouterr().out
        assert "Project 'acme': no license policy defined." in out
        assert "Not in policy" not in out

    def test_policy_download_error_is_reported(self, client, params, capsys):
        params.project_name = "acme"
        client.policy.download_project_policy_json.side_effect = ApiError("server said no")
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.return_value = "PRJ-1"
            assert handle_quick_scan(client, params) is True
        out = capsys.readouterr().out
        assert "Project 'acme': could not load the license policy (server said no)." in out
        assert "Match 2 of 2" in out

    def test_no_matches_skips_policy(self, client, params, capsys):
        params.project_name = "acme"
        client.quick_scan.scan_one_file.return_value = []
        with patch("workbench_agent.handlers.quick_scan.ResolverService") as resolver_cls:
            resolver_cls.return_value.find_project.return_value = "PRJ-1"
            assert handle_quick_scan(client, params) is True
        client.policy.download_project_policy_json.assert_not_called()
        assert "Policy Evaluation" not in capsys.readouterr().out

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
        assert "Prohibited by policy" not in out
        assert "Policy Evaluation" not in out
        resolver_cls.assert_not_called()
        client.policy.download_project_policy_json.assert_not_called()
        payload = out[out.index("[") : out.rindex("]") + 1]
        assert json.loads(payload)[1]["component"]["artifact"] == "rumboost"
