"""Tests for Workbench license policy classification."""

import pytest

from workbench_agent.utilities.license_policy import LicensePolicy, PolicyStatus


@pytest.mark.unit
class TestLicensePolicy:
    def test_unblocked_rule_is_allowed(self):
        policy = LicensePolicy.from_workbench_rules([{"id": "MIT", "blocked": False, "reason": ""}])
        assert policy.classify("MIT") is PolicyStatus.ALLOWED

    def test_blocked_rule_is_prohibited(self):
        policy = LicensePolicy.from_workbench_rules(
            [{"id": "GPL-3.0-only", "blocked": True, "reason": "Strong copyleft"}]
        )
        rule = policy.lookup("GPL-3.0-only")
        assert rule.status is PolicyStatus.PROHIBITED
        assert rule.reason == "Strong copyleft"

    @pytest.mark.parametrize(
        "reason",
        [
            "Conditionally approved: notify legal",
            "conditionally approved",
            "Approved with conditions for internal tools",
        ],
    )
    def test_conditional_reason_prefixes(self, reason):
        policy = LicensePolicy.from_workbench_rules(
            [{"id": "LGPL-2.1-only", "blocked": True, "reason": reason}]
        )
        assert policy.classify("LGPL-2.1-only") is PolicyStatus.CONDITIONAL

    def test_conditional_prefix_ignored_when_not_blocked(self):
        policy = LicensePolicy.from_workbench_rules(
            [{"id": "MPL-2.0", "blocked": False, "reason": "Conditionally approved"}]
        )
        assert policy.classify("MPL-2.0") is PolicyStatus.ALLOWED

    @pytest.mark.parametrize(
        "blocked, expected",
        [
            ("1", PolicyStatus.PROHIBITED),
            ("0", PolicyStatus.ALLOWED),
            (1, PolicyStatus.PROHIBITED),
            (0, PolicyStatus.ALLOWED),
            ("true", PolicyStatus.PROHIBITED),
            ("false", PolicyStatus.ALLOWED),
            (None, PolicyStatus.ALLOWED),
        ],
    )
    def test_blocked_parsing_is_tolerant(self, blocked, expected):
        policy = LicensePolicy.from_workbench_rules([{"id": "X", "blocked": blocked}])
        assert policy.classify("X") is expected

    def test_matching_is_case_sensitive(self):
        policy = LicensePolicy.from_workbench_rules([{"id": "MIT", "blocked": True}])
        assert policy.classify("mit") is None

    def test_uncovered_license_returns_none(self):
        policy = LicensePolicy.from_workbench_rules([{"id": "MIT", "blocked": False}])
        assert policy.classify("Apache-2.0") is None
        assert policy.lookup("Apache-2.0") is None

    def test_malformed_entries_are_skipped(self):
        policy = LicensePolicy.from_workbench_rules(
            ["junk", None, {"blocked": True}, {"id": "  "}, {"id": 5}, {"id": "MIT"}]
        )
        assert len(policy) == 1
        assert policy.classify("MIT") is PolicyStatus.ALLOWED

    def test_non_list_payload_is_empty_policy(self):
        assert len(LicensePolicy.from_workbench_rules({"unexpected": True})) == 0
