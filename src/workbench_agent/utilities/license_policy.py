"""
License policy classification for Workbench project policies.

Workbench exports a project's license policy (``download -> licenses_policy_info``)
as a list of rules shaped like ``{"id": "<SPDX id>", "blocked": ..., "reason": ...}``.
This module turns those rules into a lookup that classifies a license id as
allowed, conditional, or prohibited.

The mapping mirrors the FossID toolbox's legacy derivation so the CLI, the IDE
plugin, and the MCP server agree on the same policy:

- ``blocked`` false                                   -> allowed
- ``blocked`` true and reason starts with
  "conditionally approved" / "approved with condition" -> conditional
- any other ``blocked`` true                          -> prohibited

License id matching is case-sensitive.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("workbench-agent")

_CONDITIONAL_PREFIXES = ("conditionally approved", "approved with condition")


class PolicyStatus(str, Enum):
    """Three-way classification of a license against a policy."""

    ALLOWED = "allowed"
    CONDITIONAL = "conditional"
    PROHIBITED = "prohibited"


@dataclass(frozen=True)
class PolicyRule:
    """One normalized license rule."""

    license_id: str
    status: PolicyStatus
    reason: str = ""


def _parse_blocked(value: Any) -> bool:
    """Parse Workbench's ``blocked`` flag tolerantly (bool, int, or string)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes")
    return False


def _derive_status(blocked: bool, reason: str) -> PolicyStatus:
    if not blocked:
        return PolicyStatus.ALLOWED
    if reason.strip().lower().startswith(_CONDITIONAL_PREFIXES):
        return PolicyStatus.CONDITIONAL
    return PolicyStatus.PROHIBITED


class LicensePolicy:
    """License-level policy keyed by license id (case-sensitive)."""

    def __init__(self, rules: Iterable[PolicyRule] = ()) -> None:
        self._rules: Dict[str, PolicyRule] = {}
        for rule in rules:
            self._rules[rule.license_id] = rule

    @classmethod
    def from_workbench_rules(cls, raw_rules: Any) -> "LicensePolicy":
        """
        Build a policy from the parsed ``licenses_policy_info`` payload.

        Malformed entries (non-dicts, missing or empty ``id``) are skipped.
        """
        if not isinstance(raw_rules, list):
            logger.warning(
                "Project license policy has unexpected shape (%s); treating as empty",
                type(raw_rules).__name__,
            )
            return cls()

        rules: List[PolicyRule] = []
        for raw in raw_rules:
            if not isinstance(raw, dict):
                continue
            license_id = raw.get("id")
            if not isinstance(license_id, str) or not license_id.strip():
                continue
            reason = raw.get("reason") or ""
            if not isinstance(reason, str):
                reason = str(reason)
            status = _derive_status(_parse_blocked(raw.get("blocked")), reason)
            rules.append(PolicyRule(license_id.strip(), status, reason.strip()))
        logger.debug("Loaded %d license policy rules", len(rules))
        return cls(rules)

    def __len__(self) -> int:
        return len(self._rules)

    def lookup(self, license_id: str) -> Optional[PolicyRule]:
        """Return the rule for ``license_id``, or None if the policy does not cover it."""
        return self._rules.get(license_id)

    def classify(self, license_id: str) -> Optional[PolicyStatus]:
        """Return the status for ``license_id``, or None if not covered."""
        rule = self.lookup(license_id)
        return rule.status if rule else None
