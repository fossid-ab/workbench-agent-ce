"""Load per-Workbench-version API response contracts."""

import json
from pathlib import Path
from typing import Any, Dict, Optional, Set

CONTRACTS_DIR = Path(__file__).parent / "contracts"
FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Fallback when no version file exists (minimal checks).
from tests.api.support.contract_specs import CONTRACTS as BASE_CONTRACTS


def _normalize_sets(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Convert JSON list fields to sets for contract assertion code."""
    out = dict(spec)
    for key in (
        "item_required_keys",
        "required_keys",
        "count_only_keys",
        "list_item_keys",
    ):
        if key in out and isinstance(out[key], list):
            out[key] = set(out[key])
    return out


def load_contracts_for_version(version: str) -> Dict[str, Dict[str, Any]]:
    """
    Merge base contracts with version-specific overrides.

    Args:
        version: Normalized MAJOR.MINOR.PATCH (e.g. ``2026.1.0``).

    Returns:
        operation_id -> contract spec dict.
    """
    merged = {k: dict(v) for k, v in BASE_CONTRACTS.items()}
    path = CONTRACTS_DIR / f"{version}.json"
    if not path.is_file():
        return merged
    with path.open(encoding="utf-8") as f:
        doc = json.load(f)
    for op_id, spec in doc.get("contracts", {}).items():
        merged[op_id] = _normalize_sets(spec)
    return merged


def fixtures_dir_for_version(version: str) -> Optional[Path]:
    """Return committed JSON fixture directory for a Workbench version."""
    path = FIXTURES_DIR / version
    return path if path.is_dir() else None


def load_fixture(version: str, name: str) -> Dict[str, Any]:
    """Load a recorded API response fixture (for unit/smoke tests)."""
    path = FIXTURES_DIR / version / f"{name}.json"
    if not path.is_file():
        raise FileNotFoundError(f"No fixture: {path}")
    with path.open(encoding="utf-8") as f:
        return json.load(f)
