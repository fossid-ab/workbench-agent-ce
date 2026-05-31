"""
Shared contract assertions for API unit and live tests.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Set

from tests.api.support.contract_specs import CONTRACTS as BASE_CONTRACTS
from tests.api.support.version_contracts import load_contracts_for_version

RECORD_ENV = "WORKBENCH_RECORD_CONTRACTS"
RECORDED_DIR = Path(__file__).parent / "recorded"


def _contracts_for_version(workbench_version: str) -> Dict[str, Dict[str, Any]]:
    if workbench_version:
        return load_contracts_for_version(workbench_version)
    return {k: dict(v) for k, v in BASE_CONTRACTS.items()}


def assert_contract(
    operation_id: str,
    response: Dict[str, Any],
    *,
    workbench_version: str = "",
    data: Any = None,
) -> None:
    """
    Assert an API response matches the contract for operation_id.

    Args:
        operation_id: Key in CONTRACTS (e.g. components.list_components)
        response: Full API JSON response with status and data
        workbench_version: Server version string for error messages
        data: Optional override for data (when testing client return values)
    """
    spec = _contracts_for_version(workbench_version).get(operation_id)
    if spec is None:
        raise AssertionError(f"No contract defined for {operation_id}")

    if workbench_version:
        version_hint = f" (workbench {workbench_version})"
    else:
        version_hint = ""

    assert response.get("status") == "1", (
        f"Expected status '1' for {operation_id}{version_hint}, "
        f"got {response.get('status')!r}: {response.get('error')}"
    )

    payload = data if data is not None else response.get("data")
    shape = spec.get("data_shape", "any")

    _assert_data_shape(operation_id, payload, shape, spec, version_hint)

    if os.environ.get(RECORD_ENV, "").lower() in ("1", "true", "yes"):
        _record_response(operation_id, workbench_version, response)


def assert_data_contract(
    operation_id: str,
    data: Any,
    *,
    workbench_version: str = "",
) -> None:
    """Assert contract against data only (no status wrapper)."""
    assert_contract(
        operation_id,
        {"status": "1", "data": data},
        workbench_version=workbench_version,
        data=data,
    )


def _assert_data_shape(
    operation_id: str,
    payload: Any,
    shape: str,
    spec: Dict[str, Any],
    version_hint: str,
) -> None:
    if shape == "null":
        assert payload is None, (
            f"{operation_id}{version_hint}: expected null, got {type(payload)}"
        )
        return

    if shape == "bool":
        assert isinstance(payload, bool), (
            f"{operation_id}{version_hint}: expected bool, got {type(payload)}"
        )
        return

    if shape == "list":
        assert isinstance(payload, list), (
            f"{operation_id}{version_hint}: expected list, got {type(payload)}"
        )
        _assert_list_items(operation_id, payload, spec, version_hint)
        return

    if shape == "dict":
        assert isinstance(payload, dict), (
            f"{operation_id}{version_hint}: expected dict, got {type(payload)}"
        )
        _assert_dict_keys(operation_id, payload, spec, version_hint)
        if "list" in spec.get("required_keys", set()) and "list" in payload:
            usage_list = payload["list"]
            if isinstance(usage_list, list):
                list_keys: Set[str] = spec.get("list_item_keys", set())
                for item in usage_list[:5]:
                    if isinstance(item, dict) and list_keys:
                        missing = list_keys - item.keys()
                        assert not missing, (
                            f"{operation_id}{version_hint}: "
                            f"usage list item missing {missing}"
                        )
            elif isinstance(usage_list, dict) and usage_list:
                first = next(iter(usage_list.values()))
                if isinstance(first, dict):
                    list_keys = spec.get("list_item_keys", set())
                    if list_keys:
                        missing = list_keys - first.keys()
                        assert not missing, (
                            f"{operation_id}{version_hint}: "
                            f"usage dict item missing {missing}"
                        )
        return

    if shape == "list_or_dict":
        if isinstance(payload, list):
            _assert_list_items(operation_id, payload, spec, version_hint)
        elif isinstance(payload, dict):
            count_keys = spec.get("count_only_keys", set())
            if count_keys and count_keys <= payload.keys():
                return
            _assert_dict_keys(operation_id, payload, spec, version_hint)
        elif spec.get("count_only_keys") and isinstance(payload, (str, int)):
            # 2026.1: count_results=1 may return data as a numeric string
            return
        else:
            raise AssertionError(
                f"{operation_id}{version_hint}: expected list or dict, "
                f"got {type(payload)}"
            )
        return

    if shape == "list_or_bool":
        if isinstance(payload, list):
            _assert_list_items(operation_id, payload, spec, version_hint)
        elif isinstance(payload, bool):
            return
        else:
            raise AssertionError(
                f"{operation_id}{version_hint}: expected list or bool, "
                f"got {type(payload)}"
            )
        return

    if shape == "any":
        return

    raise AssertionError(f"Unknown data_shape {shape!r} for {operation_id}")


def _assert_list_items(
    operation_id: str,
    payload: List[Any],
    spec: Dict[str, Any],
    version_hint: str,
) -> None:
    item_keys: Set[str] = spec.get("item_required_keys", set())
    if not item_keys:
        return
    samples = payload[:5] if payload else []
    for item in samples:
        if not isinstance(item, dict):
            continue
        missing = item_keys - item.keys()
        assert not missing, (
            f"{operation_id}{version_hint}: item missing keys {missing}"
        )


def _assert_dict_keys(
    operation_id: str,
    payload: Dict[str, Any],
    spec: Dict[str, Any],
    version_hint: str,
) -> None:
    required: Set[str] = spec.get("required_keys", set())
    if not required:
        return
    missing = required - payload.keys()
    assert not missing, (
        f"{operation_id}{version_hint}: dict missing keys {missing}"
    )


def _record_response(
    operation_id: str,
    workbench_version: str,
    response: Dict[str, Any],
) -> None:
    safe_version = workbench_version.replace("/", "_") or "unknown"
    out_dir = RECORDED_DIR / safe_version
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_op = operation_id.replace(".", "_")
    path = out_dir / f"{safe_op}.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(response, f, indent=2, default=str)
