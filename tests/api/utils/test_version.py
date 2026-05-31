"""Tests for workbench_agent.api.utils.version."""

from workbench_agent.api.utils.version import normalize_workbench_version


def test_normalize_2026_1_build_id():
    assert normalize_workbench_version("2026.1.0#25559481630") == "2026.1.0"


def test_normalize_with_v_suffix():
    assert (
        normalize_workbench_version("2026.1.0.v11#24448141686")
        == "2026.1.0"
    )


def test_normalize_unknown():
    assert normalize_workbench_version("Unknown") is None
