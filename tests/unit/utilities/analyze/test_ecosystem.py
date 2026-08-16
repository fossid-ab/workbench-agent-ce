"""Tests for the analyze ecosystem registry."""

import argparse

import pytest

from workbench_agent.exceptions import ValidationError
from workbench_agent.utilities.analyze.ecosystem import (
    da_pipeline_kwargs,
    ecosystem_scope_label,
    supported_ecosystems,
    validate_analyze_ecosystem,
)


def _params(**overrides):
    ns = argparse.Namespace(
        ecosystem="bazel",
        bazel_target="//app:bin",
        bazel_path=None,
        bazel_mode=None,
        gradle_project=None,
    )
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


def test_supported_ecosystems_lists_bazel():
    assert "bazel" in supported_ecosystems()


def test_validate_bazel_ok():
    spec = validate_analyze_ecosystem(_params())
    assert spec.name == "bazel"


def test_rejects_unknown_ecosystem():
    with pytest.raises(ValidationError, match="supports -e bazel"):
        validate_analyze_ecosystem(_params(ecosystem="maven"))


def test_requires_bazel_target():
    with pytest.raises(ValidationError, match="--bazel-target"):
        validate_analyze_ecosystem(_params(bazel_target=None))


def test_normalizes_bazel_mode():
    params = _params(bazel_mode="bzlmod")
    validate_analyze_ecosystem(params)
    assert params.bazel_mode == "BZLMOD"


def test_rejects_invalid_bazel_mode():
    with pytest.raises(ValidationError, match="--bazel-mode"):
        validate_analyze_ecosystem(_params(bazel_mode="nope"))


def test_pipeline_kwargs_omits_unset_optionals():
    kwargs = da_pipeline_kwargs(_params())
    assert kwargs == {"ecosystem": "bazel", "bazel_target": "//app:bin"}


def test_pipeline_kwargs_forwards_set_toolbox_flags():
    kwargs = da_pipeline_kwargs(
        _params(bazel_path="/bin/bazel", bazel_mode="WORKSPACE")
    )
    assert kwargs["bazel_path"] == "/bin/bazel"
    assert kwargs["bazel_mode"] == "WORKSPACE"


def test_pipeline_kwargs_forwards_gradle_project_when_present():
    kwargs = da_pipeline_kwargs(_params(gradle_project=":app"))
    assert kwargs["gradle_project"] == ":app"


def test_scope_label_is_bazel_target():
    assert ecosystem_scope_label(_params()) == "//app:bin"
