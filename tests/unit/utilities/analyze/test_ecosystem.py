"""Tests for the analyze ecosystem registry."""

import argparse

import pytest

from workbench_agent.exceptions import ValidationError
from workbench_agent.utilities.analyze.ecosystem import (
    da_pipeline_kwargs,
    ecosystem_first_party_strategy,
    ecosystem_scope_label,
    supported_ecosystems,
    validate_analyze_ecosystem,
)
from workbench_agent.utilities.analyze.first_party import FirstPartyStrategy


def _params(**overrides):
    ns = argparse.Namespace(
        ecosystem="bazel",
        path=".",
        bazel_target="//app:bin",
        bazel_path=None,
        bazel_mode=None,
        maven_path=None,
        force_pipeline_build=False,
    )
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


def test_supported_ecosystems_lists_bazel_and_maven():
    assert "bazel" in supported_ecosystems()
    assert "maven" in supported_ecosystems()


def test_validate_bazel_ok():
    spec = validate_analyze_ecosystem(_params())
    assert spec.name == "bazel"
    assert ecosystem_first_party_strategy(_params()) is FirstPartyStrategy.SIDECAR


def test_validate_maven_ok():
    spec = validate_analyze_ecosystem(_params(ecosystem="maven", bazel_target=None))
    assert spec.name == "maven"
    assert (
        ecosystem_first_party_strategy(_params(ecosystem="maven", bazel_target=None))
        is FirstPartyStrategy.PATH
    )


def test_rejects_unknown_ecosystem():
    with pytest.raises(ValidationError, match="supports -e"):
        validate_analyze_ecosystem(_params(ecosystem="npm"))


def test_requires_bazel_target():
    with pytest.raises(ValidationError, match="--bazel-target"):
        validate_analyze_ecosystem(_params(bazel_target=None))


def test_maven_does_not_require_bazel_target():
    validate_analyze_ecosystem(_params(ecosystem="maven", bazel_target=None))


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


def test_pipeline_kwargs_does_not_forward_other_eco_attrs():
    kwargs = da_pipeline_kwargs(_params())
    assert "gradle_project" not in kwargs
    assert "maven_path" not in kwargs


def test_maven_pipeline_kwargs_force_build():
    kwargs = da_pipeline_kwargs(
        _params(
            ecosystem="maven",
            bazel_target=None,
            force_pipeline_build=True,
            maven_path="./mvnw",
        )
    )
    assert kwargs == {
        "ecosystem": "maven",
        "maven_path": "./mvnw",
        "force_pipeline_build": True,
    }


def test_maven_auto_detects_mvnw(tmp_path):
    wrapper = tmp_path / "mvnw"
    wrapper.write_text("#!/bin/sh\n")
    params = _params(ecosystem="maven", bazel_target=None, path=str(tmp_path))
    validate_analyze_ecosystem(params)
    assert params.maven_path == "./mvnw"


def test_maven_respects_explicit_maven_path(tmp_path):
    wrapper = tmp_path / "mvnw"
    wrapper.write_text("#!/bin/sh\n")
    params = _params(
        ecosystem="maven",
        bazel_target=None,
        path=str(tmp_path),
        maven_path="/usr/bin/mvn",
    )
    validate_analyze_ecosystem(params)
    assert params.maven_path == "/usr/bin/mvn"


def test_scope_label_is_bazel_target():
    assert ecosystem_scope_label(_params()) == "//app:bin"


def test_scope_label_maven_is_ecosystem_name():
    assert (
        ecosystem_scope_label(_params(ecosystem="maven", bazel_target=None)) == "maven"
    )
