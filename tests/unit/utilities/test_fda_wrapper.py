"""Unit tests for fda pipeline argument building and result handling."""

import json
import os
from unittest.mock import patch

import pytest

from workbench_agent.api.exceptions import ProcessError
from workbench_agent.utilities.fda_wrapper import build_pipeline_args, run_pipeline


class TestBuildPipelineArgs:
    def test_minimal_bazel(self):
        args = build_pipeline_args(
            input_path="/ws",
            output_dir="/tmp/out",
            ecosystem="bazel",
            bazel_target="//app:bin",
        )
        assert args == [
            "--pipeline",
            "--input",
            "/ws",
            "--output",
            "/tmp/out",
            "--ecosystem",
            "bazel",
            "--bazel-target",
            "//app:bin",
        ]

    def test_includes_optional_bazel_flags(self):
        args = build_pipeline_args(
            input_path="/ws",
            output_dir="/tmp/out",
            ecosystem="bazel",
            bazel_target="//:t",
            bazel_path="/usr/bin/bazelisk",
            bazel_mode="BZLMOD",
        )
        assert "--bazel-path" in args
        assert "/usr/bin/bazelisk" in args
        assert "--bazel-mode" in args
        assert "BZLMOD" in args

    def test_force_pipeline_build(self):
        args = build_pipeline_args(
            input_path="/p",
            output_dir="/o",
            ecosystem="maven",
            force_pipeline_build=True,
        )
        assert "--force-pipeline-build" in args

    def test_emit_source_files_is_opt_in(self):
        without = build_pipeline_args(input_path="/p", output_dir="/o")
        assert "--emit-source-files" not in without

        with_flag = build_pipeline_args(input_path="/p", output_dir="/o", emit_source_files=True)
        assert "--emit-source-files" in with_flag


class _CompletedProcess:
    returncode = 0
    stdout = ""
    stderr = ""


def _run_with_outputs(tmp_path, written_files, **kwargs):
    """Run the wrapper against a fake fda that writes ``written_files``."""
    output_dir = str(tmp_path / "out")
    os.makedirs(output_dir, exist_ok=True)

    def fake_run(cmd, **_):
        for name, contents in written_files.items():
            with open(os.path.join(output_dir, name), "w", encoding="utf-8") as f:
                f.write(contents)
        return _CompletedProcess()

    with (
        patch(
            "workbench_agent.utilities.fda_wrapper.tempfile.mkdtemp",
            return_value=output_dir,
        ),
        patch("workbench_agent.utilities.fda_wrapper.subprocess.run", side_effect=fake_run),
    ):
        return run_pipeline(fda_bin="fda", input_path="/ws", **kwargs)


class TestRunPipelineOutputs:
    def test_reports_the_sidecar_path_when_requested(self, tmp_path):
        sidecar = json.dumps({"schema_version": 1, "files": []})
        result = _run_with_outputs(
            tmp_path,
            {"analyzer-result.json": "{}", "first-party-sources.json": sidecar},
            emit_source_files=True,
        )
        assert result.sources_path.endswith("first-party-sources.json")
        assert os.path.isfile(result.sources_path)

    def test_missing_sidecar_names_the_unsupported_fda(self, tmp_path):
        with pytest.raises(ProcessError, match="does not support --emit-source-files"):
            _run_with_outputs(
                tmp_path,
                {"analyzer-result.json": "{}"},
                emit_source_files=True,
            )

    def test_no_sidecar_expected_without_the_flag(self, tmp_path):
        result = _run_with_outputs(tmp_path, {"analyzer-result.json": "{}"})
        assert result.sources_path is None
