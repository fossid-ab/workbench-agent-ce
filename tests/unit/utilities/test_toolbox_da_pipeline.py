"""Unit tests for Toolbox DA pipeline argument building and execution."""

import json
import os
from unittest.mock import patch

import pytest

from workbench_agent.api.exceptions import ProcessError
from workbench_agent.utilities.toolbox_wrapper import (
    ToolboxWrapper,
    build_da_pipeline_args,
)


class TestBuildDaPipelineArgs:
    def test_minimal_bazel(self):
        args = build_da_pipeline_args(
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
        assert "--fossid-conf-path" not in args
        assert "-c" not in args

    def test_includes_optional_bazel_flags(self):
        args = build_da_pipeline_args(
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
        args = build_da_pipeline_args(
            input_path="/p",
            output_dir="/o",
            ecosystem="maven",
            force_pipeline_build=True,
        )
        assert "--force-pipeline-build" in args

    def test_emit_source_files_is_opt_in(self):
        without = build_da_pipeline_args(input_path="/p", output_dir="/o")
        assert "--emit-source-files" not in without

        with_flag = build_da_pipeline_args(
            input_path="/p", output_dir="/o", emit_source_files=True
        )
        assert "--emit-source-files" in with_flag


class _CompletedProcess:
    returncode = 0
    stdout = ""
    stderr = ""


def _run_with_outputs(tmp_path, written_files, **kwargs):
    """Run the wrapper against a fake toolbox that writes ``written_files``."""
    fake_toolbox = tmp_path / "fossid-toolbox"
    fake_toolbox.write_text("#!/bin/sh\nexit 0\n")
    fake_toolbox.chmod(0o755)
    wrapper = ToolboxWrapper(toolbox_path=str(fake_toolbox))

    output_dir = str(tmp_path / "out")
    os.makedirs(output_dir, exist_ok=True)
    captured = {}

    def fake_run(cmd, **_):
        captured["cmd"] = cmd
        for name, contents in written_files.items():
            with open(os.path.join(output_dir, name), "w", encoding="utf-8") as f:
                f.write(contents)
        return _CompletedProcess()

    with (
        patch(
            "workbench_agent.utilities.toolbox_wrapper.tempfile.mkdtemp",
            return_value=output_dir,
        ),
        patch(
            "workbench_agent.utilities.toolbox_wrapper.subprocess.run",
            side_effect=fake_run,
        ),
    ):
        result = wrapper.run_da_pipeline(input_path="/ws", **kwargs)
    return result, captured.get("cmd")


class TestRunDaPipeline:
    def test_reports_the_sidecar_path_when_requested(self, tmp_path):
        sidecar = json.dumps({"schema_version": 1, "files": []})
        result, _cmd = _run_with_outputs(
            tmp_path,
            {"analyzer-result.json": "{}", "first-party-sources.json": sidecar},
            emit_source_files=True,
        )
        assert result.sources_path.endswith("first-party-sources.json")
        assert os.path.isfile(result.sources_path)

    def test_missing_sidecar_names_toolbox_emit_source_files(self, tmp_path):
        with pytest.raises(
            ProcessError, match="Toolbox.*--emit-source-files"
        ):
            _run_with_outputs(
                tmp_path,
                {"analyzer-result.json": "{}"},
                emit_source_files=True,
            )

    def test_no_sidecar_expected_without_the_flag(self, tmp_path):
        result, _cmd = _run_with_outputs(
            tmp_path, {"analyzer-result.json": "{}"}
        )
        assert result.sources_path is None

    def test_fossid_conf_is_global_flag_before_da(self, tmp_path):
        _result, cmd = _run_with_outputs(
            tmp_path,
            {"analyzer-result.json": "{}"},
            fossid_conf_path="/etc/fossid.conf",
        )
        assert cmd is not None
        assert "--fossid-conf-path" not in cmd
        assert "-c" in cmd
        assert "da" in cmd
        assert cmd.index("-c") < cmd.index("da")
        assert cmd[cmd.index("-c") + 1] == "/etc/fossid.conf"
