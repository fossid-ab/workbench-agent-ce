"""Unit tests for fda pipeline argument building."""

from workbench_agent.utilities.fda_wrapper import build_pipeline_args


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
