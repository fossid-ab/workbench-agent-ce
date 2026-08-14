"""CLI parsing and validation tests for the analyze command."""

import os
import re
import sys
from unittest.mock import patch

import pytest

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from workbench_agent.exceptions import ValidationError


class TestAnalyzeParsing:
    def test_parse_bazel_analyze(self, args, arg_parser, mock_path_exists):
        with patch("os.path.isdir", return_value=True):
            cmd_args = (
                args()
                .analyze(
                    project="BazelProj",
                    scan="target@1",
                    input_path="/ws",
                    ecosystem="bazel",
                    bazel_target="//app:bin",
                )
                .build()
            )
            parsed = arg_parser(cmd_args)

        assert parsed.command == "analyze"
        assert parsed.project_name == "BazelProj"
        assert parsed.scan_name == "target@1"
        assert parsed.input == "/ws"
        assert parsed.ecosystem == "bazel"
        assert parsed.bazel_target == "//app:bin"
        assert parsed.blind_scan is False
        assert parsed.run_dependency_analysis is False
        assert parsed.recursively_extract_archives is True
        assert parsed.da_timeout == 3600

    def test_parse_blind_scan(self, args, arg_parser, mock_path_exists):
        with patch("os.path.isdir", return_value=True):
            cmd_args = (
                args()
                .analyze(bazel_target="//:t")
                .flag("--blind-scan")
                .flag("--bazel-mode", "bzlmod")
                .build()
            )
            parsed = arg_parser(cmd_args)

        assert parsed.blind_scan is True
        assert parsed.bazel_mode == "BZLMOD"


class TestAnalyzeValidation:
    def test_requires_input_directory(self, args, arg_parser):
        with patch("os.path.exists", return_value=True), patch(
            "os.path.isdir", return_value=False
        ):
            cmd_args = args().analyze(bazel_target="//:t", input_path="/file").build()
            with pytest.raises(ValidationError, match="project directory"):
                arg_parser(cmd_args)

    def test_requires_bazel_target(self, args, arg_parser, mock_path_exists):
        with patch("os.path.isdir", return_value=True):
            # Build without --bazel-target
            builder = args()
            builder.args.extend(["analyze"])
            builder.args.extend(builder.global_args)
            builder.args.extend(
                [
                    "--project-name",
                    "P",
                    "--scan-name",
                    "S",
                    "-i",
                    "/ws",
                    "-e",
                    "bazel",
                ]
            )
            with pytest.raises(ValidationError, match="--bazel-target"):
                arg_parser(builder.build())

    def test_missing_input_path(self, args, arg_parser):
        with patch("os.path.exists", return_value=False):
            cmd_args = args().analyze(bazel_target="//:t", input_path="/missing").build()
            with pytest.raises(
                ValidationError,
                match=re.escape("Input path does not exist: /missing"),
            ):
                arg_parser(cmd_args)
