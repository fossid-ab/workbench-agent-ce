"""Tests for legacy CLI argv translation."""

import os

import pytest

from workbench_agent.cli.legacy_compat import (
    build_legacy_pipeline,
    is_legacy_argv,
    normalize_result_save_path,
    resolve_legacy_show_flag,
)
from workbench_agent.exceptions import ValidationError


def _legacy_argv(*extra: str) -> list[str]:
    base = [
        "workbench-agent",
        "--api_url",
        "https://wb.example/api.php",
        "--api_user",
        "user",
        "--api_token",
        "token",
        "--project_code",
        "PRJ",
        "--scan_code",
        "SCN",
        "--path",
        "./src",
    ]
    base.extend(extra)
    return base


class TestLegacyDetection:
    def test_modern_scan_is_not_legacy(self):
        argv = [
            "workbench-agent",
            "scan",
            "--api-url",
            "https://wb.example/api.php",
            "--project-name",
            "P",
            "--scan-name",
            "S",
            "--path",
            ".",
        ]
        assert is_legacy_argv(argv) is False

    def test_legacy_markers_detected(self):
        assert is_legacy_argv(_legacy_argv()) is True

    def test_help_is_not_legacy(self):
        assert is_legacy_argv(["workbench-agent", "--help"]) is False


class TestLegacyTranslation:
    def test_basic_scan_and_default_show(self):
        pipeline = build_legacy_pipeline(_legacy_argv())
        assert pipeline is not None
        assert pipeline.scan_argv[0] == "scan"
        assert "--api-url" in pipeline.scan_argv
        assert "--project-code" in pipeline.scan_argv
        assert "--scan-code" in pipeline.scan_argv
        assert "--path" in pipeline.scan_argv
        assert "--no-recursively-extract-archives" in pipeline.scan_argv
        assert "--log" in pipeline.scan_argv
        assert "ERROR" in pipeline.scan_argv
        assert "--match-filtering-threshold" in pipeline.scan_argv
        assert "-1" in pipeline.scan_argv
        assert "--show-licenses" in pipeline.show_argv
        assert pipeline.show_argv[0] == "show-results"

    def test_blind_scan_routing(self):
        pipeline = build_legacy_pipeline(_legacy_argv("--blind_scan"))
        assert pipeline.scan_argv[0] == "blind-scan"
        assert "--no-recursively-extract-archives" not in pipeline.scan_argv
        assert "--recursively-extract-archives" not in pipeline.scan_argv
        assert "--jar-file-extraction" not in pipeline.scan_argv

    def test_blind_scan_ignores_explicit_archive_flags(self):
        pipeline = build_legacy_pipeline(
            _legacy_argv("--blind_scan", "--recursively_extract_archives", "--jar_file_extraction")
        )
        assert pipeline.scan_argv[0] == "blind-scan"
        assert "--no-recursively-extract-archives" not in pipeline.scan_argv
        assert "--recursively-extract-archives" not in pipeline.scan_argv
        assert "--jar-file-extraction" not in pipeline.scan_argv

    def test_flag_rename_matrix(self):
        pipeline = build_legacy_pipeline(
            _legacy_argv(
                "--run_dependency_analysis",
                "--delta_only",
                "--use_projectscan",
            )
        )
        assert "--run-dependency-analysis" in pipeline.scan_argv
        assert "--delta-scan" in pipeline.scan_argv
        assert "--use-projectscan" in pipeline.scan_argv
        assert "--chunked_upload" not in " ".join(pipeline.scan_argv)

    def test_explicit_recursive_extract(self):
        pipeline = build_legacy_pipeline(_legacy_argv("--recursively_extract_archives"))
        assert "--recursively-extract-archives" in pipeline.scan_argv
        assert "--no-recursively-extract-archives" not in pipeline.scan_argv

    def test_result_flag_priority(self):
        options = {
            "--get_scan_identified_components": "1",
            "--scans_get_results": "1",
        }
        assert resolve_legacy_show_flag(options) == "--show-components"

    def test_result_flags_map_to_show(self):
        pipeline = build_legacy_pipeline(_legacy_argv("--scans_get_results"))
        assert "--show-matches" in pipeline.show_argv
        assert "--show-licenses" not in pipeline.show_argv

        pipeline = build_legacy_pipeline(_legacy_argv("--projects_get_policy_warnings_info"))
        assert "--show-project-policy-warnings" in pipeline.show_argv

        pipeline = build_legacy_pipeline(_legacy_argv("--scans_get_policy_warnings_counter"))
        assert "--show-policy-warnings" in pipeline.show_argv

    def test_path_result_directory(self, tmp_path):
        out_dir = tmp_path / "reports"
        out_dir.mkdir()
        pipeline = build_legacy_pipeline(_legacy_argv("--path-result", str(out_dir)))
        idx = pipeline.show_argv.index("--result-save-path")
        assert pipeline.show_argv[idx + 1] == str(out_dir / "wb_results.json")

    def test_path_result_json_file(self, tmp_path):
        out_file = tmp_path / "out.json"
        pipeline = build_legacy_pipeline(_legacy_argv("--path-result", str(out_file)))
        idx = pipeline.show_argv.index("--result-save-path")
        assert pipeline.show_argv[idx + 1] == str(out_file)

    def test_target_path_rejected(self):
        with pytest.raises(ValidationError, match="target_path"):
            build_legacy_pipeline(_legacy_argv("--target_path", "/server/path"))

    def test_reuse_any(self):
        pipeline = build_legacy_pipeline(
            _legacy_argv("--reuse_identifications", "--identification_reuse_type", "any")
        )
        assert "--reuse-any-identification" in pipeline.scan_argv

    def test_reuse_specific_scan(self):
        pipeline = build_legacy_pipeline(
            _legacy_argv(
                "--reuse_identifications",
                "--identification_reuse_type",
                "specific_scan",
                "--specific_code",
                "SRC_SCAN",
            )
        )
        assert "--reuse-scan-ids" in pipeline.scan_argv
        assert "SRC_SCAN" in pipeline.scan_argv

    def test_no_reuse_without_master_flag(self):
        pipeline = build_legacy_pipeline(
            _legacy_argv("--identification_reuse_type", "specific_scan", "--specific_code", "X")
        )
        assert "--reuse-scan-ids" not in pipeline.scan_argv

    def test_blind_scan_and_da_only_rejected(self):
        with pytest.raises(ValidationError, match="blind-scan"):
            build_legacy_pipeline(
                _legacy_argv("--blind_scan", "--run_only_dependency_analysis")
            )


class TestNormalizeResultSavePath:
    def test_nonexistent_directory_like_path(self):
        assert normalize_result_save_path("/tmp/no/such/legacy-dir") == os.path.join(
            "/tmp/no/such/legacy-dir", "wb_results.json"
        )

    def test_non_json_file_path(self, tmp_path):
        path = tmp_path / "results.txt"
        assert normalize_result_save_path(str(path)) == str(tmp_path / "results.json")
