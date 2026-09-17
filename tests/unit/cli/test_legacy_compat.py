"""Tests for legacy CLI argv translation."""

import os

import pytest

from workbench_agent.cli.legacy_compat import (
    LEGACY_DROPPED_FLAGS,
    LEGACY_FLAG_MAP,
    LEGACY_RESULT_FLAG_NAMES,
    LEGACY_SPECIAL_FLAGS,
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

    @pytest.mark.parametrize(
        "legacy_flags,expected_scan_tokens,forbidden_scan_tokens",
        [
            (["--limit", "7"], ["--limit", "7"], []),
            (["--sensitivity", "3"], ["--sensitivity", "3"], []),
            (
                ["--jar_file_extraction"],
                ["--jar-file-extraction"],
                [],
            ),
            (
                ["--run_only_dependency_analysis"],
                ["--dependency-analysis-only"],
                ["--run-dependency-analysis"],
            ),
            (
                ["--auto_identification_detect_declaration"],
                ["--autoid-file-licenses"],
                [],
            ),
            (
                ["--auto_identification_detect_copyright"],
                ["--autoid-file-copyrights"],
                [],
            ),
            (
                ["--auto_identification_resolve_pending_ids"],
                ["--autoid-pending-ids"],
                [],
            ),
            (
                ["--no_advanced_match_scoring"],
                ["--no-advanced-match-scoring"],
                [],
            ),
            (
                ["--match_filtering_threshold", "50"],
                ["--match-filtering-threshold", "50"],
                ["-1"],
            ),
            (
                ["--scan_number_of_tries", "12"],
                ["--scan-number-of-tries", "12"],
                [],
            ),
            (
                ["--scan_wait_time", "8"],
                ["--scan-wait-time", "8"],
                [],
            ),
            (["--log", "DEBUG"], ["--log", "DEBUG"], ["ERROR"]),
            (["--chunked_upload"], [], ["--chunked_upload", "--chunked-upload"]),
        ],
    )
    def test_individual_legacy_flag_translation(
        self,
        legacy_flags,
        expected_scan_tokens,
        forbidden_scan_tokens,
    ):
        pipeline = build_legacy_pipeline(_legacy_argv(*legacy_flags))
        scan_argv = pipeline.scan_argv
        for token in expected_scan_tokens:
            assert token in scan_argv
        for token in forbidden_scan_tokens:
            assert token not in scan_argv

    def test_equals_style_legacy_flags(self):
        pipeline = build_legacy_pipeline(
            _legacy_argv("--limit=4", "--sensitivity=2", "--log=WARNING")
        )
        assert pipeline.scan_argv[pipeline.scan_argv.index("--limit") + 1] == "4"
        assert pipeline.scan_argv[pipeline.scan_argv.index("--sensitivity") + 1] == "2"
        assert pipeline.scan_argv[pipeline.scan_argv.index("--log") + 1] == "WARNING"

    def test_reuse_defaults_to_any(self):
        pipeline = build_legacy_pipeline(_legacy_argv("--reuse_identifications"))
        assert "--reuse-any-identification" in pipeline.scan_argv

    def test_reuse_only_me(self):
        pipeline = build_legacy_pipeline(
            _legacy_argv(
                "--reuse_identifications",
                "--identification_reuse_type",
                "only_me",
            )
        )
        assert "--reuse-my-identifications" in pipeline.scan_argv

    def test_reuse_specific_project(self):
        pipeline = build_legacy_pipeline(
            _legacy_argv(
                "--reuse_identifications",
                "--identification_reuse_type",
                "specific_project",
                "--specific_code",
                "SRC_PROJ",
            )
        )
        assert "--reuse-project-ids" in pipeline.scan_argv
        assert "SRC_PROJ" in pipeline.scan_argv

    def test_reuse_specific_project_requires_code(self):
        with pytest.raises(ValidationError, match="specific_code"):
            build_legacy_pipeline(
                _legacy_argv(
                    "--reuse_identifications",
                    "--identification_reuse_type",
                    "specific_project",
                )
            )

    def test_reuse_specific_scan_requires_code(self):
        with pytest.raises(ValidationError, match="specific_code"):
            build_legacy_pipeline(
                _legacy_argv(
                    "--reuse_identifications",
                    "--identification_reuse_type",
                    "specific_scan",
                )
            )

    def test_unsupported_reuse_type(self):
        with pytest.raises(ValidationError, match="identification_reuse_type"):
            build_legacy_pipeline(
                _legacy_argv(
                    "--reuse_identifications",
                    "--identification_reuse_type",
                    "something_else",
                )
            )

    def test_get_scan_identified_components_maps_to_show(self):
        pipeline = build_legacy_pipeline(
            _legacy_argv("--get_scan_identified_components")
        )
        assert "--show-components" in pipeline.show_argv
        assert "--show-licenses" not in pipeline.show_argv

    def test_result_flag_priority_components_over_policy_and_matches(self):
        pipeline = build_legacy_pipeline(
            _legacy_argv(
                "--get_scan_identified_components",
                "--scans_get_policy_warnings_counter",
                "--projects_get_policy_warnings_info",
                "--scans_get_results",
            )
        )
        assert "--show-components" in pipeline.show_argv
        assert "--show-policy-warnings" not in pipeline.show_argv
        assert "--show-project-policy-warnings" not in pipeline.show_argv
        assert "--show-matches" not in pipeline.show_argv

    def test_kitchen_sink_scan_flags_present_on_scan_not_show(self):
        pipeline = build_legacy_pipeline(
            _legacy_argv(
                "--limit",
                "9",
                "--sensitivity",
                "4",
                "--recursively_extract_archives",
                "--jar_file_extraction",
                "--run_dependency_analysis",
                "--auto_identification_detect_declaration",
                "--auto_identification_detect_copyright",
                "--auto_identification_resolve_pending_ids",
                "--delta_only",
                "--reuse_identifications",
                "--identification_reuse_type",
                "only_me",
                "--no_advanced_match_scoring",
                "--match_filtering_threshold",
                "25",
                "--chunked_upload",
                "--use_projectscan",
                "--scan_number_of_tries",
                "11",
                "--scan_wait_time",
                "6",
                "--log",
                "INFO",
            )
        )
        scan = pipeline.scan_argv
        show = pipeline.show_argv
        assert scan[0] == "scan"
        for token in (
            "--limit",
            "--sensitivity",
            "--recursively-extract-archives",
            "--jar-file-extraction",
            "--run-dependency-analysis",
            "--autoid-file-licenses",
            "--autoid-file-copyrights",
            "--autoid-pending-ids",
            "--delta-scan",
            "--reuse-my-identifications",
            "--no-advanced-match-scoring",
            "--match-filtering-threshold",
            "--use-projectscan",
            "--scan-number-of-tries",
            "--scan-wait-time",
            "--log",
        ):
            assert token in scan
        assert "--chunked_upload" not in scan
        assert "--chunked-upload" not in scan
        assert "--show-licenses" in show
        assert "--run-dependency-analysis" not in show
        assert "--autoid-file-licenses" not in show
        assert show[show.index("--scan-number-of-tries") + 1] == "11"
        assert show[show.index("--scan-wait-time") + 1] == "6"

    def test_both_da_flags_translate_and_ce_prefers_da_only(self):
        pipeline = build_legacy_pipeline(
            _legacy_argv(
                "--run_dependency_analysis",
                "--run_only_dependency_analysis",
            )
        )
        assert "--run-dependency-analysis" in pipeline.scan_argv
        assert "--dependency-analysis-only" in pipeline.scan_argv

    def test_documented_legacy_flags_are_classified(self):
        """Every public legacy flag is mapped, dropped, or handled specially."""
        documented = {
            "--api_url",
            "--api_user",
            "--api_token",
            "--project_code",
            "--scan_code",
            "--limit",
            "--sensitivity",
            "--recursively_extract_archives",
            "--jar_file_extraction",
            "--blind_scan",
            "--run_dependency_analysis",
            "--run_only_dependency_analysis",
            "--auto_identification_detect_declaration",
            "--auto_identification_detect_copyright",
            "--auto_identification_resolve_pending_ids",
            "--delta_only",
            "--reuse_identifications",
            "--identification_reuse_type",
            "--specific_code",
            "--no_advanced_match_scoring",
            "--match_filtering_threshold",
            "--target_path",
            "--chunked_upload",
            "--scan_number_of_tries",
            "--scan_wait_time",
            "--path",
            "--log",
            "--path-result",
            "--get_scan_identified_components",
            "--scans_get_policy_warnings_counter",
            "--projects_get_policy_warnings_info",
            "--use_projectscan",
            "--scans_get_results",
        }
        classified = (
            set(LEGACY_FLAG_MAP)
            | LEGACY_SPECIAL_FLAGS
            | LEGACY_DROPPED_FLAGS
            | LEGACY_RESULT_FLAG_NAMES
            | {"--blind_scan"}
        )
        missing = documented - classified
        assert not missing, f"Unclassified legacy flags: {sorted(missing)}"


class TestNormalizeResultSavePath:
    def test_nonexistent_directory_like_path(self):
        assert normalize_result_save_path("/tmp/no/such/legacy-dir") == os.path.join(
            "/tmp/no/such/legacy-dir", "wb_results.json"
        )

    def test_non_json_file_path(self, tmp_path):
        path = tmp_path / "results.txt"
        assert normalize_result_save_path(str(path)) == str(tmp_path / "results.json")
