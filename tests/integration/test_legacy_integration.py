# tests/integration/test_legacy_integration.py

import os
import shutil
import sys
from contextlib import ExitStack
from unittest.mock import MagicMock, mock_open, patch

import pytest

from workbench_agent.api.exceptions import ScanNotFoundError
from workbench_agent.api.utils.process_waiter import StatusResult
from workbench_agent.main import main

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "fixtures")
SIGNATURES_FIXTURE = os.path.join(FIXTURES_DIR, "signatures")


def create_dummy_path(tmp_path, is_dir=False, content="dummy content"):
    path = tmp_path / ("dummy_dir" if is_dir else "dummy_file.zip")
    if is_dir:
        path.mkdir()
        (path / "file_inside.txt").write_text(content)
    else:
        path.write_text(content)
    return str(path)


def create_dummy_directory(tmp_path):
    dummy_dir = tmp_path / "test_source_code"
    dummy_dir.mkdir()
    (dummy_dir / "main.py").write_text("print('Hello, World!')")
    return str(dummy_dir)


def legacy_argv(path: str, *extra: str) -> list[str]:
    argv = [
        "workbench-agent",
        "--api_url",
        "http://dummy.com",
        "--api_user",
        "test",
        "--api_token",
        "token",
        "--project_code",
        "PRJ-LEGACY",
        "--scan_code",
        "SCN-LEGACY",
        "--path",
        path,
    ]
    argv.extend(extra)
    return argv


def copy_signatures_fixture_as_mock_fossid(dest_path) -> str:
    shutil.copy(SIGNATURES_FIXTURE, dest_path)
    return str(dest_path)


@pytest.fixture
def legacy_ready_mock(mock_workbench_api):
    """Configure mocked client for legacy scan → show-results flows."""
    mock_workbench_api.dependencies = MagicMock()
    mock_workbench_api.dependencies.list_dependencies.return_value = []
    mock_workbench_api.identification.get_unique_identified_licenses.return_value = [
        {"identifier": "MIT"}
    ]
    mock_workbench_api.identification.get_identified_components.return_value = [
        {"name": "example", "version": "1.0"}
    ]
    mock_workbench_api.scans.get_results.return_value = [{"file": "main.py"}]
    mock_workbench_api.policy.get_project_identification_policy_warnings.return_value = {
        "policy_warnings_total": 0
    }

    legacy_scans: list[dict] = []

    def scan_get_information(scan_code):
        for scan in legacy_scans:
            if str(scan.get("code")) == scan_code:
                return dict(scan)
        raise ScanNotFoundError(f"Scan '{scan_code}' not found")

    def get_all_scans(project_code):
        if project_code != "PRJ-LEGACY":
            return []
        return list(legacy_scans)

    original_create = mock_workbench_api.scans.create.side_effect

    def register_legacy_scan(payload):
        if original_create is not None:
            result = original_create(payload)
        else:
            result = {"scan_id": 99001, "code": payload.get("scan_code", "SCN-LEGACY")}

        legacy_scans.append(
            {
                "id": result.get("scan_id", 99001),
                "code": payload.get("scan_code") or result.get("code", "SCN-LEGACY"),
                "name": payload.get("scan_name", payload.get("scan_code", "SCN-LEGACY")),
                "project_code": payload.get("project_code", "PRJ-LEGACY"),
            }
        )
        return result

    mock_workbench_api.scans.get_information.side_effect = scan_get_information
    mock_workbench_api.scans.create.side_effect = register_legacy_scan
    mock_workbench_api.projects.get_information.return_value = {
        "project_code": "PRJ-LEGACY",
    }
    mock_workbench_api.projects.get_all_scans.side_effect = get_all_scans

    finished = StatusResult(
        status="FINISHED",
        is_finished=True,
        raw_data={"status": "FINISHED", "is_finished": "1"},
    )
    mock_workbench_api.status_check.check_extract_archives_status.return_value = finished
    return mock_workbench_api


def enter_scan_filesystem_patches(stack: ExitStack):
    stack.enter_context(patch("os.path.exists", return_value=True))
    stack.enter_context(patch("os.path.isdir", return_value=False))
    stack.enter_context(patch("os.path.getsize", return_value=100))
    stack.enter_context(
        patch(
            "builtins.open",
            new_callable=mock_open,
            read_data=b"dummy data",
        )
    )


class TestLegacyIntegration:
    """Integration tests for legacy underscore-flag CLI compatibility."""

    def test_legacy_scan_then_show_default_licenses(
        self,
        legacy_ready_mock,
        tmp_path,
        capsys,
    ):
        dummy_path = create_dummy_path(tmp_path)

        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(sys, "argv", legacy_argv(dummy_path)):
                return_code = main()

        assert return_code == 0

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "SCAN" in combined_output
        assert "SHOW-RESULTS" in combined_output
        assert "Workbench Agent finished successfully" in combined_output

        legacy_ready_mock.scan_content.upload_scan_target.assert_called_once()
        legacy_ready_mock.scan_operations.start_scan.assert_called_once()

        extract_call = legacy_ready_mock.scan_content.extract_archives.call_args
        assert extract_call is not None
        assert extract_call.kwargs["recursively_extract_archives"] is False

    def test_legacy_scans_get_results_runs_show_matches(
        self,
        legacy_ready_mock,
        tmp_path,
        capsys,
    ):
        dummy_path = create_dummy_path(tmp_path)

        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(sys, "argv", legacy_argv(dummy_path, "--scans_get_results")):
                return_code = main()

        assert return_code == 0
        legacy_ready_mock.scans.get_results.assert_called_once()

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "SHOW-RESULTS" in combined_output

    def test_legacy_recursive_extract_off_by_default(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)

        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(sys, "argv", legacy_argv(dummy_path)):
                main()

        _, kwargs = legacy_ready_mock.scan_content.extract_archives.call_args
        assert kwargs["recursively_extract_archives"] is False
        assert kwargs["jar_file_extraction"] is False

    def test_legacy_explicit_recursive_extract_on(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)

        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(dummy_path, "--recursively_extract_archives"),
            ):
                main()

        _, kwargs = legacy_ready_mock.scan_content.extract_archives.call_args
        assert kwargs["recursively_extract_archives"] is True

    def test_legacy_blind_scan_two_phase_flow(
        self,
        legacy_ready_mock,
        tmp_path,
        capsys,
    ):
        dummy_path = create_dummy_directory(tmp_path)

        mock_toolbox = MagicMock()
        mock_toolbox.get_version.return_value = "FossID Toolbox version 2023.2.1"
        mock_fossid = tmp_path / "mock_toolbox_out.fossid"
        mock_toolbox.generate_hashes.return_value = copy_signatures_fixture_as_mock_fossid(
            mock_fossid
        )

        with (
            patch(
                "workbench_agent.handlers.blind_scan.resolve_fossid_toolbox_path",
                return_value="/usr/bin/fossid-toolbox",
            ),
            patch(
                "workbench_agent.handlers.blind_scan.ToolboxWrapper",
                return_value=mock_toolbox,
            ),
            patch("os.path.exists", return_value=True),
            patch("os.path.isdir", return_value=True),
            patch(
                "workbench_agent.handlers.blind_scan.cleanup_temp_path",
                return_value=None,
            ),
            patch.object(sys, "argv", legacy_argv(dummy_path, "--blind_scan")),
        ):
            return_code = main()

        assert return_code == 0
        legacy_ready_mock.scan_content.extract_archives.assert_not_called()

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "BLIND-SCAN" in combined_output
        assert "SHOW-RESULTS" in combined_output

    def test_legacy_invalid_path_fails_before_show(self, tmp_path, capsys):
        invalid_path = str(tmp_path / "nonexistent_file.zip")

        with patch.object(sys, "argv", legacy_argv(invalid_path)):
            return_code = main()

        assert return_code != 0

        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "SHOW-RESULTS" not in combined_output
        assert any(
            term in combined_output.lower()
            for term in ["path", "file", "not found", "error", "exist"]
        )

    def test_legacy_target_path_rejected(self, tmp_path, capsys):
        dummy_path = create_dummy_path(tmp_path)
        with patch.object(
            sys,
            "argv",
            legacy_argv(dummy_path, "--target_path", "/server/code"),
        ):
            return_code = main()

        assert return_code == 2
        captured = capsys.readouterr()
        assert "target_path" in (captured.out + captured.err)

    def test_legacy_kitchen_sink_scan_flags_reach_start_scan(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(
                    dummy_path,
                    "--limit",
                    "7",
                    "--sensitivity",
                    "3",
                    "--recursively_extract_archives",
                    "--jar_file_extraction",
                    "--run_dependency_analysis",
                    "--auto_identification_detect_declaration",
                    "--auto_identification_detect_copyright",
                    "--auto_identification_resolve_pending_ids",
                    "--delta_only",
                    "--reuse_identifications",
                    "--identification_reuse_type",
                    "any",
                    "--no_advanced_match_scoring",
                    "--match_filtering_threshold",
                    "40",
                    "--chunked_upload",
                    "--use_projectscan",
                    "--scan_number_of_tries",
                    "15",
                    "--scan_wait_time",
                    "9",
                    "--log",
                    "DEBUG",
                ),
            ):
                assert main() == 0

        extract_kwargs = legacy_ready_mock.scan_content.extract_archives.call_args.kwargs
        assert extract_kwargs["recursively_extract_archives"] is True
        assert extract_kwargs["jar_file_extraction"] is True

        scan_kwargs = legacy_ready_mock.scan_operations.start_scan.call_args.kwargs
        assert scan_kwargs["limit"] == 7
        assert scan_kwargs["sensitivity"] == 3
        assert scan_kwargs["autoid_file_licenses"] is True
        assert scan_kwargs["autoid_file_copyrights"] is True
        assert scan_kwargs["autoid_pending_ids"] is True
        assert scan_kwargs["delta_scan"] is True
        assert scan_kwargs["id_reuse_type"] == "any"
        assert scan_kwargs["run_dependency_analysis"] is True
        assert scan_kwargs["advanced_match_scoring"] is False
        assert scan_kwargs["match_filtering_threshold"] == 40
        assert scan_kwargs["use_projectscan"] is True

    def test_legacy_da_only_skips_kb_scan(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(dummy_path, "--run_only_dependency_analysis"),
            ):
                assert main() == 0

        legacy_ready_mock.scan_operations.start_scan.assert_not_called()
        legacy_ready_mock.scan_operations.start_da_only.assert_called()

    def test_legacy_reuse_specific_scan(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        original_get_information = legacy_ready_mock.scans.get_information.side_effect

        def get_information(scan_code):
            if scan_code == "SRC_SCAN":
                return {
                    "id": 42,
                    "code": "SRC_SCAN",
                    "name": "SRC_SCAN",
                    "project_code": "PRJ-LEGACY",
                }
            return original_get_information(scan_code)

        legacy_ready_mock.scans.get_information.side_effect = get_information
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(
                    dummy_path,
                    "--reuse_identifications",
                    "--identification_reuse_type",
                    "specific_scan",
                    "--specific_code",
                    "SRC_SCAN",
                ),
            ):
                assert main() == 0

        scan_kwargs = legacy_ready_mock.scan_operations.start_scan.call_args.kwargs
        assert scan_kwargs["id_reuse_type"] == "specific_scan"
        assert scan_kwargs["id_reuse_specific_code"] == "SRC_SCAN"

    def test_legacy_show_components(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(dummy_path, "--get_scan_identified_components"),
            ):
                assert main() == 0

        legacy_ready_mock.identification.get_identified_components.assert_called()
        legacy_ready_mock.scans.get_results.assert_not_called()

    def test_legacy_show_scan_policy_warnings(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(dummy_path, "--scans_get_policy_warnings_counter"),
            ):
                assert main() == 0

        legacy_ready_mock.policy.get_policy_warnings.assert_called()

    def test_legacy_show_project_policy_warnings(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(dummy_path, "--projects_get_policy_warnings_info"),
            ):
                assert main() == 0

        legacy_ready_mock.policy.get_project_identification_policy_warnings.assert_called()

    def test_legacy_path_result_writes_json(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        result_file = tmp_path / "legacy-out.json"
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            mock_save = stack.enter_context(
                patch(
                    "workbench_agent.utilities.result_utilities.save_results_to_file"
                )
            )
            with patch.object(
                sys,
                "argv",
                legacy_argv(dummy_path, "--path-result", str(result_file)),
            ):
                assert main() == 0

        mock_save.assert_called()
        assert mock_save.call_args[0][0] == str(result_file)
        assert "kb_licenses" in mock_save.call_args[0][1]

    def test_legacy_equals_flags_parse(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(dummy_path, "--limit=8", "--sensitivity=5"),
            ):
                assert main() == 0

        scan_kwargs = legacy_ready_mock.scan_operations.start_scan.call_args.kwargs
        assert scan_kwargs["limit"] == 8
        assert scan_kwargs["sensitivity"] == 5

    def test_legacy_default_match_filter_and_extract_off(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(sys, "argv", legacy_argv(dummy_path)):
                assert main() == 0

        scan_kwargs = legacy_ready_mock.scan_operations.start_scan.call_args.kwargs
        assert scan_kwargs["match_filtering_threshold"] == -1
        assert scan_kwargs["advanced_match_scoring"] is True
        extract_kwargs = legacy_ready_mock.scan_content.extract_archives.call_args.kwargs
        assert extract_kwargs["recursively_extract_archives"] is False
        assert extract_kwargs["jar_file_extraction"] is False

    def test_legacy_matches_modern_start_scan_kwargs(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        """Explicit legacy flags produce the same start_scan payload as CE kebab flags."""
        dummy_path = create_dummy_path(tmp_path)
        compared_keys = (
            "limit",
            "sensitivity",
            "autoid_file_licenses",
            "autoid_file_copyrights",
            "autoid_pending_ids",
            "delta_scan",
            "id_reuse_type",
            "run_dependency_analysis",
            "advanced_match_scoring",
            "match_filtering_threshold",
            "use_projectscan",
        )
        modern_argv = [
            "workbench-agent",
            "scan",
            "--api-url",
            "http://dummy.com",
            "--api-user",
            "test",
            "--api-token",
            "token",
            "--project-code",
            "PRJ-LEGACY",
            "--scan-code",
            "SCN-MODERN",
            "--path",
            dummy_path,
            "--limit",
            "7",
            "--sensitivity",
            "3",
            "--recursively-extract-archives",
            "--jar-file-extraction",
            "--run-dependency-analysis",
            "--autoid-file-licenses",
            "--autoid-file-copyrights",
            "--autoid-pending-ids",
            "--delta-scan",
            "--reuse-any-identification",
            "--no-advanced-match-scoring",
            "--match-filtering-threshold",
            "40",
            "--use-projectscan",
            "--scan-number-of-tries",
            "15",
            "--scan-wait-time",
            "9",
        ]
        legacy_flags = (
            "--limit",
            "7",
            "--sensitivity",
            "3",
            "--recursively_extract_archives",
            "--jar_file_extraction",
            "--run_dependency_analysis",
            "--auto_identification_detect_declaration",
            "--auto_identification_detect_copyright",
            "--auto_identification_resolve_pending_ids",
            "--delta_only",
            "--reuse_identifications",
            "--identification_reuse_type",
            "any",
            "--no_advanced_match_scoring",
            "--match_filtering_threshold",
            "40",
            "--use_projectscan",
            "--scan_number_of_tries",
            "15",
            "--scan_wait_time",
            "9",
        )

        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(sys, "argv", modern_argv):
                assert main() == 0
            modern_scan = dict(legacy_ready_mock.scan_operations.start_scan.call_args.kwargs)
            modern_extract = dict(legacy_ready_mock.scan_content.extract_archives.call_args.kwargs)
            legacy_ready_mock.scan_operations.start_scan.reset_mock()
            legacy_ready_mock.scan_content.extract_archives.reset_mock()
            with patch.object(sys, "argv", legacy_argv(dummy_path, *legacy_flags)):
                assert main() == 0

        legacy_scan = legacy_ready_mock.scan_operations.start_scan.call_args.kwargs
        legacy_extract = legacy_ready_mock.scan_content.extract_archives.call_args.kwargs
        for key in compared_keys:
            assert legacy_scan[key] == modern_scan[key], key
        assert (
            legacy_extract["recursively_extract_archives"]
            == modern_extract["recursively_extract_archives"]
        )
        assert legacy_extract["jar_file_extraction"] == modern_extract["jar_file_extraction"]

    def test_legacy_reuse_only_me(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(
                    dummy_path,
                    "--reuse_identifications",
                    "--identification_reuse_type",
                    "only_me",
                ),
            ):
                assert main() == 0

        scan_kwargs = legacy_ready_mock.scan_operations.start_scan.call_args.kwargs
        assert scan_kwargs["id_reuse_type"] == "only_me"

    def test_legacy_reuse_specific_project(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(
                    dummy_path,
                    "--reuse_identifications",
                    "--identification_reuse_type",
                    "specific_project",
                    "--specific_code",
                    "SRC_PROJ",
                ),
            ):
                assert main() == 0

        scan_kwargs = legacy_ready_mock.scan_operations.start_scan.call_args.kwargs
        assert scan_kwargs["id_reuse_type"] == "specific_project"
        assert scan_kwargs["id_reuse_specific_code"] == "SRC_PROJ"

    def test_legacy_reuse_defaults_to_any(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(dummy_path, "--reuse_identifications"),
            ):
                assert main() == 0

        scan_kwargs = legacy_ready_mock.scan_operations.start_scan.call_args.kwargs
        assert scan_kwargs["id_reuse_type"] == "any"

    def test_legacy_jar_extraction(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(dummy_path, "--jar_file_extraction"),
            ):
                assert main() == 0

        extract_kwargs = legacy_ready_mock.scan_content.extract_archives.call_args.kwargs
        assert extract_kwargs["jar_file_extraction"] is True
        assert extract_kwargs["recursively_extract_archives"] is False

    def test_legacy_wait_and_tries_reach_status_check(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(
                    dummy_path,
                    "--scan_number_of_tries",
                    "15",
                    "--scan_wait_time",
                    "9",
                ),
            ):
                assert main() == 0

        waited = [
            call.kwargs
            for call in legacy_ready_mock.status_check.check_scan_status.call_args_list
            if call.kwargs.get("wait")
        ]
        assert waited, "expected a waiting check_scan_status call"
        assert waited[0]["wait_retry_count"] == 15
        assert waited[0]["wait_retry_interval"] == 9

    def test_legacy_default_show_licenses(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(sys, "argv", legacy_argv(dummy_path)):
                assert main() == 0

        legacy_ready_mock.identification.get_unique_identified_licenses.assert_called()
        legacy_ready_mock.identification.get_identified_components.assert_not_called()
        legacy_ready_mock.scans.get_results.assert_not_called()

    def test_legacy_path_result_directory_saves_wb_results(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        out_dir = tmp_path / "legacy-reports"
        out_dir.mkdir()
        expected = str(out_dir / "wb_results.json")
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            mock_save = stack.enter_context(
                patch(
                    "workbench_agent.utilities.result_utilities.save_results_to_file"
                )
            )
            with patch.object(
                sys,
                "argv",
                legacy_argv(dummy_path, "--path-result", str(out_dir)),
            ):
                assert main() == 0

        mock_save.assert_called()
        assert mock_save.call_args[0][0] == expected
        assert "kb_licenses" in mock_save.call_args[0][1]

    def test_legacy_both_da_flags_prefer_da_only(
        self,
        legacy_ready_mock,
        tmp_path,
    ):
        dummy_path = create_dummy_path(tmp_path)
        with ExitStack() as stack:
            enter_scan_filesystem_patches(stack)
            with patch.object(
                sys,
                "argv",
                legacy_argv(
                    dummy_path,
                    "--run_dependency_analysis",
                    "--run_only_dependency_analysis",
                ),
            ):
                assert main() == 0

        legacy_ready_mock.scan_operations.start_scan.assert_not_called()
        legacy_ready_mock.scan_operations.start_da_only.assert_called()

    def test_legacy_blind_scan_and_da_only_rejected(self, tmp_path, capsys):
        dummy_path = create_dummy_path(tmp_path)
        with patch.object(
            sys,
            "argv",
            legacy_argv(
                dummy_path,
                "--blind_scan",
                "--run_only_dependency_analysis",
            ),
        ):
            return_code = main()

        assert return_code == 2
        captured = capsys.readouterr()
        assert "blind-scan" in (captured.out + captured.err).lower()
