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
    mock_workbench_api.identification.get_unique_identified_licenses.return_value = []
    mock_workbench_api.scans.get_results.return_value = []

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
