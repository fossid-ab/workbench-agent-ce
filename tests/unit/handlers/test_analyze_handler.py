"""Unit tests for the analyze handler orchestration."""

import argparse
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.exceptions import ValidationError
from workbench_agent.handlers.analyze import handle_analyze
from workbench_agent.utilities.analyze.first_party import ResolvedFirstParty
from workbench_agent.utilities.toolbox_wrapper import DaPipelineResult


def _pipeline_result():
    return DaPipelineResult(
        report_path="/tmp/out/analyzer-result.json",
        output_dir="/tmp/out",
        sources_path="/tmp/out/first-party-sources.json",
    )


def _params(**overrides):
    ns = argparse.Namespace(
        command="analyze",
        path="/ws",
        ecosystem="bazel",
        bazel_target="//app:bin",
        bazel_path=None,
        bazel_mode=None,
        maven_path=None,
        force_pipeline_build=False,
        exclude=None,
        da_timeout=3600,
        blind_scan=False,
        no_wait=False,
        fossid_toolbox_path=None,
        fossid_toolbox_timeout=300,
        skip_lac_extraction=False,
        project_name="P",
        scan_name="S",
        scan_number_of_tries=10,
        scan_wait_time=1,
        show_summary=False,
        limit=10,
        sensitivity=10,
        autoid_file_licenses=False,
        autoid_file_copyrights=False,
        autoid_pending_ids=False,
        run_dependency_analysis=False,
        dependency_analysis_only=False,
        delta_scan=False,
        scan_failed_only=False,
        full_file_only=False,
        replace_existing_identifications=False,
        advanced_match_scoring=True,
        match_filtering_threshold=None,
        reuse_any_identification=False,
        reuse_my_identifications=False,
        reuse_scan_ids=None,
        reuse_project_ids=None,
        recursively_extract_archives=True,
        jar_file_extraction=False,
        incremental_upload=False,
    )
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


def _stub_toolbox(mock_wrapper_cls, pipeline_result=None):
    mock_wrapper = mock_wrapper_cls.return_value
    mock_wrapper.get_version.return_value = "FossID Toolbox version 1.7.11"
    mock_wrapper.run_da_pipeline.return_value = (
        pipeline_result or _pipeline_result()
    )
    return mock_wrapper


def _staged_sidecar():
    return ResolvedFirstParty(scan_root="/tmp/stage", owned=True)


class TestHandleAnalyze:
    def test_rejects_unknown_ecosystem(self):
        client = MagicMock()
        with pytest.raises(ValidationError, match="supports -e"):
            handle_analyze(client, _params(ecosystem="npm"))

    def test_rejects_missing_target(self):
        client = MagicMock()
        with pytest.raises(ValidationError, match="--bazel-target"):
            handle_analyze(client, _params(bazel_target=None))

    @patch("workbench_agent.handlers.analyze.shutil.rmtree")
    @patch("workbench_agent.handlers.analyze._import_da_report", return_value=True)
    @patch("workbench_agent.handlers.analyze._run_upload_sources", return_value=True)
    @patch(
        "workbench_agent.handlers.analyze.resolve_first_party",
        return_value=_staged_sidecar(),
    )
    @patch("workbench_agent.handlers.analyze.find_or_create_project_and_scan")
    @patch("workbench_agent.handlers.analyze.ToolboxWrapper")
    @patch(
        "workbench_agent.handlers.analyze.resolve_fossid_toolbox_path",
        return_value="/toolbox",
    )
    def test_default_flow_upload_then_import(
        self,
        _resolve_toolbox,
        mock_wrapper_cls,
        mock_resolve,
        mock_first_party,
        mock_upload,
        mock_import,
        _rmtree,
    ):
        _stub_toolbox(mock_wrapper_cls)
        mock_resolve.return_value = ("PROJ", "SCAN", True)
        client = MagicMock()

        ok = handle_analyze(client, _params())

        assert ok is True
        mock_first_party.assert_called_once()
        mock_upload.assert_called_once()
        mock_import.assert_called_once()
        assert mock_upload.call_args.args[2] == "SCAN"

    @patch("workbench_agent.handlers.analyze.shutil.rmtree")
    @patch("workbench_agent.handlers.analyze._import_da_report", return_value=True)
    @patch("workbench_agent.handlers.analyze._run_upload_sources", return_value=True)
    @patch(
        "workbench_agent.handlers.analyze.resolve_first_party",
        return_value=_staged_sidecar(),
    )
    @patch("workbench_agent.handlers.analyze.find_or_create_project_and_scan")
    @patch("workbench_agent.handlers.analyze.ToolboxWrapper")
    @patch(
        "workbench_agent.handlers.analyze.resolve_fossid_toolbox_path",
        return_value="/toolbox",
    )
    def test_bazel_emits_source_files(
        self,
        _resolve_toolbox,
        mock_wrapper_cls,
        mock_resolve,
        mock_first_party,
        _upload,
        _import,
        _rmtree,
    ):
        mock_wrapper = _stub_toolbox(mock_wrapper_cls)
        mock_resolve.return_value = ("PROJ", "SCAN", True)

        handle_analyze(MagicMock(), _params())

        assert mock_wrapper.run_da_pipeline.call_args.kwargs["emit_source_files"] is True
        assert mock_first_party.call_args.kwargs["sources_sidecar"] == (
            "/tmp/out/first-party-sources.json"
        )

    @patch("workbench_agent.handlers.analyze.shutil.rmtree")
    @patch("workbench_agent.handlers.analyze._import_da_report", return_value=True)
    @patch("workbench_agent.handlers.analyze._run_upload_sources", return_value=True)
    @patch(
        "workbench_agent.handlers.analyze.resolve_first_party",
        return_value=ResolvedFirstParty(
            scan_root="/ws", owned=False, archive_exclusions={"target", ".git"}
        ),
    )
    @patch("workbench_agent.handlers.analyze.find_or_create_project_and_scan")
    @patch("workbench_agent.handlers.analyze.ToolboxWrapper")
    @patch(
        "workbench_agent.handlers.analyze.resolve_fossid_toolbox_path",
        return_value="/toolbox",
    )
    def test_maven_path_strategy_skips_emit_and_kb_scans_path(
        self,
        _resolve_toolbox,
        mock_wrapper_cls,
        mock_resolve,
        mock_first_party,
        mock_upload,
        mock_import,
        mock_rmtree,
    ):
        mock_wrapper = _stub_toolbox(mock_wrapper_cls)
        mock_resolve.return_value = ("PROJ", "SCAN", True)

        ok = handle_analyze(
            MagicMock(), _params(ecosystem="maven", bazel_target=None)
        )

        assert ok is True
        assert mock_wrapper.run_da_pipeline.call_args.kwargs["emit_source_files"] is False
        assert mock_wrapper.run_da_pipeline.call_args.kwargs["ecosystem"] == "maven"
        mock_upload.assert_called_once()
        assert mock_upload.call_args.kwargs["archive_exclusions"] == {
            "target",
            ".git",
        }
        # Path strategy does not own the project directory — do not rmtree it.
        for call in mock_rmtree.call_args_list:
            assert call.args[0] != "/ws"
        mock_import.assert_called_once()

    @patch("workbench_agent.handlers.analyze.shutil.rmtree")
    @patch("workbench_agent.handlers.analyze._import_da_report", return_value=True)
    @patch("workbench_agent.handlers.analyze._run_blind_scan_sources", return_value=True)
    @patch(
        "workbench_agent.handlers.analyze.resolve_first_party",
        return_value=_staged_sidecar(),
    )
    @patch("workbench_agent.handlers.analyze.find_or_create_project_and_scan")
    @patch("workbench_agent.handlers.analyze.ToolboxWrapper")
    @patch(
        "workbench_agent.handlers.analyze.resolve_fossid_toolbox_path",
        return_value="/toolbox",
    )
    def test_blind_scan_opt_in(
        self,
        _resolve_toolbox,
        mock_wrapper_cls,
        mock_resolve,
        mock_first_party,
        mock_blind,
        mock_import,
        _rmtree,
    ):
        _stub_toolbox(mock_wrapper_cls)
        mock_resolve.return_value = ("PROJ", "SCAN", True)
        client = MagicMock()

        with patch(
            "workbench_agent.handlers.analyze._run_upload_sources"
        ) as mock_upload:
            ok = handle_analyze(client, _params(blind_scan=True))

        assert ok is True
        mock_blind.assert_called_once()
        mock_upload.assert_not_called()
        mock_import.assert_called_once()

    @patch("workbench_agent.handlers.analyze.shutil.rmtree")
    @patch("workbench_agent.handlers.analyze._import_da_report", return_value=True)
    @patch("workbench_agent.handlers.analyze.find_or_create_project_and_scan")
    @patch("workbench_agent.handlers.analyze.ToolboxWrapper")
    @patch(
        "workbench_agent.handlers.analyze.resolve_fossid_toolbox_path",
        return_value="/toolbox",
    )
    def test_empty_sources_skips_kb_still_imports(
        self,
        _resolve_toolbox,
        mock_wrapper_cls,
        mock_resolve,
        mock_import,
        _rmtree,
    ):
        _stub_toolbox(mock_wrapper_cls)
        mock_resolve.return_value = ("PROJ", "SCAN", True)
        client = MagicMock()

        with patch(
            "workbench_agent.handlers.analyze.resolve_first_party",
            return_value=ResolvedFirstParty(scan_root=None, owned=False),
        ), patch(
            "workbench_agent.handlers.analyze._run_upload_sources"
        ) as mock_upload, patch(
            "workbench_agent.handlers.analyze._run_blind_scan_sources"
        ) as mock_blind:
            ok = handle_analyze(client, _params())

        assert ok is True
        mock_upload.assert_not_called()
        mock_blind.assert_not_called()
        mock_import.assert_called_once()

    @patch("workbench_agent.handlers.analyze.shutil.rmtree")
    @patch("workbench_agent.handlers.analyze._import_da_report", return_value=True)
    @patch("workbench_agent.handlers.analyze.find_or_create_project_and_scan")
    @patch("workbench_agent.handlers.analyze.ToolboxWrapper")
    @patch(
        "workbench_agent.handlers.analyze.resolve_fossid_toolbox_path",
        return_value="/toolbox",
    )
    def test_dependency_analysis_only_skips_emit_and_kb(
        self,
        _resolve_toolbox,
        mock_wrapper_cls,
        mock_resolve,
        mock_import,
        _rmtree,
    ):
        mock_wrapper = _stub_toolbox(mock_wrapper_cls)
        mock_resolve.return_value = ("PROJ", "SCAN", True)
        client = MagicMock()

        with patch(
            "workbench_agent.handlers.analyze.resolve_first_party"
        ) as mock_first_party, patch(
            "workbench_agent.handlers.analyze._run_upload_sources"
        ) as mock_upload, patch(
            "workbench_agent.handlers.analyze._run_blind_scan_sources"
        ) as mock_blind:
            ok = handle_analyze(client, _params(dependency_analysis_only=True))

        assert ok is True
        assert mock_wrapper.run_da_pipeline.call_args.kwargs["emit_source_files"] is False
        mock_first_party.assert_not_called()
        mock_upload.assert_not_called()
        mock_blind.assert_not_called()
        mock_import.assert_called_once()

    @patch("workbench_agent.handlers.analyze.shutil.rmtree")
    @patch("workbench_agent.handlers.analyze._import_da_report", return_value=True)
    @patch("workbench_agent.handlers.analyze._run_upload_sources", return_value=True)
    @patch(
        "workbench_agent.handlers.analyze.resolve_first_party",
        return_value=_staged_sidecar(),
    )
    @patch("workbench_agent.handlers.analyze.find_or_create_project_and_scan")
    @patch("workbench_agent.handlers.analyze.ToolboxWrapper")
    @patch(
        "workbench_agent.handlers.analyze.resolve_fossid_toolbox_path",
        return_value="/toolbox",
    )
    @patch("workbench_agent.handlers.analyze.scan_pre_flight_check")
    def test_new_scan_skips_preflight(
        self,
        mock_preflight,
        _resolve_toolbox,
        mock_wrapper_cls,
        mock_resolve,
        _first_party,
        _upload,
        _import,
        _rmtree,
    ):
        _stub_toolbox(mock_wrapper_cls)
        mock_resolve.return_value = ("PROJ", "SCAN", True)

        handle_analyze(MagicMock(), _params())

        mock_preflight.assert_not_called()

    @patch("workbench_agent.handlers.analyze.shutil.rmtree")
    @patch("workbench_agent.handlers.analyze._import_da_report", return_value=True)
    @patch("workbench_agent.handlers.analyze._run_upload_sources", return_value=True)
    @patch(
        "workbench_agent.handlers.analyze.resolve_first_party",
        return_value=_staged_sidecar(),
    )
    @patch("workbench_agent.handlers.analyze.find_or_create_project_and_scan")
    @patch("workbench_agent.handlers.analyze.ToolboxWrapper")
    @patch(
        "workbench_agent.handlers.analyze.resolve_fossid_toolbox_path",
        return_value="/toolbox",
    )
    @patch("workbench_agent.handlers.analyze.scan_pre_flight_check")
    def test_existing_scan_runs_scan_preflight_once(
        self,
        mock_preflight,
        _resolve_toolbox,
        mock_wrapper_cls,
        mock_resolve,
        _first_party,
        _upload,
        _import,
        _rmtree,
    ):
        _stub_toolbox(mock_wrapper_cls)
        mock_resolve.return_value = ("PROJ", "SCAN", False)
        client = MagicMock()
        params = _params()

        handle_analyze(client, params)

        mock_preflight.assert_called_once_with(client, "SCAN", params)
