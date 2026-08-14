"""Unit tests for the analyze handler orchestration."""

import argparse
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.exceptions import ValidationError
from workbench_agent.handlers.analyze import handle_analyze
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
        input="/ws",
        ecosystem="bazel",
        bazel_target="//app:bin",
        bazel_path=None,
        bazel_mode=None,
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


class TestHandleAnalyze:
    def test_rejects_non_bazel(self):
        client = MagicMock()
        with pytest.raises(ValidationError, match="only -e bazel"):
            handle_analyze(client, _params(ecosystem="maven"))

    def test_rejects_missing_target(self):
        client = MagicMock()
        with pytest.raises(ValidationError, match="--bazel-target"):
            handle_analyze(client, _params(bazel_target=None))

    @patch("workbench_agent.handlers.analyze.shutil.rmtree")
    @patch("workbench_agent.handlers.analyze._import_da_report", return_value=True)
    @patch("workbench_agent.handlers.analyze._run_upload_sources", return_value=True)
    @patch("workbench_agent.handlers.analyze.stage_sources", return_value="/tmp/stage")
    @patch(
        "workbench_agent.handlers.analyze.load_first_party_sources",
        return_value=["src/main.rs"],
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
        mock_load,
        mock_stage,
        mock_upload,
        mock_import,
        _rmtree,
    ):
        _stub_toolbox(mock_wrapper_cls)
        mock_resolve.return_value = ("PROJ", "SCAN", True)
        client = MagicMock()

        ok = handle_analyze(client, _params())

        assert ok is True
        mock_stage.assert_called_once()
        mock_upload.assert_called_once()
        mock_import.assert_called_once()
        assert mock_upload.call_args.args[2] == "SCAN"

    @patch("workbench_agent.handlers.analyze.shutil.rmtree")
    @patch("workbench_agent.handlers.analyze._import_da_report", return_value=True)
    @patch("workbench_agent.handlers.analyze._run_upload_sources", return_value=True)
    @patch("workbench_agent.handlers.analyze.stage_sources", return_value="/tmp/stage")
    @patch(
        "workbench_agent.handlers.analyze.load_first_party_sources",
        return_value=["src/main.rs"],
    )
    @patch("workbench_agent.handlers.analyze.find_or_create_project_and_scan")
    @patch("workbench_agent.handlers.analyze.ToolboxWrapper")
    @patch(
        "workbench_agent.handlers.analyze.resolve_fossid_toolbox_path",
        return_value="/toolbox",
    )
    def test_sources_come_from_the_toolbox_da_sidecar(
        self,
        _resolve_toolbox,
        mock_wrapper_cls,
        mock_resolve,
        mock_load,
        _stage,
        _upload,
        _import,
        _rmtree,
    ):
        mock_wrapper = _stub_toolbox(mock_wrapper_cls)
        mock_resolve.return_value = ("PROJ", "SCAN", True)
        client = MagicMock()

        handle_analyze(client, _params())

        # Toolbox DA is asked for the source list, and the agent reads
        # exactly the sidecar it reported — no bazel query of its own.
        assert mock_wrapper.run_da_pipeline.call_args.kwargs["emit_source_files"] is True
        mock_load.assert_called_once_with("/tmp/out/first-party-sources.json")

    @patch("workbench_agent.handlers.analyze.shutil.rmtree")
    @patch("workbench_agent.handlers.analyze._import_da_report", return_value=True)
    @patch("workbench_agent.handlers.analyze._run_blind_scan_sources", return_value=True)
    @patch("workbench_agent.handlers.analyze.stage_sources", return_value="/tmp/stage")
    @patch(
        "workbench_agent.handlers.analyze.load_first_party_sources",
        return_value=["src/main.rs"],
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
        mock_load,
        mock_stage,
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
            "workbench_agent.handlers.analyze.load_first_party_sources",
            return_value=[],
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
