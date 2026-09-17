"""
Functional tests for legacy CLI compatibility (underscore flags, no subcommand).

Tests the legacy two-phase pipeline against a real Workbench server:
scan → show-results in a single invocation, then delete-scan cleanup by code.
"""

import json
import shutil
from pathlib import Path

import pytest

from tests.functional.cli_helpers import (
    assert_delete_scan_by_code_succeeded,
    assert_legacy_succeeded,
    run_delete_scan_by_code,
    run_legacy_workbench_agent,
)


@pytest.mark.functional
@pytest.mark.requires_workbench
class TestLegacyWorkflow:
    """Legacy argv translation + orchestration against Workbench."""

    def test_legacy_scan_and_show_licenses(
        self,
        workbench_config,
        temp_source_dir,
        project_code,
        unique_scan_code,
    ):
        """
        Default legacy flow: upload scan, then show licenses (no subcommand).

        Credentials come from WORKBENCH_* env vars (same as modern commands).
        """
        scan_created = False
        try:
            print(
                f"\n[LEGACY] Running scan + show-licenses "
                f"(project_code={project_code!r}, scan_code={unique_scan_code!r})"
            )
            result = run_legacy_workbench_agent(
                "--project_code",
                project_code,
                "--scan_code",
                unique_scan_code,
                "--path",
                temp_source_dir,
            )
            combined = assert_legacy_succeeded(result)
            assert "Workbench Agent finished successfully" in combined
            scan_created = True
            print("[LEGACY] ✓ Scan and default show-licenses completed")
        finally:
            if scan_created:
                print(f"[LEGACY] Cleanup: deleting scan_code={unique_scan_code!r}")
                delete_result = run_delete_scan_by_code(project_code, unique_scan_code)
                assert_delete_scan_by_code_succeeded(
                    delete_result,
                    project_code,
                    unique_scan_code,
                )
                print("[LEGACY] Cleanup: ✓ Scan removed from Workbench")

    def test_legacy_scans_get_results(
        self,
        temp_source_dir,
        project_code,
        unique_scan_code,
    ):
        """Legacy ``--scans_get_results`` maps to show-matches in phase 2."""
        scan_created = False
        try:
            print(f"\n[LEGACY] Running scan + --scans_get_results (scan_code={unique_scan_code!r})")
            result = run_legacy_workbench_agent(
                "--project_code",
                project_code,
                "--scan_code",
                unique_scan_code,
                "--path",
                temp_source_dir,
                "--scans_get_results",
            )
            assert_legacy_succeeded(result)
            scan_created = True
            print("[LEGACY] ✓ Scan and show-matches completed")
        finally:
            if scan_created:
                delete_result = run_delete_scan_by_code(project_code, unique_scan_code)
                assert_delete_scan_by_code_succeeded(
                    delete_result,
                    project_code,
                    unique_scan_code,
                )

    def test_legacy_with_underscore_credentials(
        self,
        workbench_config,
        temp_source_dir,
        project_code,
        unique_scan_code,
    ):
        """Legacy ``--api_url`` / ``--api_user`` / ``--api_token`` flags work end-to-end."""
        scan_created = False
        try:
            result = run_legacy_workbench_agent(
                "--api_url",
                workbench_config["url"],
                "--api_user",
                workbench_config["user"],
                "--api_token",
                workbench_config["token"],
                "--project_code",
                project_code,
                "--scan_code",
                unique_scan_code,
                "--path",
                temp_source_dir,
            )
            assert_legacy_succeeded(result)
            scan_created = True
        finally:
            if scan_created:
                delete_result = run_delete_scan_by_code(project_code, unique_scan_code)
                assert_delete_scan_by_code_succeeded(
                    delete_result,
                    project_code,
                    unique_scan_code,
                )


@pytest.mark.functional
@pytest.mark.requires_workbench
class TestLegacyBlindScanWorkflow:
    """Legacy ``--blind_scan`` routing against Workbench."""

    def test_legacy_blind_scan_and_show_licenses(
        self,
        temp_source_dir,
        project_code,
        unique_scan_code,
        fixtures_dir,
    ):
        """
        Legacy blind scan using a pre-generated ``.fossid`` file (no toolbox).

        Archive extraction flags are ignored for blind-scan, same as modern CLI.
        """
        signatures_src = fixtures_dir / "signatures"
        assert signatures_src.is_file(), f"Missing fixture: {signatures_src}"
        fossid_path = Path(temp_source_dir) / "signatures.fossid"
        shutil.copy(signatures_src, fossid_path)

        scan_created = False
        try:
            print(
                f"\n[LEGACY-BLIND] blind_scan + show-licenses "
                f"(scan_code={unique_scan_code!r})"
            )
            result = run_legacy_workbench_agent(
                "--project_code",
                project_code,
                "--scan_code",
                unique_scan_code,
                "--path",
                str(fossid_path),
                "--blind_scan",
            )
            assert_legacy_succeeded(result, expected_scan_section="BLIND-SCAN")
            scan_created = True
            print("[LEGACY-BLIND] ✓ Blind scan and show-licenses completed")
        finally:
            if scan_created:
                delete_result = run_delete_scan_by_code(project_code, unique_scan_code)
                assert_delete_scan_by_code_succeeded(
                    delete_result,
                    project_code,
                    unique_scan_code,
                )


@pytest.mark.functional
@pytest.mark.requires_workbench
class TestLegacyFlagCoverage:
    """Live coverage for remaining legacy scan/show flags."""

    def test_legacy_kitchen_sink_and_path_result(
        self,
        temp_source_dir,
        temp_reports_dir,
        project_code,
        unique_scan_code,
    ):
        """Legacy scan flags map to CE scan + default show-licenses and save JSON."""
        result_path = temp_reports_dir / "legacy-kitchen.json"
        scan_created = False
        try:
            result = run_legacy_workbench_agent(
                "--project_code",
                project_code,
                "--scan_code",
                unique_scan_code,
                "--path",
                temp_source_dir,
                "--limit=5",
                "--sensitivity=5",
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
                "20",
                "--chunked_upload",
                "--scan_number_of_tries",
                "40",
                "--scan_wait_time",
                "10",
                "--log",
                "INFO",
                "--path-result",
                str(result_path),
            )
            combined = assert_legacy_succeeded(result)
            assert "Workbench Agent finished successfully" in combined
            assert result_path.is_file()
            saved = json.loads(result_path.read_text())
            assert isinstance(saved, dict)
            scan_created = True
        finally:
            if scan_created:
                delete_result = run_delete_scan_by_code(project_code, unique_scan_code)
                assert_delete_scan_by_code_succeeded(
                    delete_result,
                    project_code,
                    unique_scan_code,
                )

    @pytest.mark.parametrize(
        "legacy_flag",
        [
            "--get_scan_identified_components",
            "--scans_get_policy_warnings_counter",
            "--projects_get_policy_warnings_info",
        ],
    )
    def test_legacy_result_flag_modes(
        self,
        temp_source_dir,
        project_code,
        unique_scan_code,
        legacy_flag,
    ):
        """Each remaining legacy result flag completes the show-results phase."""
        scan_created = False
        try:
            result = run_legacy_workbench_agent(
                "--project_code",
                project_code,
                "--scan_code",
                unique_scan_code,
                "--path",
                temp_source_dir,
                legacy_flag,
            )
            assert_legacy_succeeded(result)
            scan_created = True
        finally:
            if scan_created:
                delete_result = run_delete_scan_by_code(project_code, unique_scan_code)
                assert_delete_scan_by_code_succeeded(
                    delete_result,
                    project_code,
                    unique_scan_code,
                )

    def test_legacy_da_only(
        self,
        temp_source_dir,
        project_code,
        unique_scan_code,
    ):
        """Legacy ``--run_only_dependency_analysis`` skips KB scan and still shows results."""
        scan_created = False
        try:
            result = run_legacy_workbench_agent(
                "--project_code",
                project_code,
                "--scan_code",
                unique_scan_code,
                "--path",
                temp_source_dir,
                "--run_only_dependency_analysis",
            )
            assert_legacy_succeeded(result)
            scan_created = True
        finally:
            if scan_created:
                delete_result = run_delete_scan_by_code(project_code, unique_scan_code)
                assert_delete_scan_by_code_succeeded(
                    delete_result,
                    project_code,
                    unique_scan_code,
                )

    def test_legacy_target_path_rejected(
        self,
        temp_source_dir,
        project_code,
        unique_scan_code,
    ):
        """Legacy ``--target_path`` is rejected before any Workbench write."""
        result = run_legacy_workbench_agent(
            "--project_code",
            project_code,
            "--scan_code",
            unique_scan_code,
            "--path",
            temp_source_dir,
            "--target_path",
            "/server/path",
        )
        assert result.returncode == 2
        combined = result.stdout + result.stderr
        assert "target_path" in combined
        assert "SHOW-RESULTS" not in combined

    def test_legacy_reuse_specific_scan(
        self,
        temp_source_dir,
        project_code,
        unique_scan_code,
    ):
        """Reuse identifications from a prior legacy scan via ``specific_scan``."""
        source_code = unique_scan_code
        dest_code = f"{unique_scan_code[:26]}Reuse"
        created = []
        try:
            source = run_legacy_workbench_agent(
                "--project_code",
                project_code,
                "--scan_code",
                source_code,
                "--path",
                temp_source_dir,
            )
            assert_legacy_succeeded(source)
            created.append(source_code)

            dest = run_legacy_workbench_agent(
                "--project_code",
                project_code,
                "--scan_code",
                dest_code,
                "--path",
                temp_source_dir,
                "--reuse_identifications",
                "--identification_reuse_type",
                "specific_scan",
                "--specific_code",
                source_code,
            )
            assert_legacy_succeeded(dest)
            created.append(dest_code)
        finally:
            for scan_code in reversed(created):
                delete_result = run_delete_scan_by_code(project_code, scan_code)
                assert_delete_scan_by_code_succeeded(
                    delete_result,
                    project_code,
                    scan_code,
                )
