"""
Functional tests for legacy CLI compatibility (underscore flags, no subcommand).

Tests the legacy two-phase pipeline against a real Workbench server:
scan → show-results in a single invocation, then delete-scan cleanup by code.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from tests.functional.cli_helpers import (
    assert_delete_scan_by_code_succeeded,
    run_delete_scan_by_code,
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
            result = subprocess.run(
                [
                    "workbench-agent",
                    "--project_code",
                    project_code,
                    "--scan_code",
                    unique_scan_code,
                    "--path",
                    temp_source_dir,
                ],
                capture_output=True,
                text=True,
            )

            combined = result.stdout + result.stderr
            assert result.returncode == 0, (
                f"Legacy scan/show command failed with exit code {result.returncode}\n"
                f"STDOUT: {result.stdout}\n"
                f"STDERR: {result.stderr}"
            )
            assert "SCAN" in combined
            assert "SHOW-RESULTS" in combined
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
            result = subprocess.run(
                [
                    "workbench-agent",
                    "--project_code",
                    project_code,
                    "--scan_code",
                    unique_scan_code,
                    "--path",
                    temp_source_dir,
                    "--scans_get_results",
                ],
                capture_output=True,
                text=True,
            )

            combined = result.stdout + result.stderr
            assert result.returncode == 0, (
                f"Legacy scans_get_results command failed with exit code {result.returncode}\n"
                f"STDOUT: {result.stdout}\n"
                f"STDERR: {result.stderr}"
            )
            assert "SHOW-RESULTS" in combined
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
            result = subprocess.run(
                [
                    "workbench-agent",
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
                ],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0, (
                f"Legacy command with underscore credentials failed: {result.returncode}\n"
                f"STDOUT: {result.stdout}\n"
                f"STDERR: {result.stderr}"
            )
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
            result = subprocess.run(
                [
                    "workbench-agent",
                    "--project_code",
                    project_code,
                    "--scan_code",
                    unique_scan_code,
                    "--path",
                    str(fossid_path),
                    "--blind_scan",
                ],
                capture_output=True,
                text=True,
            )

            combined = result.stdout + result.stderr
            assert result.returncode == 0, (
                f"Legacy blind-scan command failed with exit code {result.returncode}\n"
                f"STDOUT: {result.stdout}\n"
                f"STDERR: {result.stderr}"
            )
            assert "BLIND-SCAN" in combined
            assert "SHOW-RESULTS" in combined
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
