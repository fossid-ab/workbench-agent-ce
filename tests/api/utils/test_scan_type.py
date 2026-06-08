"""Tests for scan type classification and reuse compatibility."""

import pytest

from workbench_agent.api.utils.scan_type import (
    GitTarget,
    ScanReuseIssueCode,
    ScanType,
    check_scan_reuse,
    infer_scan_type,
)


def test_infer_scan_type_upload():
    assert infer_scan_type({}) == ScanType.UPLOAD
    assert infer_scan_type({"is_from_report": "0"}) == ScanType.UPLOAD


def test_infer_scan_type_git():
    assert (
        infer_scan_type({"git_repo_url": "https://example.com/repo.git"})
        == ScanType.GIT
    )


def test_infer_scan_type_sbom():
    assert infer_scan_type({"is_from_report": "1"}) == ScanType.SBOM


def test_required_upload_success():
    assert (
        check_scan_reuse({"git_repo_url": None}, required=ScanType.UPLOAD)
        is None
    )


def test_required_upload_rejects_git():
    issue = check_scan_reuse(
        {
            "git_repo_url": "https://github.com/example/repo.git",
            "git_branch": "main",
            "git_ref_type": "branch",
        },
        required=ScanType.UPLOAD,
    )
    assert issue is not None
    assert issue.code == ScanReuseIssueCode.TYPE_MISMATCH
    assert issue.actual == ScanType.GIT
    assert issue.required == ScanType.UPLOAD


def test_required_git_success():
    target = GitTarget(
        url="https://github.com/example/repo.git",
        ref_type="branch",
        ref_value="main",
    )
    scan_info = {
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch",
    }
    assert (
        check_scan_reuse(
            scan_info, required=ScanType.GIT, git_target=target
        )
        is None
    )


def test_required_git_repo_mismatch():
    target = GitTarget(
        url="https://github.com/example/different.git",
        ref_type="branch",
        ref_value="main",
    )
    issue = check_scan_reuse(
        {
            "git_repo_url": "https://github.com/example/repo.git",
            "git_branch": "main",
            "git_ref_type": "branch",
        },
        required=ScanType.GIT,
        git_target=target,
    )
    assert issue is not None
    assert issue.code == ScanReuseIssueCode.GIT_REPO_MISMATCH


def test_required_git_ref_type_mismatch():
    target = GitTarget(
        url="https://github.com/example/repo.git",
        ref_type="tag",
        ref_value="v1.0.0",
    )
    issue = check_scan_reuse(
        {
            "git_repo_url": "https://github.com/example/repo.git",
            "git_branch": "main",
            "git_ref_type": "branch",
        },
        required=ScanType.GIT,
        git_target=target,
    )
    assert issue is not None
    assert issue.code == ScanReuseIssueCode.GIT_REF_TYPE_MISMATCH


def test_required_sbom_success():
    assert (
        check_scan_reuse({"is_from_report": "1"}, required=ScanType.SBOM)
        is None
    )


def test_required_sbom_rejects_upload():
    issue = check_scan_reuse(
        {"is_from_report": "0", "git_repo_url": None},
        required=ScanType.SBOM,
    )
    assert issue is not None
    assert issue.code == ScanReuseIssueCode.TYPE_MISMATCH
    assert issue.actual == ScanType.UPLOAD


def test_required_upload_rejects_sbom():
    issue = check_scan_reuse(
        {"is_from_report": "1"},
        required=ScanType.UPLOAD,
    )
    assert issue is not None
    assert issue.actual == ScanType.SBOM
    assert issue.required == ScanType.UPLOAD


def test_required_git_rejects_sbom():
    target = GitTarget(
        url="https://github.com/test/repo.git",
        ref_type="branch",
        ref_value="main",
    )
    issue = check_scan_reuse(
        {"is_from_report": "1"},
        required=ScanType.GIT,
        git_target=target,
    )
    assert issue is not None
    assert issue.actual == ScanType.SBOM


def test_forbidden_sbom_rejects_sbom():
    issue = check_scan_reuse(
        {"is_from_report": "1"},
        forbidden=frozenset({ScanType.SBOM}),
    )
    assert issue is not None
    assert issue.code == ScanReuseIssueCode.TYPE_FORBIDDEN
    assert issue.actual == ScanType.SBOM


def test_forbidden_sbom_allows_upload():
    assert (
        check_scan_reuse(
            {"git_repo_url": None},
            forbidden=frozenset({ScanType.SBOM}),
        )
        is None
    )


def test_check_scan_reuse_requires_constraint():
    with pytest.raises(ValueError, match="requires required or forbidden"):
        check_scan_reuse({})
