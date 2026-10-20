"""Tests for analyze first-party strategies."""

from workbench_agent.utilities.analyze.first_party import (
    FirstPartyStrategy,
    path_exclusion_names,
    resolve_first_party,
    stage_filtered_tree,
)


def test_path_exclusion_names_include_defaults_and_user():
    names = path_exclusion_names("foo,bar")
    assert "foo" in names
    assert "bar" in names
    assert ".git" in names
    assert "target" in names


def test_resolve_path_upload_uses_project_root(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.java").write_text("class A {}")
    resolved = resolve_first_party(
        strategy=FirstPartyStrategy.PATH,
        project_path=str(tmp_path),
        sources_sidecar=None,
        user_excludes=None,
        blind_scan=False,
    )
    assert resolved.scan_root == str(tmp_path)
    assert resolved.owned is False
    assert resolved.archive_exclusions is not None
    assert "target" in resolved.archive_exclusions


def test_stage_filtered_tree_skips_excluded_dirs(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.java").write_text("class A {}")
    (tmp_path / "target").mkdir()
    (tmp_path / "target" / "A.class").write_text("bytes")

    staged = stage_filtered_tree(str(tmp_path), {"target", ".git"})
    assert staged is not None
    import os
    import shutil

    assert os.path.isfile(os.path.join(staged, "src", "A.java"))
    assert not os.path.exists(os.path.join(staged, "target", "A.class"))
    shutil.rmtree(staged, ignore_errors=True)
