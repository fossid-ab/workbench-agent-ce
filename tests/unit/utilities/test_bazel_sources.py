"""Unit tests for loading and staging fda's first-party source list."""

import json
import os

import pytest

from workbench_agent.exceptions import FileSystemError, ValidationError
from workbench_agent.utilities.bazel_sources import (
    load_first_party_sources,
    stage_sources,
)


def _write_sidecar(tmp_path, payload):
    path = tmp_path / "first-party-sources.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


class TestLoadFirstPartySources:
    def test_returns_the_listed_files(self, tmp_path):
        path = _write_sidecar(
            tmp_path,
            {
                "schema_version": 1,
                "ecosystem": "bazel",
                "project_dir": "/ws",
                "scope": {"bazel_target": "//app:bin"},
                "files": ["app/main.rs", "app/util.rs"],
                "missing": ["app/generated.rs"],
                "method": "bazel_query_source_file",
            },
        )
        assert load_first_party_sources(path) == ["app/main.rs", "app/util.rs"]

    def test_empty_list_is_valid(self, tmp_path):
        path = _write_sidecar(
            tmp_path,
            {"schema_version": 1, "files": [], "method": "unsupported"},
        )
        assert load_first_party_sources(path) == []

    def test_missing_file_is_an_error(self, tmp_path):
        with pytest.raises(FileSystemError, match="Failed to read"):
            load_first_party_sources(str(tmp_path / "nope.json"))

    def test_malformed_json_is_an_error(self, tmp_path):
        path = tmp_path / "first-party-sources.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(FileSystemError, match="not valid JSON"):
            load_first_party_sources(str(path))

    def test_unknown_schema_version_is_rejected(self, tmp_path):
        path = _write_sidecar(tmp_path, {"schema_version": 99, "files": []})
        with pytest.raises(ValidationError, match="schema_version"):
            load_first_party_sources(path)

    def test_malformed_files_entry_is_rejected(self, tmp_path):
        path = _write_sidecar(tmp_path, {"schema_version": 1, "files": [1, 2]})
        with pytest.raises(FileSystemError, match="malformed"):
            load_first_party_sources(path)


class TestStageSources:
    def test_copies_files_preserving_relative_layout(self, tmp_path):
        workspace = tmp_path / "ws"
        (workspace / "app").mkdir(parents=True)
        (workspace / "app" / "main.rs").write_text("fn main() {}", encoding="utf-8")
        (workspace / "README.md").write_text("hi", encoding="utf-8")

        staging_dir = stage_sources(str(workspace), ["app/main.rs", "README.md"])

        assert os.path.isfile(os.path.join(staging_dir, "app", "main.rs"))
        assert os.path.isfile(os.path.join(staging_dir, "README.md"))

    def test_rejects_an_empty_list(self, tmp_path):
        with pytest.raises(ValidationError, match="No first-party source files"):
            stage_sources(str(tmp_path), [])
