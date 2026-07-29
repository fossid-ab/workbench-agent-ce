"""Unit tests for Bazel source-label helpers."""

from workbench_agent.utilities.bazel_sources import label_to_workspace_path


class TestLabelToWorkspacePath:
    def test_package_file(self):
        assert (
            label_to_workspace_path("//rest_tokio:src/main.rs")
            == "rest_tokio/src/main.rs"
        )

    def test_root_package_file(self):
        assert label_to_workspace_path("//:README.md") == "README.md"

    def test_skips_external_labels(self):
        assert label_to_workspace_path("@crates//:tokio") is None
        assert label_to_workspace_path("@@rules_rust++crate+crates__tokio-1.0//:tokio") is None

    def test_skips_build_metadata(self):
        assert label_to_workspace_path("//pkg:BUILD") is None
        assert label_to_workspace_path("//pkg:BUILD.bazel") is None
        assert label_to_workspace_path("//:MODULE.bazel") is None

    def test_strips_config_annotation(self):
        assert (
            label_to_workspace_path("//pkg:src/lib.rs (abc123)")
            == "pkg/src/lib.rs"
        )

    def test_rejects_malformed(self):
        assert label_to_workspace_path("") is None
        assert label_to_workspace_path("//pkg") is None
        assert label_to_workspace_path("not-a-label") is None
