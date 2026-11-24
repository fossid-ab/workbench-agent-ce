"""Parser and validation tests for quick-scan license policy flags."""

import pytest

from workbench_agent.cli import parse_cmdline_args
from workbench_agent.exceptions import ValidationError

GLOBAL = ["--api-url", "https://test.com", "--api-user", "u", "--api-token", "t"]


@pytest.fixture
def scan_file(tmp_path):
    path = tmp_path / "a.py"
    path.write_text("x = 1\n")
    return str(path)


@pytest.mark.unit
class TestQuickScanPolicyFlags:
    def test_defaults_have_no_project(self, scan_file):
        parsed = parse_cmdline_args(["quick-scan", *GLOBAL, scan_file])
        assert parsed.project_name is None
        assert parsed.project_code is None
        assert parsed.path == scan_file

    @pytest.mark.parametrize("flag", ["--project", "--project-name"])
    def test_project_name_aliases(self, scan_file, flag):
        parsed = parse_cmdline_args(["quick-scan", *GLOBAL, scan_file, flag, "acme"])
        assert parsed.project_name == "acme"

    def test_project_code(self, scan_file):
        parsed = parse_cmdline_args(["quick-scan", *GLOBAL, scan_file, "--project-code", "PRJ-1"])
        assert parsed.project_code == "PRJ-1"

    def test_name_and_code_together_rejected(self, scan_file):
        with pytest.raises(ValidationError, match="not both"):
            parse_cmdline_args(
                [
                    "quick-scan",
                    *GLOBAL,
                    scan_file,
                    "--project",
                    "acme",
                    "--project-code",
                    "PRJ-1",
                ]
            )
