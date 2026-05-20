# tests/unit/cli/test_fossid_toolbox_parser.py

from workbench_agent.cli.parent_parsers import create_fossid_toolbox_parser


class TestFossidToolboxParser:
    """Test the FossID Toolbox parent parser."""

    def test_create_fossid_toolbox_parser(self):
        parser = create_fossid_toolbox_parser()
        assert parser is not None
        assert parser.add_help is False

    def test_default_timeout(self):
        parser = create_fossid_toolbox_parser()
        args = parser.parse_args([])
        assert args.fossid_toolbox_timeout == 300
        assert args.fossid_toolbox_path is None

    def test_custom_timeout_and_path(self):
        parser = create_fossid_toolbox_parser()
        args = parser.parse_args(
            [
                "--fossid-toolbox-path",
                "/opt/fossid-toolbox",
                "--fossid-toolbox-timeout",
                "600",
            ]
        )
        assert args.fossid_toolbox_path == "/opt/fossid-toolbox"
        assert args.fossid_toolbox_timeout == 600
