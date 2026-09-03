"""Tests for the projectscan parent parser."""

from workbench_agent.cli.parent_parsers import create_projectscan_parser


class TestProjectscanParser:
    def test_create_projectscan_parser(self):
        parser = create_projectscan_parser()
        assert parser is not None
        assert parser.add_help is False

    def test_use_projectscan_default_false(self):
        args = create_projectscan_parser().parse_args([])
        assert args.use_projectscan is False

    def test_use_projectscan_default_true(self):
        args = create_projectscan_parser(default_use_projectscan=True).parse_args([])
        assert args.use_projectscan is True

    def test_use_projectscan_flag(self):
        args = create_projectscan_parser().parse_args(["--use-projectscan"])
        assert args.use_projectscan is True

    def test_argument_group_name(self):
        help_text = create_projectscan_parser().format_help()
        assert "Projectscan" in help_text
        assert "--use-projectscan" in help_text
