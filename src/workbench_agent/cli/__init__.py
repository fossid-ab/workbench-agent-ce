"""
CLI module for workbench-agent.

This module provides command-line argument parsing and validation
functionality.
"""

from .parser import parse_cmdline_args

__all__ = [
    "parse_cmdline_args",
    "validate_parsed_args",
]


def validate_parsed_args(*args, **kwargs):
    """Deferred import so scan/show commands do not load validators at package import."""
    from .validators import validate_parsed_args as _validate_parsed_args

    return _validate_parsed_args(*args, **kwargs)
