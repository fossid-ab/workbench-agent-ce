"""
CLI module for workbench-agent.

This module provides command-line argument parsing and validation
functionality.
"""

from .parser import parse_cmdline_args

__all__ = [
    "parse_cmdline_args",
]
