"""Scans API client package."""

from .client import ScansClient
from .errors import is_scan_not_found

__all__ = ["ScansClient", "is_scan_not_found"]
