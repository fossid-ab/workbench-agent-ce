"""Uploads API client package."""

from .client import UploadsClient
from .errors import (
    HEADER_FILE_NAME,
    HEADER_SCAN_CODE,
    HEADER_UPLOAD_TYPE,
    UPLOAD_TYPE_DEPENDENCY_ANALYSIS,
)

__all__ = [
    "UploadsClient",
    "HEADER_SCAN_CODE",
    "HEADER_FILE_NAME",
    "HEADER_UPLOAD_TYPE",
    "UPLOAD_TYPE_DEPENDENCY_ANALYSIS",
]
