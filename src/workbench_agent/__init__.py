"""
FossID Workbench Agent - Modular API client for automated scanning
"""

__version__ = "0.8.0"

# Import main API client
from .api.workbench_client import WorkbenchClient

__all__ = ["WorkbenchClient"]
