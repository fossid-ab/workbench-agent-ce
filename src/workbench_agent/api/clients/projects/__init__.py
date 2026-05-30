"""Projects API client package."""

from .client import ProjectsClient
from .errors import is_project_not_found

__all__ = ["ProjectsClient", "is_project_not_found"]
