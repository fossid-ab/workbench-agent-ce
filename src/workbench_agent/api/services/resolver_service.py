"""
Deprecated shim — delegates to ``workbench_agent.services.resolver_service``.

Preserved for ``client.resolver`` until in-tree ``api/`` is removed.
"""

from workbench_agent.services.resolver_service import ResolverService as _CeResolverService
from workbench_agent.services.types import (
    ResolutionResult,
    ResolvedScan,
    ResolvedTargets,
)


class ResolverService(_CeResolverService):
    """Backward-compatible alias for CE ResolverService."""


__all__ = [
    "ResolutionResult",
    "ResolvedScan",
    "ResolvedTargets",
    "ResolverService",
]
