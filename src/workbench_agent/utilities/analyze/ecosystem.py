"""Backward-compatible facade for the analyze ecosystem registry.

Prefer importing from ``workbench_agent.utilities.analyze.registry``.
Importing this module also loads ecosystem plugins.
"""

from __future__ import annotations

import workbench_agent.utilities.analyze.ecosystems  # noqa: F401  # register plugins
from workbench_agent.utilities.analyze.registry import (  # noqa: F401
    ECOSYSTEMS,
    AnalyzeEcosystem,
    all_config_display_keys,
    da_pipeline_kwargs,
    ecosystem_first_party_strategy,
    ecosystem_scope_label,
    register_ecosystem_cli_arguments,
    resolve_analyze_ecosystem,
    supported_ecosystems,
    validate_analyze_ecosystem,
)
