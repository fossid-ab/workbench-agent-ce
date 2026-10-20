"""Maven ecosystem plugin for ``analyze``."""

from __future__ import annotations

import logging
import os
from argparse import Namespace, _ArgumentGroup

from workbench_agent.utilities.analyze.first_party import FirstPartyStrategy
from workbench_agent.utilities.analyze.registry import AnalyzeEcosystem, register_ecosystem

logger = logging.getLogger("workbench-agent")


def _prepare_maven(params: Namespace) -> None:
    """Prefer the project Maven wrapper when ``--maven-path`` is unset."""
    if getattr(params, "maven_path", None):
        return
    project = getattr(params, "path", None) or "."
    for name in ("mvnw", "mvnw.cmd"):
        candidate = os.path.join(project, name)
        if os.path.isfile(candidate):
            # Relative to project dir — FDA resolves against --input.
            params.maven_path = f"./{name}" if name == "mvnw" else name
            logger.info(
                "Using Maven wrapper at %s (pass --maven-path to override)",
                candidate,
            )
            return


def _add_maven_arguments(group: _ArgumentGroup) -> None:
    group.add_argument(
        "--maven-path",
        dest="maven_path",
        help=(
            "Path to mvn or the project wrapper (e.g. ./mvnw). "
            "Default: ./mvnw under --path when present, else mvn on PATH"
        ),
        required=False,
        metavar="PATH",
    )


MAVEN = register_ecosystem(
    AnalyzeEcosystem(
        name="maven",
        manifests=("pom.xml",),
        first_party=FirstPartyStrategy.PATH,
        required_flags=(),
        pipeline_attrs=("maven_path", "force_pipeline_build"),
        prepare=_prepare_maven,
        add_arguments=_add_maven_arguments,
        config_display_keys=("maven_path", "force_pipeline_build"),
    )
)
