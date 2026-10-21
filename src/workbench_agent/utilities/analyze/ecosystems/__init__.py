"""Register all ``analyze`` ecosystem plugins."""

from workbench_agent.utilities.analyze.ecosystems.bazel import BAZEL
from workbench_agent.utilities.analyze.ecosystems.maven import MAVEN

__all__ = ["BAZEL", "MAVEN"]
