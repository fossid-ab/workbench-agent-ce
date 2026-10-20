"""Ecosystem registry for the ``analyze`` command.

Each build-tool ecosystem is a small plugin (:class:`AnalyzeEcosystem`).
The handler and CLI validators stay generic: add a module under
``ecosystems/`` and register it in ``ecosystems/__init__.py``.
"""

from __future__ import annotations

import logging
import os
from argparse import ArgumentParser, Namespace, _ArgumentGroup
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from workbench_agent.exceptions import ValidationError
from workbench_agent.utilities.analyze.first_party import FirstPartyStrategy

logger = logging.getLogger("workbench-agent")

NormalizeFn = Callable[[Namespace], None]
PrepareFn = Callable[[Namespace], None]
AddArgumentsFn = Callable[[_ArgumentGroup], None]


@dataclass(frozen=True)
class AnalyzeEcosystem:
    """How ``analyze`` validates and talks to Toolbox for one ecosystem."""

    name: str
    #: Project-root filenames that identify this ecosystem. Used when ``-e`` is omitted.
    manifests: Tuple[str, ...] = ()
    first_party: FirstPartyStrategy = FirstPartyStrategy.SIDECAR
    # (namespace attr, CLI flag, optional example value)
    required_flags: Tuple[Tuple[str, str, Optional[str]], ...] = ()
    #: Namespace attrs forwarded to ``run_da_pipeline`` when set.
    pipeline_attrs: Tuple[str, ...] = ()
    scope_attr: Optional[str] = None
    normalize: Optional[NormalizeFn] = None
    prepare: Optional[PrepareFn] = None
    add_arguments: Optional[AddArgumentsFn] = None
    config_display_keys: Tuple[str, ...] = field(default_factory=tuple)

    def validate(self, params: Namespace) -> None:
        if self.normalize is not None:
            self.normalize(params)
        for attr, flag, example in self.required_flags:
            value = getattr(params, attr, None)
            if not value or not str(value).strip():
                message = f"analyze with -e {self.name} requires {flag}"
                if example:
                    message += f" (e.g. {flag} {example!r})"
                raise ValidationError(message)
        if self.prepare is not None:
            self.prepare(params)

    def pipeline_kwargs(self, params: Namespace) -> Dict[str, object]:
        kwargs: Dict[str, object] = {"ecosystem": self.name}
        for attr in self.pipeline_attrs:
            value = getattr(params, attr, None)
            if isinstance(value, bool):
                if value:
                    kwargs[attr] = value
            elif value is not None and value != "":
                kwargs[attr] = value
        return kwargs

    def scope_label(self, params: Namespace) -> str:
        if self.scope_attr:
            value = getattr(params, self.scope_attr, None)
            if value:
                return str(value)
        return self.name


ECOSYSTEMS: Dict[str, AnalyzeEcosystem] = {}


def register_ecosystem(spec: AnalyzeEcosystem) -> AnalyzeEcosystem:
    """Register an ecosystem plugin. Returns ``spec`` for decorator-style use."""
    ECOSYSTEMS[spec.name] = spec
    return spec


def supported_ecosystems() -> Tuple[str, ...]:
    return tuple(sorted(ECOSYSTEMS))


def all_config_display_keys() -> frozenset[str]:
    keys = {
        "ecosystem",
        "da_timeout",
        "blind_scan",
        "fossid_conf_path",
        "exclude",
        "buildless",
    }
    for spec in ECOSYSTEMS.values():
        keys.update(spec.config_display_keys)
        keys.update(spec.pipeline_attrs)
    return frozenset(keys)


def register_ecosystem_cli_arguments(parser: ArgumentParser) -> None:
    """Add per-ecosystem argument groups to the analyze parser."""
    for name in supported_ecosystems():
        spec = ECOSYSTEMS[name]
        if spec.add_arguments is None:
            continue
        group = parser.add_argument_group(f"{name} options")
        spec.add_arguments(group)


def detect_ecosystems(project_dir: str) -> List[str]:
    """Return supported ecosystems whose marker files exist in ``project_dir``."""
    found: List[str] = []
    for name in supported_ecosystems():
        spec = ECOSYSTEMS[name]
        if any(os.path.isfile(os.path.join(project_dir, marker)) for marker in spec.manifests):
            found.append(name)
    return found


def resolve_analyze_ecosystem(params: Namespace) -> AnalyzeEcosystem:
    name = (getattr(params, "ecosystem", None) or "").strip().lower()
    if not name:
        name = _autodetect_ecosystem(params)
        params.ecosystem = name
    spec = ECOSYSTEMS.get(name)
    if spec is None:
        supported = ", ".join(f"-e {eco}" for eco in supported_ecosystems())
        raise ValidationError(
            f"analyze currently supports {supported} (got {name!r})"
        )
    return spec


def _autodetect_ecosystem(params: Namespace) -> str:
    """Pick the ecosystem when ``-e`` was omitted. Exactly one marker set must match."""
    project_dir = getattr(params, "path", None) or "."
    found = detect_ecosystems(project_dir)
    supported = ", ".join(f"-e {eco}" for eco in supported_ecosystems())
    if len(found) == 1:
        chosen = found[0]
        print(
            f"Detected {chosen} project in {project_dir}. "
            f"Pass -e to choose a different build tool."
        )
        logger.info("Auto-selected analyze ecosystem %s for %s", chosen, project_dir)
        return chosen
    if not found:
        raise ValidationError(
            f"No supported build tool detected in {project_dir}. "
            f"Pass {supported}."
        )
    listed = ", ".join(found)
    raise ValidationError(
        f"Several build tools detected in {project_dir} ({listed}). "
        f"Pass {supported} to choose one."
    )


# Flags that only apply to ``fossid-toolbox da --pipeline``.
_PIPELINE_ONLY_FLAGS = (
    ("force_pipeline_build", "--force-pipeline-build"),
    ("bazel_target", "--bazel-target"),
    ("bazel_path", "--bazel-path"),
    ("bazel_mode", "--bazel-mode"),
    ("maven_path", "--maven-path"),
)


def reject_buildless_pipeline_flags(params: Namespace) -> None:
    """``--buildless`` resolves manifests; pipeline flags do not apply."""
    if not getattr(params, "buildless", False):
        return
    for attr, flag in _PIPELINE_ONLY_FLAGS:
        value = getattr(params, attr, None)
        if value:
            raise ValidationError(f"{flag} cannot be used with --buildless")


def prepare_analyze_run(params: Namespace) -> Optional[AnalyzeEcosystem]:
    """Validate analyze flags.

    Returns the ecosystem plugin for a pipeline run, or ``None`` for
    ``--buildless`` (any Toolbox DA ecosystem, no build tool).
    """
    if getattr(params, "buildless", False):
        reject_buildless_pipeline_flags(params)
        return None
    return validate_analyze_ecosystem(params)


def validate_analyze_ecosystem(params: Namespace) -> AnalyzeEcosystem:
    """Validate ecosystem-specific analyze flags. Mutates params if needed."""
    spec = resolve_analyze_ecosystem(params)
    spec.validate(params)
    return spec


def da_pipeline_kwargs(params: Namespace) -> Dict[str, object]:
    """Keyword args to pass through to ``ToolboxWrapper.run_da_pipeline``."""
    return resolve_analyze_ecosystem(params).pipeline_kwargs(params)


def ecosystem_scope_label(params: Namespace) -> str:
    """User-facing label for the analyzed unit (target, module, …)."""
    return resolve_analyze_ecosystem(params).scope_label(params)


def ecosystem_first_party_strategy(params: Namespace) -> FirstPartyStrategy:
    return resolve_analyze_ecosystem(params).first_party
