"""Ecosystem registry for the ``analyze`` command.

Each build-tool ecosystem is a small plugin (:class:`AnalyzeEcosystem`).
The handler and CLI validators stay generic: add a module under
``ecosystems/`` and register it in ``ecosystems/__init__.py``.
"""

from __future__ import annotations

from argparse import ArgumentParser, Namespace, _ArgumentGroup
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Tuple

from workbench_agent.exceptions import ValidationError
from workbench_agent.utilities.analyze.first_party import FirstPartyStrategy

NormalizeFn = Callable[[Namespace], None]
PrepareFn = Callable[[Namespace], None]
AddArgumentsFn = Callable[[_ArgumentGroup], None]


@dataclass(frozen=True)
class AnalyzeEcosystem:
    """How ``analyze`` validates and talks to Toolbox for one ecosystem."""

    name: str
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
    keys = {"ecosystem", "da_timeout", "blind_scan", "fossid_conf_path", "exclude"}
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


def resolve_analyze_ecosystem(params: Namespace) -> AnalyzeEcosystem:
    name = (getattr(params, "ecosystem", None) or "").strip().lower()
    spec = ECOSYSTEMS.get(name)
    if spec is None:
        supported = ", ".join(f"-e {eco}" for eco in supported_ecosystems())
        raise ValidationError(
            f"analyze currently supports {supported} (got {name!r})"
        )
    return spec


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
