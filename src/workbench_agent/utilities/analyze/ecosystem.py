"""Ecosystem registry for the ``analyze`` command.

Adding a Toolbox DA ecosystem later means a new ``AnalyzeEcosystem`` entry
here (required flags, optional normalizer) and, if Toolbox needs new
flags, those attr names on ``TOOLBOX_PIPELINE_ATTRS``. The handler and
CLI validators stay generic.
"""

from __future__ import annotations

from argparse import Namespace
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

from workbench_agent.exceptions import ValidationError

NormalizeFn = Callable[[Namespace], None]

# Namespace attrs forwarded to ``run_da_pipeline`` when set.
TOOLBOX_PIPELINE_ATTRS = (
    "bazel_target",
    "bazel_path",
    "bazel_mode",
    "gradle_project",
)


@dataclass(frozen=True)
class AnalyzeEcosystem:
    """How ``analyze`` validates and talks to Toolbox for one ecosystem."""

    name: str
    # (namespace attr, CLI flag, optional example value)
    required_flags: Tuple[Tuple[str, str, Optional[str]], ...] = ()
    scope_attr: Optional[str] = None
    normalize: Optional[NormalizeFn] = None

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

    def pipeline_kwargs(self, params: Namespace) -> Dict[str, object]:
        kwargs: Dict[str, object] = {"ecosystem": self.name}
        for attr in TOOLBOX_PIPELINE_ATTRS:
            value = getattr(params, attr, None)
            if value is not None and value != "":
                kwargs[attr] = value
        return kwargs

    def scope_label(self, params: Namespace) -> str:
        if self.scope_attr:
            value = getattr(params, self.scope_attr, None)
            if value:
                return str(value)
        return self.name


def _normalize_bazel(params: Namespace) -> None:
    bazel_mode = getattr(params, "bazel_mode", None)
    if bazel_mode is None:
        return
    normalized = str(bazel_mode).strip().upper()
    if normalized not in {"BZLMOD", "WORKSPACE"}:
        raise ValidationError(
            f"invalid --bazel-mode '{bazel_mode}'; expected BZLMOD or WORKSPACE"
        )
    params.bazel_mode = normalized


ECOSYSTEMS: Dict[str, AnalyzeEcosystem] = {
    "bazel": AnalyzeEcosystem(
        name="bazel",
        required_flags=(("bazel_target", "--bazel-target", "//myapp:app"),),
        scope_attr="bazel_target",
        normalize=_normalize_bazel,
    ),
}


def supported_ecosystems() -> Tuple[str, ...]:
    return tuple(sorted(ECOSYSTEMS))


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
