"""Bazel ecosystem plugin for ``analyze``."""

from __future__ import annotations

from argparse import Namespace, _ArgumentGroup

from workbench_agent.exceptions import ValidationError
from workbench_agent.utilities.analyze.first_party import FirstPartyStrategy
from workbench_agent.utilities.analyze.registry import AnalyzeEcosystem, register_ecosystem


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


def _add_bazel_arguments(group: _ArgumentGroup) -> None:
    group.add_argument(
        "--bazel-target",
        dest="bazel_target",
        help=(
            "Bazel build target whose deps() are analyzed, "
            "e.g. //myapp:app (required for -e bazel)"
        ),
        required=False,
        metavar="TARGET",
    )
    group.add_argument(
        "--bazel-path",
        dest="bazel_path",
        help="Path to the bazel executable (default: bazel/bazelisk on PATH)",
        required=False,
        metavar="PATH",
    )
    group.add_argument(
        "--bazel-mode",
        dest="bazel_mode",
        help="Force Bazel mode: BZLMOD or WORKSPACE (auto-detected if omitted)",
        required=False,
        choices=["BZLMOD", "WORKSPACE", "bzlmod", "workspace"],
        metavar="MODE",
    )


BAZEL = register_ecosystem(
    AnalyzeEcosystem(
        name="bazel",
        manifests=("MODULE.bazel", "WORKSPACE.bazel", "WORKSPACE"),
        first_party=FirstPartyStrategy.SIDECAR,
        required_flags=(("bazel_target", "--bazel-target", "//myapp:app"),),
        pipeline_attrs=("bazel_target", "bazel_path", "bazel_mode"),
        scope_attr="bazel_target",
        normalize=_normalize_bazel,
        add_arguments=_add_bazel_arguments,
        config_display_keys=("bazel_target", "bazel_path", "bazel_mode"),
    )
)
