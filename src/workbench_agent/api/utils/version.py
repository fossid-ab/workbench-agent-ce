"""Workbench server version normalization (aligned with WorkbenchClient)."""

import re
from typing import Optional

# Leading MAJOR.MINOR.PATCH from getConfig "version" (e.g. 2026.1.0#buildid).
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def normalize_workbench_version(raw_version: str) -> Optional[str]:
    """
    Normalize raw ``getConfig`` version to MAJOR.MINOR.PATCH.

    Examples:
        ``2026.1.0#25559481630`` -> ``2026.1.0``
        ``2026.1.0.v11#24448141686`` -> ``2026.1.0``

    Args:
        raw_version: Value of ``config["version"]`` from internal getConfig.

    Returns:
        Normalized version string, or None if no numeric triple is found.
    """
    if not raw_version or raw_version == "Unknown":
        return None
    version_str = raw_version.split()[0]
    version_str = version_str.split("-")[0]
    version_str = version_str.split("#")[0]
    match = _VERSION_RE.match(version_str)
    if match:
        return match.group(1)
    return None
