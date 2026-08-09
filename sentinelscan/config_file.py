"""Config/profile file loading (TOML) so common scan setups don't need retyping.

A profile is a small TOML file setting defaults for a subset of CLI flags.
Precedence is: explicit CLI flag > profile value > built-in default. Only a
fixed set of fields are profile-settable (see PROFILE_FIELDS) -- session- or
target-specific flags (--cookie, --verbose, --no-color, etc.) are deliberately
excluded so a profile can't silently do something surprising per-invocation.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib

DEFAULT_CONFIG_DIR = Path(os.environ.get("SENTINELSCAN_CONFIG_DIR", str(Path.home() / ".config" / "sentinelscan")))

# Keep in sync with build_parser()'s dest names in cli.py.
# Deliberately excludes --output: a fixed output path in a profile would make
# every scan silently overwrite the same file regardless of target.
PROFILE_FIELDS = {
    "modules",
    "format",
    "severity",
    "timing",
    "timeout",
    "retries",
    "user_agent",
    "plugin_dir",
    "crawl_max_pages",
    "score_threshold",
}


def load_profile(name: str | None = None, path: str | Path | None = None) -> dict[str, Any]:
    """Load a named profile from the default profile dir, or an explicit TOML file path."""
    if path:
        profile_path = Path(path)
    elif name:
        profile_path = DEFAULT_CONFIG_DIR / "profiles" / f"{name}.toml"
    else:
        return {}

    if not profile_path.is_file():
        raise FileNotFoundError(f"profile file not found: {profile_path}")

    with open(profile_path, "rb") as fh:
        data = tomllib.load(fh)

    unknown = set(data) - PROFILE_FIELDS
    if unknown:
        raise ValueError(
            f"unknown profile field(s) in {profile_path}: {', '.join(sorted(unknown))}. "
            f"Allowed: {', '.join(sorted(PROFILE_FIELDS))}"
        )

    return data
