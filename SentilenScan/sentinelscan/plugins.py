"""Plugin loader – discovers external BaseAnalyzer subclasses without touching source.

A plugin is a `*.py` file in the plugin directory that exposes a module-level
`ANALYZER` attribute pointing at a `BaseAnalyzer` subclass with a unique `name`.
This mirrors nmap's NSE scripts: drop a file in, it becomes selectable via `-m`.
"""

from __future__ import annotations

import importlib.util
import logging
import os
from pathlib import Path
from typing import Any

from sentinelscan.analyzers.base import BaseAnalyzer

logger = logging.getLogger("sentinelscan.plugins")

DEFAULT_PLUGIN_DIR = Path(
    os.environ.get("SENTINELSCAN_PLUGIN_DIR", str(Path.home() / ".config" / "sentinelscan" / "plugins"))
)


def load_plugins(plugin_dir: str | Path | None = None) -> dict[str, type[Any]]:
    """Load BaseAnalyzer subclasses from *.py files in plugin_dir (default: DEFAULT_PLUGIN_DIR)."""
    directory = Path(plugin_dir) if plugin_dir else DEFAULT_PLUGIN_DIR
    modules: dict[str, type[Any]] = {}

    if not directory.is_dir():
        return modules

    for path in sorted(directory.glob("*.py")):
        if path.name.startswith("_"):
            continue

        module_name = f"sentinelscan_plugin_{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                logger.warning("Could not load plugin spec for %s", path)
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:
            logger.warning("Failed to load plugin %s: %s", path, exc)
            continue

        analyzer_cls = getattr(module, "ANALYZER", None)
        if analyzer_cls is None:
            logger.warning("Plugin %s has no module-level ANALYZER attribute, skipping", path)
            continue
        if not (isinstance(analyzer_cls, type) and issubclass(analyzer_cls, BaseAnalyzer)):
            logger.warning("Plugin %s: ANALYZER is not a BaseAnalyzer subclass, skipping", path)
            continue

        name = getattr(analyzer_cls, "name", None)
        if not name or name == "base":
            logger.warning("Plugin %s has no valid `name` attribute, skipping", path)
            continue
        if name in modules:
            logger.warning("Duplicate plugin module name '%s' in %s, skipping", name, path)
            continue

        modules[name] = analyzer_cls
        logger.info("Loaded plugin analyzer '%s' from %s", name, path)

    return modules
