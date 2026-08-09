"""Signature database updater – refreshes the bundled CVE signature data from a remote URL.

The tool ships with a small, static `data/cve_signatures.json` dataset (see
`sentinelscan/analyzers/cve_fingerprint.py`). `--update-db` downloads a fresh
copy and installs it as a user-level override, checked before the bundled
default. This is a static dataset refreshed on demand, not a live threat-intel
feed — treat it accordingly.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentinelscan.updater")

DEFAULT_SIGNATURES_URL = (
    "https://raw.githubusercontent.com/aljabid/SentinelScan/main/sentinelscan/data/cve_signatures.json"
)

USER_SIGNATURES_PATH = Path(
    os.environ.get(
        "SENTINELSCAN_SIGNATURES_PATH",
        str(Path.home() / ".config" / "sentinelscan" / "cve_signatures.json"),
    )
)


def update_signatures(session: Any, url: str = DEFAULT_SIGNATURES_URL, timeout: int = 15) -> tuple[bool, str]:
    """Download a signatures JSON file and install it as the user override.

    Returns (success, message).
    """
    try:
        resp = session.get(url, timeout=timeout)
    except Exception as exc:
        return False, f"Failed to fetch {url}: {exc}"

    if resp.status_code != 200:
        return False, f"Server returned HTTP {resp.status_code} for {url}"

    try:
        data = json.loads(resp.text)
    except ValueError as exc:
        return False, f"Downloaded file is not valid JSON: {exc}"

    if not isinstance(data, dict):
        return False, "Downloaded signatures file has an unexpected format (expected a JSON object)"

    USER_SIGNATURES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(USER_SIGNATURES_PATH, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)

    total = sum(len(v) for v in data.values() if isinstance(v, list))
    return True, f"Installed {total} signature(s) across {len(data)} product(s) to {USER_SIGNATURES_PATH}"
