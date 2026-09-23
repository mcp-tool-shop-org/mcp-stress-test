"""On-disk locations for checkpoints, reports, and cache.

``MCP_STRESS_DATA`` is the persistent root. The Docker image sets it to
``/var/lib/mcp-stress`` and declares that path as a volume, so a named
volume keeps freeze/thaw state and stress reports across container
restarts. Unset, the CLI keeps writing next to the working directory.
"""

from __future__ import annotations

import os
from pathlib import Path


def persistent_root() -> Path | None:
    """Return the persistent data root, creating it when the env var is set."""
    raw = os.environ.get("MCP_STRESS_DATA", "").strip()
    if not raw:
        return None
    root = Path(raw)
    root.mkdir(parents=True, exist_ok=True)
    return root


def default_checkpoint_dir() -> Path:
    """Checkpoint directory: volume subdir, or ``.stress-checkpoints``."""
    root = persistent_root()
    path = (root / "checkpoints") if root is not None else Path(".stress-checkpoints")
    path.mkdir(parents=True, exist_ok=True)
    return path


def apply_persistent_defaults(config: object) -> None:
    """Point report, cache, and evasion dirs at the volume when it is set.

    An explicit ``MCP_STRESS_REPORT_DIR`` still wins for reports.
    """
    root = persistent_root()
    if root is None:
        return
    report = getattr(config, "report", None)
    if report is not None and not os.environ.get("MCP_STRESS_REPORT_DIR", "").strip():
        report.output_dir = str(root / "reports")
    if hasattr(config, "cache_dir"):
        config.cache_dir = str(root / "cache")
    fuzz = getattr(config, "fuzz", None)
    if fuzz is not None:
        fuzz.evasion_output_dir = str(root / "evasions")
