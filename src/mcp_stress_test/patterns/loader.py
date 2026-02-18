"""Pattern loading utilities."""

from pathlib import Path

from mcp_stress_test.models import PoisonPayload
from mcp_stress_test.patterns.library import PatternLibrary
from mcp_stress_test.patterns.payloads import ALL_PAYLOADS, get_all_payloads


def load_patterns(patterns_dir: Path | None = None) -> PatternLibrary:
    """Load the pattern library.

    Args:
        patterns_dir: Custom directory for additional patterns.

    Returns:
        Loaded PatternLibrary instance.
    """
    library = PatternLibrary(patterns_dir)
    library.load()
    return library


def load_payloads(category: str | None = None) -> list[PoisonPayload]:
    """Load poison payloads.

    Args:
        category: Optional category filter (e.g., 'data_exfil', 'privilege_escalation').

    Returns:
        List of PoisonPayload instances.
    """
    if category:
        return ALL_PAYLOADS.get(category, [])
    return get_all_payloads()
