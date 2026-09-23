"""CI quality gates for shipped CLI commands."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

import click

F = TypeVar("F", bound=Callable[..., Any])


def quality_gate_options(func: F) -> F:
    """Attach --fail-under-detection and --fail-on-evasion to a command."""
    func = click.option(
        "--fail-on-evasion",
        is_flag=True,
        default=False,
        help="Exit 1 if any attacks evaded detection (evasion rate > 0).",
    )(func)
    func = click.option(
        "--fail-under-detection",
        type=float,
        default=None,
        help="Exit 1 if detection rate percent is below this threshold.",
    )(func)
    return func


def enforce_quality_gate(
    detection_rate: float,
    *,
    fail_under_detection: float | None = None,
    fail_on_evasion: bool = False,
) -> None:
    """Exit 1 when a detection threshold is missed.

    ``detection_rate`` is a percent in [0, 100]. Omitting both flags keeps
    the current exit-0 behavior.
    """
    if fail_under_detection is not None and detection_rate < fail_under_detection:
        raise click.ClickException(
            f"Detection rate {detection_rate:.1f}% is under the minimum "
            f"{fail_under_detection:g}% (--fail-under-detection)."
        )
    if fail_on_evasion:
        evasion_rate = 100.0 - detection_rate
        if evasion_rate > 0:
            raise click.ClickException(
                f"Evasion rate {evasion_rate:.1f}% failed --fail-on-evasion "
                f"(detection {detection_rate:.1f}%)."
            )
