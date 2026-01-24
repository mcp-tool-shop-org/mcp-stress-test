"""Base reporter class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from mcp_stress_test.core.protocols import AttackResult, ChainResult, ReportFormat

if TYPE_CHECKING:
    pass


@dataclass
class ReportMetrics:
    """Computed metrics for a report."""

    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    detection_rate: float = 0.0
    evasion_rate: float = 0.0
    avg_scan_time_ms: float = 0.0

    by_strategy: dict[str, dict] = None
    by_tool: dict[str, dict] = None
    by_chain: dict[str, dict] = None

    def __post_init__(self):
        self.by_strategy = self.by_strategy or {}
        self.by_tool = self.by_tool or {}
        self.by_chain = self.by_chain or {}


class BaseReporter(ABC):
    """Base class for report generators."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Reporter identifier."""
        ...

    @property
    @abstractmethod
    def format(self) -> ReportFormat:
        """Output format."""
        ...

    @property
    def file_extension(self) -> str:
        """Default file extension for this format."""
        return self.format.value

    def generate(
        self,
        results: list[AttackResult],
        chain_results: list[ChainResult] | None = None,
        output_path: str | None = None,
    ) -> str:
        """Generate a report.

        Args:
            results: Attack results to report on
            chain_results: Optional chain results
            output_path: Optional path to write report to

        Returns:
            The report content as a string
        """
        metrics = self._compute_metrics(results, chain_results)
        content = self._render(results, chain_results, metrics)

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

        return content

    @abstractmethod
    def _render(
        self,
        results: list[AttackResult],
        chain_results: list[ChainResult] | None,
        metrics: ReportMetrics,
    ) -> str:
        """Render the report content.

        Args:
            results: Attack results
            chain_results: Chain results
            metrics: Computed metrics

        Returns:
            Rendered report string
        """
        ...

    def _compute_metrics(
        self,
        results: list[AttackResult],
        chain_results: list[ChainResult] | None,
    ) -> ReportMetrics:
        """Compute metrics from results."""
        metrics = ReportMetrics()
        metrics.total_tests = len(results)

        if not results:
            return metrics

        # Basic counts
        detected = sum(1 for r in results if r.detected)
        metrics.passed = detected
        metrics.failed = metrics.total_tests - detected
        metrics.detection_rate = detected / metrics.total_tests * 100
        metrics.evasion_rate = 100 - metrics.detection_rate

        # Timing
        times = [r.scan_time_ms for r in results if r.scan_time_ms > 0]
        metrics.avg_scan_time_ms = sum(times) / len(times) if times else 0

        # By strategy
        by_strategy: dict[str, dict] = {}
        for r in results:
            if r.strategy not in by_strategy:
                by_strategy[r.strategy] = {"detected": 0, "missed": 0}
            if r.detected:
                by_strategy[r.strategy]["detected"] += 1
            else:
                by_strategy[r.strategy]["missed"] += 1
        metrics.by_strategy = by_strategy

        # By tool
        by_tool: dict[str, dict] = {}
        for r in results:
            if r.tool_name not in by_tool:
                by_tool[r.tool_name] = {"detected": 0, "missed": 0}
            if r.detected:
                by_tool[r.tool_name]["detected"] += 1
            else:
                by_tool[r.tool_name]["missed"] += 1
        metrics.by_tool = by_tool

        # By chain
        if chain_results:
            by_chain: dict[str, dict] = {}
            for cr in chain_results:
                by_chain[cr.chain_name] = {
                    "detected": cr.chain_detected,
                    "steps_total": len(cr.steps),
                    "steps_detected": cr.steps_detected,
                    "detection_rate": cr.detection_rate,
                }
            metrics.by_chain = by_chain

        return metrics
