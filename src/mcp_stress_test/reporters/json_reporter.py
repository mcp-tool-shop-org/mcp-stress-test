"""JSON reporter for machine-readable output."""

from __future__ import annotations

import json
from datetime import datetime

from mcp_stress_test.core.protocols import AttackResult, ChainResult, ReportFormat
from mcp_stress_test.reporters.base import BaseReporter, ReportMetrics


class JSONReporter(BaseReporter):
    """JSON format reporter."""

    @property
    def name(self) -> str:
        return "json"

    @property
    def format(self) -> ReportFormat:
        return ReportFormat.JSON

    def _render(
        self,
        results: list[AttackResult],
        chain_results: list[ChainResult] | None,
        metrics: ReportMetrics,
    ) -> str:
        """Render JSON report."""
        report = {
            "metadata": {
                "generated": datetime.now().isoformat(),
                "version": "0.6.0",
                "framework": "mcp-stress-test",
            },
            "summary": {
                "total_tests": metrics.total_tests,
                "passed": metrics.passed,
                "failed": metrics.failed,
                "detection_rate": metrics.detection_rate,
                "evasion_rate": metrics.evasion_rate,
                "avg_scan_time_ms": metrics.avg_scan_time_ms,
            },
            "by_strategy": metrics.by_strategy,
            "by_tool": metrics.by_tool,
            "results": [
                {
                    "tool_name": r.tool_name,
                    "strategy": r.strategy,
                    "detected": r.detected,
                    "score_before": r.score_before,
                    "score_after": r.score_after,
                    "score_delta": r.score_delta,
                    "threats_found": r.threats_found,
                    "scan_time_ms": r.scan_time_ms,
                    "metadata": r.metadata,
                }
                for r in results
            ],
        }

        if chain_results:
            report["chains"] = {
                "by_chain": metrics.by_chain,
                "results": [
                    {
                        "chain_name": cr.chain_name,
                        "chain_detected": cr.chain_detected,
                        "steps_total": len(cr.steps),
                        "steps_detected": cr.steps_detected,
                        "detection_rate": cr.detection_rate,
                        "total_time_ms": cr.total_time_ms,
                        "steps": [
                            {
                                "tool_name": s.tool_name,
                                "detected": s.detected,
                                "metadata": s.metadata,
                            }
                            for s in cr.steps
                        ],
                    }
                    for cr in chain_results
                ],
            }

        return json.dumps(report, indent=2)
