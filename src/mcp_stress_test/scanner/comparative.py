"""Fan one ToolSchema out to N registered scanners; per-scanner metrics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_stress_test.core.protocols import AttackResult, Scanner
from mcp_stress_test.core.registry import PluginRegistry
from mcp_stress_test.models import ScanComparison, ScanResult, ToolSchema


def _to_scan_result(result: AttackResult) -> ScanResult:
    error = result.metadata.get("error") if result.metadata else None
    error_s = error if isinstance(error, str) else None
    return ScanResult(
        tool_name=result.tool_name,
        score=result.score_after,
        grade="ERR" if error_s else ("F" if result.detected else "A"),
        threats_detected=list(result.threats_found),
        scan_duration_ms=result.scan_time_ms,
        error=error_s,
        scanner_version=str((result.metadata or {}).get("scanner") or ""),
    )


class _AdapterAsScanner:
    """Wrap ScannerAdapter / any object with .scan() -> ScanResult as Scanner."""

    def __init__(self, adapter: Any):
        self._adapter = adapter

    @property
    def name(self) -> str:
        name = getattr(self._adapter, "scanner_name", None)
        if isinstance(name, str) and name:
            return name
        backend = getattr(self._adapter, "backend", None)
        if backend is not None and callable(getattr(backend, "name", None)):
            return str(backend.name())
        return "adapter"

    def scan(self, tool: ToolSchema) -> AttackResult:
        raw = self._adapter.scan(tool)
        if isinstance(raw, AttackResult):
            return raw
        if isinstance(raw, ScanResult):
            if raw.errored:
                return AttackResult.scanner_error(
                    tool.name,
                    raw.error or "scan error",
                    self.name,
                    scan_time_ms=raw.scan_duration_ms,
                )
            return AttackResult(
                tool_name=raw.tool_name,
                strategy="scan",
                detected=len(raw.threats_detected) > 0,
                score_before=100.0,
                score_after=raw.score,
                threats_found=list(raw.threats_detected),
                scan_time_ms=raw.scan_duration_ms,
                metadata={"scanner": self.name, "grade": raw.grade},
            )
        raise TypeError(f"unsupported scan return type: {type(raw)!r}")

    def scan_batch(self, tools: list[ToolSchema]) -> list[AttackResult]:
        return [self.scan(tool) for tool in tools]


@dataclass
class ComparativeScanner:
    """Iterate PluginRegistry.list_scanners() or an explicit list; side-by-side metrics."""

    _scanners: list[Scanner] = field(default_factory=list)
    _names: list[str] = field(default_factory=list)
    _metrics: dict[str, Any] = field(default_factory=dict)
    _comparisons: dict[str, list[ScanComparison]] = field(default_factory=dict)

    def __init__(
        self,
        *,
        registry: PluginRegistry | None = None,
        scanners: list[Scanner] | None = None,
        adapters: list[Any] | None = None,
    ):
        from mcp_stress_test.scanner.runner import StressMetrics

        found: list[Scanner] = []
        if scanners:
            found.extend(scanners)
        if adapters:
            found.extend(_AdapterAsScanner(adapter) for adapter in adapters)
        source = registry
        if source is None and not scanners and not adapters:
            from mcp_stress_test.core.registry import registry as global_registry

            source = global_registry
        if source is not None:
            for name in source.list_scanners():
                scanner = source.get_scanner(name)
                if scanner is not None:
                    found.append(scanner)
        if not found:
            raise ValueError("ComparativeScanner requires at least one scanner")
        counts: dict[str, int] = {}
        self._scanners = found
        self._names = []
        self._metrics = {}
        self._comparisons = {}
        for scanner in found:
            base = scanner.name
            counts[base] = counts.get(base, 0) + 1
            name = base if counts[base] == 1 else f"{base}_{counts[base]}"
            self._names.append(name)
            self._metrics[name] = StressMetrics()
            self._comparisons[name] = []

    @property
    def scanner_names(self) -> list[str]:
        return list(self._names)

    def fan_out(self, tool: ToolSchema) -> dict[str, AttackResult]:
        """Scan one tool with every registered scanner."""
        out: dict[str, AttackResult] = {}
        for name, scanner in zip(self._names, self._scanners, strict=True):
            try:
                out[name] = scanner.scan(tool)
            except Exception as exc:  # noqa: BLE001 — per-scanner isolation
                out[name] = AttackResult.scanner_error(tool.name, str(exc), name)
        return out

    def evaluate_tool(self, tool: ToolSchema, *, is_attack: bool) -> dict[str, AttackResult]:
        """Fan out and record TP/FP/TN/FN per scanner."""
        results = self.fan_out(tool)
        for name, result in results.items():
            metrics = self._metrics[name]
            metrics.record_scan(result.scan_time_ms)
            if result.errored:
                metrics.record_error()
            else:
                metrics.record_result(detected=result.detected, is_attack=is_attack)
        return results

    def compare_fan_out(
        self,
        original: ToolSchema,
        modified: ToolSchema,
        test_case_id: str = "",
        *,
        is_attack: bool = True,
    ) -> dict[str, ScanComparison]:
        """Pre/post ScanComparison keyed by scanner name, with per-scanner metrics."""
        pre_map = self.fan_out(original)
        post_map = self.fan_out(modified)
        comparisons: dict[str, ScanComparison] = {}
        for name in self._names:
            pre = _to_scan_result(pre_map[name])
            post = _to_scan_result(post_map[name])
            score_delta = post.score - pre.score
            new_threats = [t for t in post.threats_detected if t not in pre.threats_detected]
            resolved = [t for t in pre.threats_detected if t not in post.threats_detected]
            scan_error = pre.error or post.error
            if scan_error:
                comparison = ScanComparison(
                    test_case_id=test_case_id,
                    pre_scan=pre,
                    post_scan=post,
                    score_delta=score_delta,
                    new_threats=[],
                    resolved_threats=[],
                    attack_detected=False,
                    error=scan_error,
                )
            else:
                attack_detected = (
                    len(new_threats) > 0
                    or score_delta < -20
                    or (post.grade == "F" and pre.grade != "F")
                )
                comparison = ScanComparison(
                    test_case_id=test_case_id,
                    pre_scan=pre,
                    post_scan=post,
                    score_delta=score_delta,
                    new_threats=new_threats,
                    resolved_threats=resolved,
                    attack_detected=attack_detected,
                    detection_latency_calls=1 if attack_detected else 0,
                )
            comparisons[name] = comparison
            self._comparisons[name].append(comparison)
            metrics = self._metrics[name]
            metrics.record_scan(post.scan_duration_ms)
            if comparison.errored:
                metrics.record_error()
            else:
                metrics.record_result(detected=comparison.attack_detected, is_attack=is_attack)
        return comparisons

    def metrics_for(self, name: str) -> Any:
        return self._metrics[name]

    def side_by_side(self) -> dict[str, dict[str, float | int]]:
        """detection_rate, precision, errors keyed by scanner name."""
        summary: dict[str, dict[str, float | int]] = {}
        for name, metrics in self._metrics.items():
            summary[name] = {
                "detection_rate": round(metrics.detection_rate, 2),
                "precision": round(metrics.precision, 2),
                "errors": metrics.errors,
                "true_positives": metrics.true_positives,
                "false_positives": metrics.false_positives,
                "true_negatives": metrics.true_negatives,
                "false_negatives": metrics.false_negatives,
                "total_tests": metrics.total_tests,
            }
        return summary
