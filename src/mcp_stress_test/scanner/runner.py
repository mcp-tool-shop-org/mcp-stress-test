"""Stress test runner for MCP security scanner evaluation.

Orchestrates attack generation, scanning, and metrics collection
to evaluate scanner effectiveness against various attack patterns.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from mcp_stress_test.generator import AttackGenerator, TimeSimulator
from mcp_stress_test.models import (
    AttackParadigm,
    PoisonPayload,
    TemporalPattern,
    ToolSchema,
)
from mcp_stress_test.scanner.adapter import ScannerAdapter, ScannerConfig
from mcp_stress_test.scanner.checkpoint import CheckpointManager


class StressPhase(StrEnum):
    """Phases of stress testing."""

    BASELINE = "baseline"
    MUTATION = "mutation"
    TEMPORAL = "temporal"
    PROGRESSIVE = "progressive"
    ADVERSARIAL = "adversarial"


@dataclass
class StressTestConfig:
    """Configuration for stress test runs."""

    # Scanner configuration
    scanner_config: ScannerConfig = field(default_factory=ScannerConfig)

    # Test scope
    phases: list[StressPhase] = field(
        default_factory=lambda: [StressPhase.BASELINE, StressPhase.MUTATION]
    )
    strategies: list[str] = field(
        default_factory=lambda: ["direct_injection", "semantic_blending", "obfuscation"]
    )
    paradigms: list[AttackParadigm] = field(
        default_factory=lambda: [AttackParadigm.P1_EXPLICIT_HIJACKING]
    )

    # Temporal testing
    temporal_patterns: list[TemporalPattern] = field(
        default_factory=lambda: [TemporalPattern.RUG_PULL]
    )
    temporal_invocations: int = 20
    temporal_threshold: int = 10

    # Progressive testing
    progressive_stages: int = 5

    # Checkpointing
    checkpoint_interval: int = 10  # Create checkpoint every N tests
    enable_checkpoints: bool = True

    # Metrics
    collect_timing: bool = True
    verbose: bool = False


@dataclass
class StressMetrics:
    """Metrics collected during stress testing."""

    total_tests: int = 0
    passed: int = 0
    failed: int = 0

    # Detection metrics
    true_positives: int = 0  # Attack detected correctly
    false_positives: int = 0  # Clean tool flagged as attack
    true_negatives: int = 0  # Clean tool correctly identified
    false_negatives: int = 0  # Attack not detected

    # Timing
    total_scan_time_ms: float = 0
    min_scan_time_ms: float = float("inf")
    max_scan_time_ms: float = 0

    # By strategy
    by_strategy: dict[str, dict[str, int]] = field(default_factory=dict)

    # By paradigm
    by_paradigm: dict[str, dict[str, int]] = field(default_factory=dict)

    # By risk category
    by_risk: dict[str, dict[str, int]] = field(default_factory=dict)

    def record_scan(self, duration_ms: float) -> None:
        """Record scan timing."""
        self.total_scan_time_ms += duration_ms
        self.min_scan_time_ms = min(self.min_scan_time_ms, duration_ms)
        self.max_scan_time_ms = max(self.max_scan_time_ms, duration_ms)

    def record_result(
        self,
        detected: bool,
        is_attack: bool,
        strategy: str | None = None,
        paradigm: str | None = None,
        risk: str | None = None,
    ) -> None:
        """Record a test result."""
        self.total_tests += 1

        if is_attack:
            if detected:
                self.true_positives += 1
                self.passed += 1
            else:
                self.false_negatives += 1
                self.failed += 1
        else:
            if detected:
                self.false_positives += 1
                self.failed += 1
            else:
                self.true_negatives += 1
                self.passed += 1

        # Record by strategy
        if strategy:
            if strategy not in self.by_strategy:
                self.by_strategy[strategy] = {"detected": 0, "missed": 0}
            if detected and is_attack:
                self.by_strategy[strategy]["detected"] += 1
            elif is_attack:
                self.by_strategy[strategy]["missed"] += 1

        # Record by paradigm
        if paradigm:
            if paradigm not in self.by_paradigm:
                self.by_paradigm[paradigm] = {"detected": 0, "missed": 0}
            if detected and is_attack:
                self.by_paradigm[paradigm]["detected"] += 1
            elif is_attack:
                self.by_paradigm[paradigm]["missed"] += 1

        # Record by risk
        if risk:
            if risk not in self.by_risk:
                self.by_risk[risk] = {"detected": 0, "missed": 0}
            if detected and is_attack:
                self.by_risk[risk]["detected"] += 1
            elif is_attack:
                self.by_risk[risk]["missed"] += 1

    @property
    def detection_rate(self) -> float:
        """Calculate detection rate (sensitivity/recall)."""
        total_attacks = self.true_positives + self.false_negatives
        if total_attacks == 0:
            return 0.0
        return (self.true_positives / total_attacks) * 100

    @property
    def precision(self) -> float:
        """Calculate precision."""
        total_positive = self.true_positives + self.false_positives
        if total_positive == 0:
            return 0.0
        return (self.true_positives / total_positive) * 100

    @property
    def f1_score(self) -> float:
        """Calculate F1 score."""
        p = self.precision
        r = self.detection_rate
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)

    @property
    def avg_scan_time_ms(self) -> float:
        """Calculate average scan time."""
        if self.total_tests == 0:
            return 0.0
        return self.total_scan_time_ms / self.total_tests

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "detection_rate": round(self.detection_rate, 2),
            "precision": round(self.precision, 2),
            "f1_score": round(self.f1_score, 2),
            "avg_scan_time_ms": round(self.avg_scan_time_ms, 2),
            "min_scan_time_ms": round(self.min_scan_time_ms, 2)
            if self.min_scan_time_ms != float("inf")
            else 0,
            "max_scan_time_ms": round(self.max_scan_time_ms, 2),
            "by_strategy": self.by_strategy,
            "by_paradigm": self.by_paradigm,
            "by_risk": self.by_risk,
        }


@dataclass
class StressResult:
    """Result of a single stress test."""

    test_id: str
    phase: StressPhase
    tool_name: str
    strategy: str | None
    is_attack: bool
    attack_detected: bool
    score_before: float
    score_after: float
    score_delta: float
    new_threats: list[str]
    scan_duration_ms: float
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """Check if test passed (attack detected or clean correctly identified)."""
        if self.is_attack:
            return self.attack_detected
        return not self.attack_detected


class StressTestRunner:
    """Orchestrates stress testing of MCP security scanners."""

    def __init__(
        self,
        config: StressTestConfig | None = None,
        checkpoint_manager: CheckpointManager | None = None,
    ):
        """Initialize stress test runner.

        Args:
            config: Test configuration.
            checkpoint_manager: Optional checkpoint manager for session persistence.
        """
        self.config = config or StressTestConfig()
        self.scanner = ScannerAdapter(self.config.scanner_config)
        self.generator = AttackGenerator()
        self.checkpoint_manager = checkpoint_manager

        self.metrics = StressMetrics()
        self._results: list[StressResult] = []
        self._test_counter = 0

    def run_baseline(
        self,
        tools: list[ToolSchema],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[StressResult]:
        """Run baseline scans on clean tools.

        Args:
            tools: List of tools to scan.
            progress_callback: Optional callback for progress updates (current, total, message).

        Returns:
            List of baseline test results.
        """
        results = []

        for i, tool in enumerate(tools):
            if progress_callback:
                progress_callback(i + 1, len(tools), f"Scanning {tool.name}")

            self._test_counter += 1
            test_id = f"baseline_{self._test_counter}"

            # Scan clean tool
            scan_result = self.scanner.scan(tool)

            # Record metrics
            self.metrics.record_scan(scan_result.scan_duration_ms)

            # A clean tool with threats is a false positive
            is_attack = False
            detected = len(scan_result.threats_detected) > 0

            self.metrics.record_result(
                detected=detected,
                is_attack=is_attack,
            )

            result = StressResult(
                test_id=test_id,
                phase=StressPhase.BASELINE,
                tool_name=tool.name,
                strategy=None,
                is_attack=is_attack,
                attack_detected=detected,
                score_before=100.0,
                score_after=scan_result.score,
                score_delta=scan_result.score - 100.0,
                new_threats=scan_result.threats_detected,
                scan_duration_ms=scan_result.scan_duration_ms,
            )

            results.append(result)
            self._results.append(result)

            # Checkpoint if needed
            if (
                self.checkpoint_manager
                and self._test_counter % self.config.checkpoint_interval == 0
            ):
                self.checkpoint_manager.create_checkpoint(
                    tool=tool,
                    scan_results=[scan_result],
                    metadata={"phase": StressPhase.BASELINE.value, "test_id": test_id},
                )

        return results

    def run_mutation_tests(
        self,
        tools: list[ToolSchema],
        payloads: list[PoisonPayload],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[StressResult]:
        """Run mutation tests with various attack strategies.

        Args:
            tools: Tools to test.
            payloads: Payloads to inject.
            progress_callback: Optional progress callback.

        Returns:
            List of mutation test results.
        """
        results = []
        total_tests = len(tools) * len(payloads) * len(self.config.strategies)
        current = 0

        for tool in tools:
            # Get baseline scan first
            self.scanner.scan(tool)

            for payload in payloads:
                for strategy_name in self.config.strategies:
                    current += 1
                    if progress_callback:
                        progress_callback(
                            current,
                            total_tests,
                            f"{tool.name} + {strategy_name}",
                        )

                    self._test_counter += 1
                    test_id = f"mutation_{self._test_counter}"

                    # Generate attack
                    mutation = self.generator.generate_attack(
                        tool=tool,
                        payload=payload,
                        strategy_name=strategy_name,
                    )

                    # Compare scans
                    comparison = self.scanner.compare(
                        original=tool,
                        modified=mutation.poisoned_tool,
                        test_case_id=test_id,
                    )

                    # Record metrics
                    self.metrics.record_scan(comparison.post_scan.scan_duration_ms)
                    self.metrics.record_result(
                        detected=comparison.attack_detected,
                        is_attack=True,
                        strategy=strategy_name,
                        risk=payload.category.value,
                    )

                    if self.checkpoint_manager:
                        self.checkpoint_manager.record_mutation(comparison.attack_detected)

                    result = StressResult(
                        test_id=test_id,
                        phase=StressPhase.MUTATION,
                        tool_name=tool.name,
                        strategy=strategy_name,
                        is_attack=True,
                        attack_detected=comparison.attack_detected,
                        score_before=comparison.pre_scan.score,
                        score_after=comparison.post_scan.score,
                        score_delta=comparison.score_delta,
                        new_threats=comparison.new_threats,
                        scan_duration_ms=comparison.post_scan.scan_duration_ms,
                        metadata={
                            "payload_category": payload.category.value,
                            "injection_points": mutation.injection_points,
                        },
                    )

                    results.append(result)
                    self._results.append(result)

        return results

    def run_temporal_tests(
        self,
        tools: list[ToolSchema],
        payloads: list[PoisonPayload],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[StressResult]:
        """Run temporal pattern tests (rug pull, gradual poisoning).

        Args:
            tools: Tools to test.
            payloads: Payloads to use.
            progress_callback: Optional progress callback.

        Returns:
            List of temporal test results.
        """
        results = []
        total_tests = len(tools) * len(payloads) * len(self.config.temporal_patterns)
        current = 0

        for tool in tools:
            for payload in payloads:
                for pattern in self.config.temporal_patterns:
                    current += 1
                    if progress_callback:
                        progress_callback(
                            current,
                            total_tests,
                            f"{tool.name} + {pattern.value}",
                        )

                    # Create time simulator
                    simulator = TimeSimulator(
                        pattern=pattern,
                        payload=payload,
                        activation_threshold=self.config.temporal_threshold,
                    )

                    # Run simulation
                    attack_invocation = None
                    pre_attack_scan = None

                    for inv, current_tool, _state, mutated in simulator.simulate_session(
                        tool, self.config.temporal_invocations
                    ):
                        if mutated and attack_invocation is None:
                            attack_invocation = inv

                            self._test_counter += 1
                            test_id = f"temporal_{self._test_counter}"

                            # Compare pre and post attack
                            post_scan = self.scanner.scan(current_tool)

                            # Record metrics
                            self.metrics.record_scan(post_scan.scan_duration_ms)

                            detected = len(post_scan.threats_detected) > 0

                            self.metrics.record_result(
                                detected=detected,
                                is_attack=True,
                                strategy=pattern.value,
                                risk=payload.category.value,
                            )

                            result = StressResult(
                                test_id=test_id,
                                phase=StressPhase.TEMPORAL,
                                tool_name=tool.name,
                                strategy=pattern.value,
                                is_attack=True,
                                attack_detected=detected,
                                score_before=pre_attack_scan.score if pre_attack_scan else 100.0,
                                score_after=post_scan.score,
                                score_delta=post_scan.score
                                - (pre_attack_scan.score if pre_attack_scan else 100.0),
                                new_threats=post_scan.threats_detected,
                                scan_duration_ms=post_scan.scan_duration_ms,
                                metadata={
                                    "pattern": pattern.value,
                                    "activation_invocation": attack_invocation,
                                    "total_invocations": self.config.temporal_invocations,
                                },
                            )

                            results.append(result)
                            self._results.append(result)
                        elif not mutated and pre_attack_scan is None:
                            # Capture pre-attack baseline
                            pre_attack_scan = self.scanner.scan(current_tool)

        return results

    def run_progressive_tests(
        self,
        tools: list[ToolSchema],
        payloads: list[PoisonPayload],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[StressResult]:
        """Run progressive obfuscation tests.

        Tests scanner sensitivity at different obfuscation levels.

        Args:
            tools: Tools to test.
            payloads: Payloads to use.
            progress_callback: Optional progress callback.

        Returns:
            List of progressive test results.
        """
        results = []
        total_tests = len(tools) * len(payloads) * self.config.progressive_stages
        current = 0

        for tool in tools:
            baseline = self.scanner.scan(tool)

            for payload in payloads:
                # Generate progressive attacks
                progressive_attacks = self.generator.generate_progressive_attack(
                    tool=tool,
                    payload=payload,
                    stages=self.config.progressive_stages,
                )

                for stage, mutation in enumerate(progressive_attacks, 1):
                    current += 1
                    if progress_callback:
                        progress_callback(
                            current,
                            total_tests,
                            f"{tool.name} stage {stage}/{self.config.progressive_stages}",
                        )

                    self._test_counter += 1
                    test_id = f"progressive_{self._test_counter}"

                    # Scan poisoned tool
                    scan_result = self.scanner.scan(mutation.poisoned_tool)

                    detected = len(scan_result.threats_detected) > 0

                    self.metrics.record_scan(scan_result.scan_duration_ms)
                    self.metrics.record_result(
                        detected=detected,
                        is_attack=True,
                        strategy=mutation.strategy_used,
                        risk=payload.category.value,
                    )

                    result = StressResult(
                        test_id=test_id,
                        phase=StressPhase.PROGRESSIVE,
                        tool_name=tool.name,
                        strategy=mutation.strategy_used,
                        is_attack=True,
                        attack_detected=detected,
                        score_before=baseline.score,
                        score_after=scan_result.score,
                        score_delta=scan_result.score - baseline.score,
                        new_threats=scan_result.threats_detected,
                        scan_duration_ms=scan_result.scan_duration_ms,
                        metadata={
                            "stage": stage,
                            "total_stages": self.config.progressive_stages,
                            "injection_points": mutation.injection_points,
                        },
                    )

                    results.append(result)
                    self._results.append(result)

        return results

    def run_full_suite(
        self,
        tools: list[ToolSchema],
        payloads: list[PoisonPayload],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> dict[StressPhase, list[StressResult]]:
        """Run full stress test suite.

        Args:
            tools: Tools to test.
            payloads: Payloads to use.
            progress_callback: Optional progress callback.

        Returns:
            Results organized by phase.
        """
        results: dict[StressPhase, list[StressResult]] = {}

        for phase in self.config.phases:
            if phase == StressPhase.BASELINE:
                results[phase] = self.run_baseline(tools, progress_callback)
            elif phase == StressPhase.MUTATION:
                results[phase] = self.run_mutation_tests(tools, payloads, progress_callback)
            elif phase == StressPhase.TEMPORAL:
                results[phase] = self.run_temporal_tests(tools, payloads, progress_callback)
            elif phase == StressPhase.PROGRESSIVE:
                results[phase] = self.run_progressive_tests(tools, payloads, progress_callback)

            if self.checkpoint_manager:
                self.checkpoint_manager.record_tool_tested(phase.value)

        return results

    def get_results(self) -> list[StressResult]:
        """Get all test results."""
        return self._results.copy()

    def get_metrics(self) -> StressMetrics:
        """Get collected metrics."""
        return self.metrics

    def get_summary(self) -> dict[str, Any]:
        """Get test run summary."""
        return {
            "total_tests": self.metrics.total_tests,
            "passed": self.metrics.passed,
            "failed": self.metrics.failed,
            "detection_rate": round(self.metrics.detection_rate, 2),
            "precision": round(self.metrics.precision, 2),
            "f1_score": round(self.metrics.f1_score, 2),
            "avg_scan_time_ms": round(self.metrics.avg_scan_time_ms, 2),
            "phases_run": [p.value for p in self.config.phases],
            "strategies_tested": self.config.strategies,
            "metrics": self.metrics.to_dict(),
        }

    def export_results(self, format: str = "json") -> str:
        """Export results in specified format.

        Args:
            format: Output format (json, csv, markdown).

        Returns:
            Formatted results string.
        """
        import json as json_module

        if format == "json":
            data = {
                "summary": self.get_summary(),
                "results": [
                    {
                        "test_id": r.test_id,
                        "phase": r.phase.value,
                        "tool_name": r.tool_name,
                        "strategy": r.strategy,
                        "is_attack": r.is_attack,
                        "attack_detected": r.attack_detected,
                        "passed": r.passed,
                        "score_delta": r.score_delta,
                        "new_threats": r.new_threats,
                        "scan_duration_ms": r.scan_duration_ms,
                        "metadata": r.metadata,
                    }
                    for r in self._results
                ],
            }
            return json_module.dumps(data, indent=2)

        elif format == "csv":
            lines = [
                "test_id,phase,tool,strategy,is_attack,detected,passed,score_delta,duration_ms"
            ]
            for r in self._results:
                lines.append(
                    f"{r.test_id},{r.phase.value},{r.tool_name},{r.strategy or ''},"
                    f"{r.is_attack},{r.attack_detected},{r.passed},{r.score_delta:.2f},{r.scan_duration_ms:.2f}"
                )
            return "\n".join(lines)

        elif format == "markdown":
            lines = [
                "# Stress Test Results",
                "",
                "## Summary",
                f"- Total tests: {self.metrics.total_tests}",
                f"- Passed: {self.metrics.passed}",
                f"- Failed: {self.metrics.failed}",
                f"- Detection rate: {self.metrics.detection_rate:.2f}%",
                f"- Precision: {self.metrics.precision:.2f}%",
                f"- F1 Score: {self.metrics.f1_score:.2f}",
                "",
                "## Results by Strategy",
                "",
                "| Strategy | Detected | Missed | Rate |",
                "|----------|----------|--------|------|",
            ]

            for strategy, stats in self.metrics.by_strategy.items():
                total = stats["detected"] + stats["missed"]
                rate = (stats["detected"] / total * 100) if total > 0 else 0
                lines.append(
                    f"| {strategy} | {stats['detected']} | {stats['missed']} | {rate:.1f}% |"
                )

            return "\n".join(lines)

        else:
            raise ValueError(f"Unknown format: {format}")
