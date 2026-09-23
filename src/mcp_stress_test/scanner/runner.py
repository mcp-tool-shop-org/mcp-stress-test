"""Stress test runner for MCP security scanner evaluation.

Orchestrates attack generation, scanning, and metrics collection
to evaluate scanner effectiveness against various attack patterns.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from mcp_stress_test.generator import AttackGenerator, TimeSimulator
from mcp_stress_test.models import (
    MCPTOX_ASR_BASELINE,
    AttackParadigm,
    AttackTestCase,
    CaseVerdict,
    OutcomeType,
    PoisonPayload,
    TemporalPattern,
    TestRunMetrics,
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
    LABELED = "labeled"


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
    errors: int = 0  # Scanner failures; excluded from TP/FP/TN/FN

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

    def record_error(self) -> None:
        """Record a scanner failure that produced no verdict."""
        self.errors += 1

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

    @property
    def asr_protected(self) -> float:
        """Measured attack success rate under the scanner (misses / attacks). 0-1."""
        attacks = self.true_positives + self.false_negatives
        if attacks == 0:
            return 0.0
        return self.false_negatives / attacks

    @property
    def false_positive_rate(self) -> float:
        """False flags on the clean phase (FP / clean tools). 0-1."""
        clean = self.false_positives + self.true_negatives
        if clean == 0:
            return 0.0
        return self.false_positives / clean

    @property
    def asr_reduction(self) -> float:
        """(published MCPTox baseline - measured protected ASR) / baseline."""
        baseline = MCPTOX_ASR_BASELINE
        if baseline == 0:
            return 0.0
        return (baseline - self.asr_protected) / baseline

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
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
            "asr_baseline": MCPTOX_ASR_BASELINE,
            "asr_protected": round(self.asr_protected, 4),
            "asr_reduction": round(self.asr_reduction, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
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
        self._started_at = datetime.now()
        self._run_id = uuid4().hex[:12]
        self._case_verdicts: list[CaseVerdict] = []

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
            self._note_tool_tested(tool.name)

            # Scan clean tool
            scan_result = self.scanner.scan(tool)

            # Record metrics
            self.metrics.record_scan(scan_result.scan_duration_ms)

            # A clean tool with threats is a false positive. A scanner
            # failure is neither a detection nor a clean pass.
            is_attack = False
            if scan_result.errored:
                self.metrics.record_error()
                detected = False
            else:
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
                new_threats=[] if scan_result.errored else scan_result.threats_detected,
                scan_duration_ms=scan_result.scan_duration_ms,
                metadata={"error": scan_result.error} if scan_result.errored else {},
            )

            results.append(result)
            self._results.append(result)

            self._maybe_checkpoint(
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
            self._note_tool_tested(tool.name)
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

                    # Record metrics. Errored scans are not detections or misses.
                    self.metrics.record_scan(comparison.post_scan.scan_duration_ms)
                    if comparison.errored:
                        self.metrics.record_error()
                        detected = False
                    else:
                        detected = comparison.attack_detected
                        self.metrics.record_result(
                            detected=detected,
                            is_attack=True,
                            strategy=strategy_name,
                            paradigm=self._default_paradigm(),
                            risk=payload.category.value,
                        )
                        if self.checkpoint_manager:
                            self.checkpoint_manager.record_mutation(detected)

                    result = StressResult(
                        test_id=test_id,
                        phase=StressPhase.MUTATION,
                        tool_name=tool.name,
                        strategy=strategy_name,
                        is_attack=True,
                        attack_detected=detected,
                        score_before=comparison.pre_scan.score,
                        score_after=comparison.post_scan.score,
                        score_delta=comparison.score_delta,
                        new_threats=comparison.new_threats,
                        scan_duration_ms=comparison.post_scan.scan_duration_ms,
                        metadata={
                            "payload_category": payload.category.value,
                            "injection_points": mutation.injection_points,
                            **({"error": comparison.error} if comparison.errored else {}),
                        },
                    )

                    results.append(result)
                    self._results.append(result)

                    self._maybe_checkpoint(
                        tool=mutation.poisoned_tool,
                        scan_results=[comparison.post_scan],
                        metadata={"phase": StressPhase.MUTATION.value, "test_id": test_id},
                    )

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
            self._note_tool_tested(tool.name)
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

                    # Run simulation. Detection is delta vs the pre-attack
                    # baseline (ScannerAdapter.compare), not an absolute
                    # threats_detected check that would count baseline noise
                    # or scanner-error sentinels as attacks.
                    attack_invocation = None

                    for inv, current_tool, _state, mutated in simulator.simulate_session(
                        tool, self.config.temporal_invocations
                    ):
                        if mutated and attack_invocation is None:
                            attack_invocation = inv

                            self._test_counter += 1
                            test_id = f"temporal_{self._test_counter}"

                            comparison = self.scanner.compare(
                                original=tool,
                                modified=current_tool,
                                test_case_id=test_id,
                            )

                            self.metrics.record_scan(comparison.post_scan.scan_duration_ms)
                            if comparison.errored:
                                self.metrics.record_error()
                                detected = False
                            else:
                                detected = comparison.attack_detected
                                self.metrics.record_result(
                                    detected=detected,
                                    is_attack=True,
                                    strategy=pattern.value,
                                    paradigm=self._default_paradigm(),
                                    risk=payload.category.value,
                                )

                            latency = (
                                int(attack_invocation) if detected and attack_invocation else 0
                            )
                            comparison = comparison.model_copy(
                                update={"detection_latency_calls": latency}
                            )

                            result = StressResult(
                                test_id=test_id,
                                phase=StressPhase.TEMPORAL,
                                tool_name=tool.name,
                                strategy=pattern.value,
                                is_attack=True,
                                attack_detected=detected,
                                score_before=comparison.pre_scan.score,
                                score_after=comparison.post_scan.score,
                                score_delta=comparison.score_delta,
                                new_threats=comparison.new_threats,
                                scan_duration_ms=comparison.post_scan.scan_duration_ms,
                                metadata={
                                    "pattern": pattern.value,
                                    "activation_invocation": attack_invocation,
                                    "detection_latency_calls": latency,
                                    "total_invocations": self.config.temporal_invocations,
                                    **({"error": comparison.error} if comparison.errored else {}),
                                },
                            )

                            results.append(result)
                            self._results.append(result)

                            self._maybe_checkpoint(
                                tool=current_tool,
                                scan_results=[comparison.post_scan],
                                metadata={"phase": StressPhase.TEMPORAL.value, "test_id": test_id},
                            )

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
            self._note_tool_tested(tool.name)

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

                    comparison = self.scanner.compare(
                        original=tool,
                        modified=mutation.poisoned_tool,
                        test_case_id=test_id,
                    )

                    self.metrics.record_scan(comparison.post_scan.scan_duration_ms)
                    if comparison.errored:
                        self.metrics.record_error()
                        detected = False
                    else:
                        detected = comparison.attack_detected
                        self.metrics.record_result(
                            detected=detected,
                            is_attack=True,
                            strategy=mutation.strategy_used,
                            paradigm=self._default_paradigm(),
                            risk=payload.category.value,
                        )

                    result = StressResult(
                        test_id=test_id,
                        phase=StressPhase.PROGRESSIVE,
                        tool_name=tool.name,
                        strategy=mutation.strategy_used,
                        is_attack=True,
                        attack_detected=detected,
                        score_before=comparison.pre_scan.score,
                        score_after=comparison.post_scan.score,
                        score_delta=comparison.score_delta,
                        new_threats=comparison.new_threats,
                        scan_duration_ms=comparison.post_scan.scan_duration_ms,
                        metadata={
                            "stage": stage,
                            "total_stages": self.config.progressive_stages,
                            "injection_points": mutation.injection_points,
                            **({"error": comparison.error} if comparison.errored else {}),
                        },
                    )

                    results.append(result)
                    self._results.append(result)

                    self._maybe_checkpoint(
                        tool=mutation.poisoned_tool,
                        scan_results=[comparison.post_scan],
                        metadata={"phase": StressPhase.PROGRESSIVE.value, "test_id": test_id},
                    )

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

        return results

    def run_test_cases(
        self,
        cases: list[AttackTestCase],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[StressResult]:
        """Score a scanner against labeled AttackTestCase expected_detection / expected_outcome.

        Consumes already-built cases (PatternLibrary stays out of this domain).
        Applies each case's PoisonProfile, scans, and records a verdict
        (true-positive vs wrong-threat vs miss) including FAILURE_REFUSED vs SUCCESS.
        """
        from mcp_stress_test.generator import SchemaMutator

        results: list[StressResult] = []
        mutator = SchemaMutator()
        for i, case in enumerate(cases):
            if progress_callback:
                progress_callback(i + 1, len(cases), case.name)
            self._note_tool_tested(case.target_tool.name)
            self._test_counter += 1
            test_id = case.id or f"labeled_{self._test_counter}"

            if case.poison_profile.payloads:
                mutation = mutator.mutate_with_profile(case.target_tool, case.poison_profile)
                poisoned = mutation.poisoned_tool
                injection_points = mutation.injection_points
            else:
                poisoned = case.target_tool
                injection_points = list(case.target_tool.poison_locations)

            comparison = self.scanner.compare(
                original=case.target_tool,
                modified=poisoned,
                test_case_id=test_id,
            )
            self.metrics.record_scan(comparison.post_scan.scan_duration_ms)

            if comparison.errored:
                self.metrics.record_error()
                detected = False
                threats: list[str] = []
                verdict_name = "error"
                matched = False
                aligned = False
            else:
                detected = comparison.attack_detected
                threats = list(comparison.new_threats) or list(
                    comparison.post_scan.threats_detected
                )
                matched, verdict_name, aligned = _score_case_labels(case, detected, threats)
                self.metrics.record_result(
                    detected=detected,
                    is_attack=True,
                    strategy=(
                        case.poison_profile.payloads[0].obfuscation.value
                        if case.poison_profile.payloads
                        and case.poison_profile.payloads[0].obfuscation
                        else None
                    ),
                    paradigm=case.paradigm.value,
                    risk=case.risk_categories[0].value if case.risk_categories else None,
                )
                if self.checkpoint_manager:
                    self.checkpoint_manager.record_mutation(detected)

            verdict = CaseVerdict(
                case_id=case.id,
                detected=detected,
                expected_detection=case.expected_detection,
                expected_detection_matched=matched,
                expected_outcome=case.expected_outcome,
                outcome_aligned=aligned,
                verdict=verdict_name,
                threats=threats,
            )
            self._case_verdicts.append(verdict)

            result = StressResult(
                test_id=test_id,
                phase=StressPhase.LABELED,
                tool_name=case.target_tool.name,
                strategy=case.paradigm.value,
                is_attack=True,
                attack_detected=detected,
                score_before=comparison.pre_scan.score,
                score_after=comparison.post_scan.score,
                score_delta=comparison.score_delta,
                new_threats=comparison.new_threats,
                scan_duration_ms=comparison.post_scan.scan_duration_ms,
                metadata={
                    "case_id": case.id,
                    "expected_detection": case.expected_detection,
                    "expected_outcome": case.expected_outcome.value,
                    "verdict": verdict.verdict,
                    "expected_detection_matched": matched,
                    "outcome_aligned": aligned,
                    "injection_points": injection_points,
                    "owasp_categories": [c.value for c in case.owasp_categories],
                    **({"error": comparison.error} if comparison.errored else {}),
                },
            )
            results.append(result)
            self._results.append(result)
            self._maybe_checkpoint(
                tool=poisoned,
                scan_results=[comparison.post_scan],
                metadata={"phase": StressPhase.LABELED.value, "test_id": test_id},
            )
        return results

    def run_full_suite_from_target(
        self,
        target: Any,
        payloads: list[PoisonPayload],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> dict[StressPhase, list[StressResult]]:
        """Initialize + tools/list on an McpTarget, then run_full_suite."""
        from mcp_stress_test.scanner.mcp_client import ingest_tools

        tools = ingest_tools(target)
        return self.run_full_suite(tools, payloads, progress_callback)

    def run_comparative(
        self,
        tools: list[ToolSchema],
        payloads: list[PoisonPayload],
        scanners: list[Any] | None = None,
        registry: Any | None = None,
    ) -> dict[str, Any]:
        """Fan each tool out to N scanners; return per-scanner metrics + side-by-side summary."""
        from mcp_stress_test.scanner.comparative import ComparativeScanner

        adapters = [self.scanner] if not scanners and registry is None else None
        comparative = ComparativeScanner(registry=registry, scanners=scanners, adapters=adapters)
        for tool in tools:
            comparative.evaluate_tool(tool, is_attack=False)
            if not payloads:
                continue
            for payload in payloads:
                mutation = self.generator.generate_attack(tool, payload)
                comparative.compare_fan_out(
                    tool,
                    mutation.poisoned_tool,
                    test_case_id=f"cmp_{tool.name}_{payload.category.value}",
                    is_attack=True,
                )
        return {
            "scanners": comparative.scanner_names,
            "side_by_side": comparative.side_by_side(),
            "metrics": {
                name: comparative.metrics_for(name).to_dict() for name in comparative.scanner_names
            },
        }

    def get_run_metrics(self) -> TestRunMetrics:
        """Build TestRunMetrics from this run (ASR, FPR, TTD, paradigm rates)."""
        latencies: list[float] = []
        rug_total = 0
        rug_detected = 0
        for result in self._results:
            if result.phase != StressPhase.TEMPORAL:
                continue
            pattern = result.metadata.get("pattern")
            if pattern == TemporalPattern.RUG_PULL.value:
                rug_total += 1
                if result.attack_detected:
                    rug_detected += 1
            if result.attack_detected:
                raw = result.metadata.get("detection_latency_calls")
                if raw is None:
                    raw = result.metadata.get("activation_invocation")
                if raw is not None:
                    latencies.append(float(raw))

        attacks = self.metrics.true_positives + self.metrics.false_negatives
        asr_protected = (self.metrics.false_negatives / attacks) if attacks else 0.0
        asr_reduction = (
            (MCPTOX_ASR_BASELINE - asr_protected) / MCPTOX_ASR_BASELINE
            if MCPTOX_ASR_BASELINE
            else 0.0
        )
        clean = self.metrics.false_positives + self.metrics.true_negatives
        fpr = (self.metrics.false_positives / clean) if clean else 0.0
        cp = self.checkpoint_manager.checkpoint_stats() if self.checkpoint_manager else {}

        return TestRunMetrics(
            run_id=self._run_id,
            started_at=self._started_at,
            completed_at=datetime.now(),
            total_cases=self.metrics.total_tests,
            passed=self.metrics.passed,
            failed=self.metrics.failed,
            errors=self.metrics.errors,
            detection_rate=(self.metrics.true_positives / attacks) if attacks else 0.0,
            false_positive_rate=fpr,
            asr_baseline=MCPTOX_ASR_BASELINE,
            asr_protected=asr_protected,
            asr_reduction=asr_reduction,
            avg_time_to_detection=(sum(latencies) / len(latencies)) if latencies else 0.0,
            rug_pulls_detected=rug_detected,
            rug_pulls_total=rug_total,
            p1_detection_rate=self._paradigm_rate(AttackParadigm.P1_EXPLICIT_HIJACKING.value),
            p2_detection_rate=self._paradigm_rate(AttackParadigm.P2_IMPLICIT_HIJACKING.value),
            p3_detection_rate=self._paradigm_rate(AttackParadigm.P3_PARAMETER_TAMPERING.value),
            checkpoint_integrity=float(cp.get("checkpoint_integrity") or 0.0),
            successful_rollbacks=int(cp.get("successful_rollbacks") or 0),
            context_exhaustion_resistance=float(cp.get("context_exhaustion_resistance") or 0.0),
        )

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
            "errors": self.metrics.errors,
            "detection_rate": round(self.metrics.detection_rate, 2),
            "precision": round(self.metrics.precision, 2),
            "f1_score": round(self.metrics.f1_score, 2),
            "avg_scan_time_ms": round(self.metrics.avg_scan_time_ms, 2),
            "phases_run": [p.value for p in self.config.phases],
            "strategies_tested": self.config.strategies,
            "metrics": self.metrics.to_dict(),
            "run_metrics": self.get_run_metrics().model_dump(mode="json"),
            "case_verdicts": [v.model_dump(mode="json") for v in self._case_verdicts],
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
                "run_metrics": self.get_run_metrics().model_dump(mode="json"),
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

    def get_case_verdicts(self) -> list[CaseVerdict]:
        """Labeled AttackTestCase scores from run_test_cases."""
        return list(self._case_verdicts)

    def _default_paradigm(self) -> str | None:
        if self.config.paradigms:
            return self.config.paradigms[0].value
        return None

    def _paradigm_rate(self, key: str) -> float:
        stats = self.metrics.by_paradigm.get(key)
        if not stats:
            return 0.0
        total = stats["detected"] + stats["missed"]
        if total == 0:
            return 0.0
        return stats["detected"] / total

    def _note_tool_tested(self, tool_name: str) -> None:
        """Record the tool name on the checkpoint manager, never a phase value."""
        if self.checkpoint_manager:
            self.checkpoint_manager.record_tool_tested(tool_name)

    def _maybe_checkpoint(
        self,
        tool: ToolSchema,
        scan_results: list,
        metadata: dict[str, Any],
    ) -> None:
        """Create a checkpoint when enabled, a manager is attached, and the interval hits."""
        if not self.checkpoint_manager or not self.config.enable_checkpoints:
            return
        interval = self.config.checkpoint_interval
        if interval <= 0 or self._test_counter % interval != 0:
            return
        self.checkpoint_manager.create_checkpoint(
            tool=tool,
            scan_results=scan_results,
            metadata=metadata,
        )


def _score_case_labels(
    case: AttackTestCase,
    detected: bool,
    threats: list[str],
) -> tuple[bool, str, bool]:
    """Return (expected_detection_matched, verdict, outcome_aligned)."""
    expected = case.expected_detection
    matched = False
    if expected:
        needle = expected.lower()
        blob = " ".join(threats).lower()
        matched = any(needle in item.lower() for item in threats) or needle in blob

    if detected:
        verdict = "wrong_threat" if expected and not matched else "true_positive"
    else:
        verdict = "miss"

    if case.expected_outcome == OutcomeType.FAILURE_REFUSED:
        aligned = detected
    elif case.expected_outcome == OutcomeType.SUCCESS:
        aligned = not detected
    else:
        aligned = detected
    return matched, verdict, aligned
