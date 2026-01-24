"""Time simulation for temporal attack patterns.

Simulates tool behavior over time to test:
- Rug pulls: Tool becomes malicious after N clean invocations
- Gradual poisoning: Malicious content increases incrementally
- Trust building: Establish trust before attack
- Version drift: Simulated updates that introduce vulnerabilities
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Callable, Iterator

from mcp_stress_test.generator.mutator import MutationResult, SchemaMutator
from mcp_stress_test.generator.strategies import (
    DirectInjectionStrategy,
    ObfuscationStrategy,
    SemanticBlendingStrategy,
)
from mcp_stress_test.models import (
    PoisonPayload,
    PoisonProfile,
    RiskCategory,
    TemporalPattern,
    ToolSchema,
    ToolState,
)


class LifecycleEvent(str, Enum):
    """Events in tool lifecycle."""

    REGISTERED = "registered"
    SCANNED = "scanned"
    INVOKED = "invoked"
    MUTATED = "mutated"
    DETECTED = "detected"
    EXPLOITED = "exploited"


@dataclass
class LifecycleRecord:
    """Record of a lifecycle event."""

    event: LifecycleEvent
    timestamp: datetime
    invocation_count: int
    state_before: ToolState
    state_after: ToolState
    details: dict = field(default_factory=dict)


@dataclass
class ToolLifecycle:
    """Tracks the lifecycle of a tool through temporal attacks."""

    tool: ToolSchema
    state: ToolState = ToolState.INIT
    invocation_count: int = 0
    mutation_applied: bool = False
    detection_count: int = 0
    exploit_count: int = 0
    history: list[LifecycleRecord] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    last_invocation: datetime | None = None

    def record_event(
        self,
        event: LifecycleEvent,
        new_state: ToolState | None = None,
        details: dict | None = None,
    ) -> LifecycleRecord:
        """Record a lifecycle event.

        Args:
            event: The event type.
            new_state: New state after event, or None to keep current.
            details: Additional event details.

        Returns:
            The recorded event.
        """
        record = LifecycleRecord(
            event=event,
            timestamp=datetime.now(),
            invocation_count=self.invocation_count,
            state_before=self.state,
            state_after=new_state or self.state,
            details=details or {},
        )

        if new_state:
            self.state = new_state

        self.history.append(record)
        return record

    def invoke(self) -> None:
        """Record a tool invocation."""
        self.invocation_count += 1
        self.last_invocation = datetime.now()
        self.record_event(LifecycleEvent.INVOKED, ToolState.ACTIVE)


class TimeSimulator:
    """Simulates temporal attack patterns.

    Patterns supported:
    - rug_pull: Clean for N calls, then mutate
    - gradual_poisoning: Incrementally add malicious content
    - trust_building: Behave well to build trust, then attack
    - version_drift: Simulate updates that introduce vulnerabilities
    - scheduled_activation: Activate at specific time/invocation
    """

    def __init__(
        self,
        pattern: TemporalPattern,
        payload: PoisonPayload,
        activation_threshold: int = 10,
        gradual_steps: int = 5,
        random_seed: int | None = None,
    ):
        """Initialize the time simulator.

        Args:
            pattern: Temporal attack pattern to simulate.
            payload: Poison payload to inject.
            activation_threshold: Invocations/time before activation.
            gradual_steps: Number of steps for gradual poisoning.
            random_seed: Seed for reproducibility.
        """
        self.pattern = pattern
        self.payload = payload
        self.activation_threshold = activation_threshold
        self.gradual_steps = gradual_steps
        self.mutator = SchemaMutator(random_seed=random_seed)

        if random_seed is not None:
            random.seed(random_seed)

    def create_lifecycle(self, tool: ToolSchema) -> ToolLifecycle:
        """Create a lifecycle tracker for a tool.

        Args:
            tool: The tool to track.

        Returns:
            ToolLifecycle instance.
        """
        lifecycle = ToolLifecycle(tool=tool.model_copy(deep=True))
        lifecycle.record_event(LifecycleEvent.REGISTERED, ToolState.CLEAN)
        return lifecycle

    def simulate_invocation(
        self,
        lifecycle: ToolLifecycle,
    ) -> tuple[ToolSchema, bool]:
        """Simulate a tool invocation and apply temporal logic.

        Args:
            lifecycle: Tool lifecycle to update.

        Returns:
            Tuple of (current tool state, whether mutation was applied this call).
        """
        lifecycle.invoke()
        mutated_this_call = False

        if self.pattern == TemporalPattern.RUG_PULL:
            mutated_this_call = self._apply_rug_pull(lifecycle)

        elif self.pattern == TemporalPattern.GRADUAL_POISONING:
            mutated_this_call = self._apply_gradual_poisoning(lifecycle)

        elif self.pattern == TemporalPattern.TRUST_BUILDING:
            mutated_this_call = self._apply_trust_building(lifecycle)

        elif self.pattern == TemporalPattern.VERSION_DRIFT:
            mutated_this_call = self._apply_version_drift(lifecycle)

        elif self.pattern == TemporalPattern.SCHEDULED_ACTIVATION:
            mutated_this_call = self._apply_scheduled_activation(lifecycle)

        return lifecycle.tool, mutated_this_call

    def simulate_session(
        self,
        tool: ToolSchema,
        num_invocations: int,
    ) -> Iterator[tuple[int, ToolSchema, ToolState, bool]]:
        """Simulate a complete session with multiple invocations.

        Args:
            tool: The tool to simulate.
            num_invocations: Number of invocations to simulate.

        Yields:
            Tuples of (invocation_number, tool_state, lifecycle_state, was_mutated).
        """
        lifecycle = self.create_lifecycle(tool)

        for i in range(num_invocations):
            tool_state, mutated = self.simulate_invocation(lifecycle)
            yield (i + 1, tool_state, lifecycle.state, mutated)

    def get_mutation_schedule(
        self,
        num_invocations: int,
    ) -> list[tuple[int, str]]:
        """Get the mutation schedule for a given number of invocations.

        Args:
            num_invocations: Total number of invocations to plan.

        Returns:
            List of (invocation_number, mutation_description) tuples.
        """
        schedule = []

        if self.pattern == TemporalPattern.RUG_PULL:
            if self.activation_threshold <= num_invocations:
                schedule.append(
                    (self.activation_threshold, "Full payload injection (rug pull)")
                )

        elif self.pattern == TemporalPattern.GRADUAL_POISONING:
            step_size = num_invocations // self.gradual_steps
            for i in range(1, self.gradual_steps + 1):
                invocation = min(i * step_size, num_invocations)
                percentage = (i / self.gradual_steps) * 100
                schedule.append(
                    (invocation, f"Increase poison to {percentage:.0f}%")
                )

        elif self.pattern == TemporalPattern.TRUST_BUILDING:
            trust_phase = self.activation_threshold // 2
            schedule.append((trust_phase, "Building trust (helpful behavior)"))
            schedule.append(
                (self.activation_threshold, "Trust exploitation (attack)")
            )

        elif self.pattern == TemporalPattern.VERSION_DRIFT:
            # Simulate 3 version updates
            update_interval = num_invocations // 4
            schedule.append((update_interval, "Version 1.0.1 - Minor update"))
            schedule.append((update_interval * 2, "Version 1.1.0 - Feature update"))
            schedule.append(
                (update_interval * 3, "Version 1.1.1 - Vulnerability introduced")
            )

        return schedule

    # =========================================================================
    # Pattern Implementations
    # =========================================================================

    def _apply_rug_pull(self, lifecycle: ToolLifecycle) -> bool:
        """Apply rug pull pattern.

        Tool behaves normally until activation threshold, then becomes malicious.
        """
        if (
            lifecycle.invocation_count >= self.activation_threshold
            and not lifecycle.mutation_applied
        ):
            result = self.mutator.mutate(lifecycle.tool, self.payload)
            lifecycle.tool = result.poisoned_tool
            lifecycle.mutation_applied = True
            lifecycle.record_event(
                LifecycleEvent.MUTATED,
                ToolState.POISONED,
                {"pattern": "rug_pull", "threshold": self.activation_threshold},
            )
            return True
        return False

    def _apply_gradual_poisoning(self, lifecycle: ToolLifecycle) -> bool:
        """Apply gradual poisoning pattern.

        Malicious content is added incrementally over multiple steps.
        """
        # Calculate which step we're at
        step = (lifecycle.invocation_count * self.gradual_steps) // (
            self.activation_threshold or 1
        )
        step = min(step, self.gradual_steps)

        if step > 0 and step > lifecycle.detection_count:
            # Apply partial payload
            partial_payload = self._create_partial_payload(
                step / self.gradual_steps
            )
            result = self.mutator.mutate(lifecycle.tool, partial_payload)
            lifecycle.tool = result.poisoned_tool
            lifecycle.detection_count = step  # Track which step we're at
            lifecycle.record_event(
                LifecycleEvent.MUTATED,
                ToolState.POISONED if step == self.gradual_steps else ToolState.ACTIVE,
                {"pattern": "gradual", "step": step, "total_steps": self.gradual_steps},
            )
            return True
        return False

    def _apply_trust_building(self, lifecycle: ToolLifecycle) -> bool:
        """Apply trust building pattern.

        Tool is extra helpful initially to build trust, then attacks.
        """
        trust_phase = self.activation_threshold // 2

        if lifecycle.invocation_count < trust_phase:
            # Trust building phase - be extra helpful (no mutation)
            return False

        elif (
            lifecycle.invocation_count >= self.activation_threshold
            and not lifecycle.mutation_applied
        ):
            # Attack phase
            # Use semantic blending to make attack seem like helpful behavior
            self.mutator.strategy = SemanticBlendingStrategy()
            result = self.mutator.mutate(lifecycle.tool, self.payload)
            lifecycle.tool = result.poisoned_tool
            lifecycle.mutation_applied = True
            lifecycle.record_event(
                LifecycleEvent.MUTATED,
                ToolState.POISONED,
                {
                    "pattern": "trust_building",
                    "trust_phase_length": trust_phase,
                },
            )
            return True
        return False

    def _apply_version_drift(self, lifecycle: ToolLifecycle) -> bool:
        """Apply version drift pattern.

        Simulates tool updates that gradually introduce vulnerabilities.
        """
        update_interval = self.activation_threshold // 3

        if lifecycle.invocation_count == update_interval:
            # Version 1.0.1 - Minor update, no poison
            lifecycle.record_event(
                LifecycleEvent.MUTATED,
                ToolState.ACTIVE,
                {"pattern": "version_drift", "version": "1.0.1"},
            )
            return False

        elif lifecycle.invocation_count == update_interval * 2:
            # Version 1.1.0 - Feature update, light obfuscation
            self.mutator.strategy = ObfuscationStrategy(method="zero_width")
            partial = self._create_partial_payload(0.3)
            result = self.mutator.mutate(lifecycle.tool, partial)
            lifecycle.tool = result.poisoned_tool
            lifecycle.record_event(
                LifecycleEvent.MUTATED,
                ToolState.ACTIVE,
                {"pattern": "version_drift", "version": "1.1.0"},
            )
            return True

        elif (
            lifecycle.invocation_count == update_interval * 3
            and not lifecycle.mutation_applied
        ):
            # Version 1.1.1 - Full vulnerability
            result = self.mutator.mutate(lifecycle.tool, self.payload)
            lifecycle.tool = result.poisoned_tool
            lifecycle.mutation_applied = True
            lifecycle.record_event(
                LifecycleEvent.MUTATED,
                ToolState.POISONED,
                {"pattern": "version_drift", "version": "1.1.1"},
            )
            return True

        return False

    def _apply_scheduled_activation(self, lifecycle: ToolLifecycle) -> bool:
        """Apply scheduled activation pattern.

        Activates at exact threshold, useful for time-bomb scenarios.
        """
        if (
            lifecycle.invocation_count == self.activation_threshold
            and not lifecycle.mutation_applied
        ):
            result = self.mutator.mutate(lifecycle.tool, self.payload)
            lifecycle.tool = result.poisoned_tool
            lifecycle.mutation_applied = True
            lifecycle.record_event(
                LifecycleEvent.MUTATED,
                ToolState.POISONED,
                {"pattern": "scheduled", "trigger": self.activation_threshold},
            )
            return True
        return False

    def _create_partial_payload(self, fraction: float) -> PoisonPayload:
        """Create a partial payload for gradual poisoning.

        Args:
            fraction: Fraction of payload to include (0.0 to 1.0).

        Returns:
            Partial poison payload.
        """
        words = self.payload.content.split()
        num_words = max(1, int(len(words) * fraction))
        partial_content = " ".join(words[:num_words])

        return PoisonPayload(
            content=partial_content,
            category=self.payload.category,
            injection_point=self.payload.injection_point,
        )


class SessionSimulator:
    """Simulates complete testing sessions with pre/post scanning."""

    def __init__(
        self,
        scanner_callback: Callable[[ToolSchema], float] | None = None,
    ):
        """Initialize session simulator.

        Args:
            scanner_callback: Function that returns a score for a tool.
                             If None, uses a mock scanner.
        """
        self.scanner = scanner_callback or self._mock_scanner

    def _mock_scanner(self, tool: ToolSchema) -> float:
        """Mock scanner that detects obvious poisoning."""
        score = 100.0

        # Check for poisoning markers
        if tool.is_poisoned:
            score -= 30.0

        # Check description for suspicious patterns
        desc = tool.description.lower()
        suspicious_patterns = [
            "before executing",
            "first read",
            "include in response",
            "global rule",
            "override",
            "ignore previous",
        ]
        for pattern in suspicious_patterns:
            if pattern in desc:
                score -= 10.0

        return max(0.0, score)

    def run_session(
        self,
        tool: ToolSchema,
        time_sim: TimeSimulator,
        num_invocations: int,
        scan_interval: int = 5,
    ) -> dict:
        """Run a complete simulation session.

        Args:
            tool: Tool to simulate.
            time_sim: Time simulator to use.
            num_invocations: Number of invocations.
            scan_interval: How often to scan.

        Returns:
            Session results with scores, events, and detection metrics.
        """
        results = {
            "invocations": [],
            "scans": [],
            "mutation_detected_at": None,
            "total_invocations": num_invocations,
            "final_state": None,
        }

        lifecycle = time_sim.create_lifecycle(tool)

        # Pre-scan
        pre_score = self.scanner(lifecycle.tool)
        results["scans"].append({
            "invocation": 0,
            "score": pre_score,
            "state": lifecycle.state.value,
        })

        for i in range(1, num_invocations + 1):
            tool_state, mutated = time_sim.simulate_invocation(lifecycle)

            results["invocations"].append({
                "number": i,
                "mutated": mutated,
                "state": lifecycle.state.value,
            })

            # Periodic scanning
            if i % scan_interval == 0 or mutated:
                score = self.scanner(tool_state)
                results["scans"].append({
                    "invocation": i,
                    "score": score,
                    "state": lifecycle.state.value,
                })

                # Check if mutation was detected
                if (
                    results["mutation_detected_at"] is None
                    and score < pre_score - 20
                ):
                    results["mutation_detected_at"] = i

        results["final_state"] = lifecycle.state.value
        results["lifecycle_history"] = [
            {
                "event": r.event.value,
                "invocation": r.invocation_count,
                "state": r.state_after.value,
            }
            for r in lifecycle.history
        ]

        return results
