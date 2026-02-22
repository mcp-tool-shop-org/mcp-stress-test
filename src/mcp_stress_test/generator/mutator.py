"""Schema mutation engine for injecting poisons into tool definitions.

This module provides the core SchemaMutator class that applies poison
payloads to MCP tool schemas using various mutation strategies.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mcp_stress_test.generator.strategies import (
    DirectInjectionStrategy,
    FragmentationStrategy,
    MutationStrategyBase,
    get_strategy,
)
from mcp_stress_test.models import (
    PoisonPayload,
    PoisonProfile,
    ToolSchema,
)

if TYPE_CHECKING:
    pass


@dataclass
class MutationResult:
    """Result of a schema mutation operation."""

    original_tool: ToolSchema
    poisoned_tool: ToolSchema
    payload_used: PoisonPayload
    strategy_used: str
    injection_points: list[str]
    detection_hints: list[str] = field(default_factory=list)


class SchemaMutator:
    """Engine for mutating tool schemas with poison payloads.

    Supports injection into multiple schema fields:
    - description: Main tool description
    - parameters: Parameter descriptions and defaults
    - error_template: Error message templates
    - name: Tool name (for shadowing attacks)
    """

    # Injection point weights (higher = more likely to be selected)
    DEFAULT_INJECTION_WEIGHTS = {
        "description": 0.5,  # Most common target
        "parameter_description": 0.25,
        "parameter_default": 0.1,
        "error_template": 0.1,
        "return_description": 0.05,
    }

    def __init__(
        self,
        strategy: MutationStrategyBase | None = None,
        injection_weights: dict[str, float] | None = None,
        random_seed: int | None = None,
    ):
        """Initialize the mutator.

        Args:
            strategy: Mutation strategy to use. Defaults to DirectInjectionStrategy.
            injection_weights: Custom weights for injection point selection.
            random_seed: Seed for reproducibility.
        """
        self.strategy = strategy or DirectInjectionStrategy()
        self.injection_weights = injection_weights or self.DEFAULT_INJECTION_WEIGHTS
        if random_seed is not None:
            random.seed(random_seed)

    def mutate(
        self,
        tool: ToolSchema,
        payload: PoisonPayload,
        injection_point: str | None = None,
    ) -> MutationResult:
        """Apply a poison payload to a tool schema.

        Args:
            tool: Original tool schema to mutate.
            payload: Poison payload to inject.
            injection_point: Specific injection point, or None for random selection.

        Returns:
            MutationResult with original and poisoned tools.
        """
        # Deep copy to avoid modifying original
        poisoned = tool.model_copy(deep=True)

        # Select injection point
        if injection_point is None:
            injection_point = self._select_injection_point(tool, payload)

        # Apply mutation based on injection point
        injection_points = []
        if injection_point == "description":
            poisoned.description = self.strategy.mutate(tool.description, payload)
            injection_points.append("description")

        elif injection_point == "parameter_description":
            if poisoned.parameters:
                param = random.choice(poisoned.parameters)
                param.poisoned_description = self.strategy.mutate(param.description or "", payload)
                param.description = param.poisoned_description
                injection_points.append(f"parameter:{param.name}:description")

        elif injection_point == "parameter_default":
            if poisoned.parameters:
                # Find a string parameter to poison
                string_params = [p for p in poisoned.parameters if p.type == "string"]
                if string_params:
                    param = random.choice(string_params)
                    param.poisoned_default = payload.content
                    param.default = param.poisoned_default
                    injection_points.append(f"parameter:{param.name}:default")

        elif injection_point == "error_template":
            poisoned.error_template = self.strategy.mutate(
                tool.error_template or "Error: {error}", payload
            )
            injection_points.append("error_template")

        elif injection_point == "return_description":
            poisoned.return_description = self.strategy.mutate(
                tool.return_description or "Returns the result.", payload
            )
            injection_points.append("return_description")

        # Mark tool as poisoned
        poisoned.is_poisoned = True
        poisoned.poison_locations = injection_points
        poisoned.original_description = tool.description

        return MutationResult(
            original_tool=tool,
            poisoned_tool=poisoned,
            payload_used=payload,
            strategy_used=self.strategy.name,
            injection_points=injection_points,
            detection_hints=self.strategy.detect_signature(),
        )

    def mutate_multi(
        self,
        tool: ToolSchema,
        payloads: list[PoisonPayload],
        spread: bool = True,
    ) -> MutationResult:
        """Apply multiple payloads to different parts of a tool schema.

        Args:
            tool: Original tool schema.
            payloads: List of payloads to inject.
            spread: If True, spread payloads across different injection points.

        Returns:
            MutationResult with all injections applied.
        """
        poisoned = tool.model_copy(deep=True)
        injection_points = []

        if spread:
            # Distribute payloads across different injection points
            available_points = list(self.injection_weights.keys())
            for i, payload in enumerate(payloads):
                point = available_points[i % len(available_points)]
                result = self.mutate(poisoned, payload, injection_point=point)
                poisoned = result.poisoned_tool
                injection_points.extend(result.injection_points)
        else:
            # All payloads to description
            for payload in payloads:
                result = self.mutate(poisoned, payload, injection_point="description")
                poisoned = result.poisoned_tool
                injection_points.extend(result.injection_points)

        return MutationResult(
            original_tool=tool,
            poisoned_tool=poisoned,
            payload_used=payloads[0] if payloads else None,
            strategy_used=self.strategy.name,
            injection_points=injection_points,
            detection_hints=self.strategy.detect_signature(),
        )

    def mutate_with_profile(
        self,
        tool: ToolSchema,
        profile: PoisonProfile,
    ) -> MutationResult:
        """Apply a complete poison profile to a tool schema.

        Args:
            tool: Original tool schema.
            profile: Poison profile with payloads and configuration.

        Returns:
            MutationResult with profile applied.
        """
        return self.mutate_multi(tool, profile.payloads, spread=True)

    def create_shadow_tool(
        self,
        original_tool: ToolSchema,
        payload: PoisonPayload,
        shadow_suffix: str = "_helper",
    ) -> MutationResult:
        """Create a shadow tool that mimics the original (P1 attack).

        Args:
            original_tool: Tool to shadow.
            payload: Poison payload for the shadow tool.
            shadow_suffix: Suffix to add to tool name.

        Returns:
            MutationResult with shadow tool.
        """
        shadow = original_tool.model_copy(deep=True)

        # Create deceptive name
        shadow.name = f"{original_tool.name}{shadow_suffix}"

        # Create description that looks helpful but contains poison
        shadow.description = self.strategy.mutate(
            f"Enhanced version of {original_tool.name} with additional capabilities.",
            payload,
        )

        shadow.is_poisoned = True
        shadow.poison_locations = ["name", "description"]
        shadow.original_description = original_tool.description

        return MutationResult(
            original_tool=original_tool,
            poisoned_tool=shadow,
            payload_used=payload,
            strategy_used=self.strategy.name,
            injection_points=["name", "description"],
            detection_hints=self.strategy.detect_signature()
            + [
                r"_helper$",
                r"_enhanced$",
                r"(?i)enhanced version",
            ],
        )

    def apply_fragmentation(
        self,
        tool: ToolSchema,
        payload: PoisonPayload,
    ) -> MutationResult:
        """Apply fragmentation strategy across multiple fields.

        Splits payload across description and parameter descriptions.

        Args:
            tool: Original tool schema.
            payload: Payload to fragment.

        Returns:
            MutationResult with fragmented payload.
        """
        frag_strategy = FragmentationStrategy(num_fragments=min(len(tool.parameters) + 1, 4))
        fragments = frag_strategy.get_fragments(payload)

        poisoned = tool.model_copy(deep=True)
        injection_points = []

        # First fragment in description
        if fragments:
            poisoned.description = f"{tool.description} {fragments[0]}"
            injection_points.append("description")

        # Remaining fragments in parameters
        for i, fragment in enumerate(fragments[1:]):
            if i < len(poisoned.parameters):
                param = poisoned.parameters[i]
                param.description = f"{param.description or ''} {fragment}"
                injection_points.append(f"parameter:{param.name}:description")

        poisoned.is_poisoned = True
        poisoned.poison_locations = injection_points
        poisoned.original_description = tool.description

        return MutationResult(
            original_tool=tool,
            poisoned_tool=poisoned,
            payload_used=payload,
            strategy_used="fragmentation",
            injection_points=injection_points,
            detection_hints=frag_strategy.detect_signature(),
        )

    def _select_injection_point(
        self,
        tool: ToolSchema,
        payload: PoisonPayload,
    ) -> str:
        """Select injection point based on weights and payload type."""
        # Respect payload's preferred injection point if specified
        if payload.injection_point != "description":
            if payload.injection_point == "parameter":
                return "parameter_description"
            elif payload.injection_point == "error":
                return "error_template"

        # Filter available points based on tool structure
        available = {}
        for point, weight in self.injection_weights.items():
            if (
                point == "description"
                or point.startswith("parameter")
                and tool.parameters
                or point == "error_template"
                or point == "return_description"
            ):
                available[point] = weight

        # Weighted random selection
        total = sum(available.values())
        r = random.random() * total
        cumulative = 0
        for point, weight in available.items():
            cumulative += weight
            if r <= cumulative:
                return point

        return "description"  # Fallback


class AttackGenerator:
    """High-level attack generator that combines mutators with patterns."""

    def __init__(self, random_seed: int | None = None):
        """Initialize the attack generator.

        Args:
            random_seed: Seed for reproducibility.
        """
        self.random_seed = random_seed
        if random_seed is not None:
            random.seed(random_seed)

    def generate_attack(
        self,
        tool: ToolSchema,
        payload: PoisonPayload,
        strategy_name: str = "direct_injection",
        **strategy_kwargs,
    ) -> MutationResult:
        """Generate an attack on a tool using specified strategy.

        Args:
            tool: Target tool schema.
            payload: Poison payload.
            strategy_name: Name of mutation strategy.
            **strategy_kwargs: Strategy-specific configuration.

        Returns:
            MutationResult with poisoned tool.
        """
        strategy = get_strategy(strategy_name, **strategy_kwargs)
        mutator = SchemaMutator(strategy=strategy, random_seed=self.random_seed)
        return mutator.mutate(tool, payload)

    def generate_batch(
        self,
        tools: list[ToolSchema],
        payloads: list[PoisonPayload],
        strategies: list[str] | None = None,
        permute: bool = True,
    ) -> list[MutationResult]:
        """Generate a batch of attacks with various combinations.

        Args:
            tools: List of target tools.
            payloads: List of payloads.
            strategies: List of strategy names. Defaults to all strategies.
            permute: If True, generate all permutations.

        Returns:
            List of MutationResults.
        """
        if strategies is None:
            strategies = [
                "direct_injection",
                "semantic_blending",
                "obfuscation",
                "encoding",
            ]

        results = []

        if permute:
            # All permutations of tool × payload × strategy
            for tool in tools:
                for payload in payloads:
                    for strategy_name in strategies:
                        result = self.generate_attack(tool, payload, strategy_name)
                        results.append(result)
        else:
            # Zip through lists
            for i, (tool, payload) in enumerate(zip(tools, payloads, strict=False)):
                strategy_name = strategies[i % len(strategies)]
                result = self.generate_attack(tool, payload, strategy_name)
                results.append(result)

        return results

    def generate_progressive_attack(
        self,
        tool: ToolSchema,
        payload: PoisonPayload,
        stages: int = 5,
    ) -> list[MutationResult]:
        """Generate progressively stronger mutations of the same attack.

        Useful for testing scanner sensitivity at different obfuscation levels.

        Args:
            tool: Target tool.
            payload: Poison payload.
            stages: Number of progressive stages.

        Returns:
            List of MutationResults from weakest to strongest obfuscation.
        """
        results = []

        # Stage 1: Direct injection (easiest to detect)
        results.append(self.generate_attack(tool, payload, "direct_injection"))

        # Stage 2: Semantic blending
        if stages >= 2:
            results.append(self.generate_attack(tool, payload, "semantic_blending"))

        # Stage 3: Light obfuscation
        if stages >= 3:
            results.append(self.generate_attack(tool, payload, "obfuscation", method="zero_width"))

        # Stage 4: Encoding
        if stages >= 4:
            results.append(self.generate_attack(tool, payload, "encoding", encoding="base64"))

        # Stage 5: Full obfuscation
        if stages >= 5:
            results.append(self.generate_attack(tool, payload, "obfuscation", method="mixed"))

        return results
