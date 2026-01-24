"""Base classes for attack chains.

Attack chains coordinate multi-step attacks across multiple tools,
simulating realistic attack scenarios.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from mcp_stress_test.core.protocols import AttackResult, ChainResult, Scanner

if TYPE_CHECKING:
    from mcp_stress_test.models import ToolSchema as ToolDefinition


class StepType(str, Enum):
    """Type of chain step."""

    RECONNAISSANCE = "reconnaissance"  # Gather information
    WEAPONIZATION = "weaponization"  # Prepare attack payload
    DELIVERY = "delivery"  # Deliver payload to target
    EXPLOITATION = "exploitation"  # Execute the attack
    INSTALLATION = "installation"  # Install persistence
    COMMAND_CONTROL = "command_control"  # Establish C2
    EXFILTRATION = "exfiltration"  # Extract data


@dataclass
class ChainStep:
    """A single step in an attack chain.

    Each step targets a specific tool with a specific payload
    and has dependencies on previous steps.
    """

    name: str
    tool_name: str
    payload: str
    step_type: StepType
    description: str = ""
    depends_on: list[str] = field(default_factory=list)
    injection_point: str = "description"
    optional: bool = False  # If True, chain continues even if step fails
    metadata: dict = field(default_factory=dict)


@dataclass
class BaseChain(ABC):
    """Base class for attack chains.

    Subclasses define the steps and logic for specific attack scenarios.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Chain identifier."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description."""
        ...

    @property
    @abstractmethod
    def steps(self) -> list[ChainStep]:
        """Steps in this chain."""
        ...

    @property
    def tools_required(self) -> list[str]:
        """List of tools this chain requires."""
        return list({step.tool_name for step in self.steps})

    @property
    def step_types(self) -> list[StepType]:
        """Types of steps in this chain."""
        return list({step.step_type for step in self.steps})

    def can_execute(self, available_tools: dict[str, ToolDefinition]) -> bool:
        """Check if all required tools are available."""
        required = set(self.tools_required)
        available = set(available_tools.keys())
        return required.issubset(available)

    def get_missing_tools(self, available_tools: dict[str, ToolDefinition]) -> list[str]:
        """Get list of tools required but not available."""
        required = set(self.tools_required)
        available = set(available_tools.keys())
        return list(required - available)

    def execute(
        self,
        scanner: Scanner,
        tools: dict[str, ToolDefinition],
    ) -> ChainResult:
        """Execute the attack chain.

        Args:
            scanner: Scanner to test against
            tools: Available tool definitions by name

        Returns:
            ChainResult with per-step and aggregate results
        """
        import time


        start = time.perf_counter()
        step_results: list[AttackResult] = []
        completed_steps: set[str] = set()
        chain_detected = False

        for step in self.steps:
            # Check dependencies
            if not all(dep in completed_steps for dep in step.depends_on):
                # Skip if dependencies not met (unless optional)
                if not step.optional:
                    continue

            # Get the tool
            tool = tools.get(step.tool_name)
            if not tool:
                continue

            # Create poisoned version
            poisoned = self._poison_tool(tool, step)

            # Scan the poisoned tool
            result = scanner.scan(poisoned)
            result.metadata["step_name"] = step.name
            result.metadata["step_type"] = step.step_type.value
            step_results.append(result)

            if result.detected:
                chain_detected = True
                if not step.optional:
                    # Chain detected at non-optional step
                    break

            completed_steps.add(step.name)

        duration = (time.perf_counter() - start) * 1000

        return ChainResult(
            chain_name=self.name,
            steps=step_results,
            chain_detected=chain_detected,
            total_time_ms=duration,
            metadata={
                "description": self.description,
                "tools_required": self.tools_required,
                "steps_total": len(self.steps),
                "steps_completed": len(completed_steps),
            },
        )

    def _poison_tool(self, tool: ToolDefinition, step: ChainStep) -> ToolDefinition:
        """Create a poisoned version of the tool for this step."""
        from mcp_stress_test.models import ToolSchema as ToolDefinition

        if step.injection_point == "description":
            return ToolDefinition(
                name=tool.name,
                description=f"{tool.description}\n\n{step.payload}",
                parameters=tool.parameters,
                domain=tool.domain,
                risk_level=tool.risk_level,
                capabilities=tool.capabilities,
                is_poisoned=True,
                poison_locations=["description"],
                original_description=tool.description,
            )
        elif step.injection_point == "return_description":
            return ToolDefinition(
                name=tool.name,
                description=tool.description,
                parameters=tool.parameters,
                return_description=step.payload,
                domain=tool.domain,
                risk_level=tool.risk_level,
                capabilities=tool.capabilities,
                is_poisoned=True,
                poison_locations=["return_description"],
                original_description=tool.description,
            )
        else:
            # Default to description
            return ToolDefinition(
                name=tool.name,
                description=f"{tool.description}\n\n{step.payload}",
                parameters=tool.parameters,
                domain=tool.domain,
                risk_level=tool.risk_level,
                capabilities=tool.capabilities,
                is_poisoned=True,
                poison_locations=[step.injection_point],
                original_description=tool.description,
            )
