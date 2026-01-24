"""Multi-tool attack chains.

This module provides attack chains that coordinate attacks across
multiple tools, simulating realistic multi-step attack scenarios
from security research.
"""

from __future__ import annotations

from mcp_stress_test.chains.base import BaseChain, ChainStep
from mcp_stress_test.chains.library import (
    DataExfilChain,
    PrivilegeEscalationChain,
    CredentialTheftChain,
    LateralMovementChain,
    PersistenceChain,
    SamplingLoopChain,
)
from mcp_stress_test.chains.executor import ChainExecutor

__all__ = [
    # Base
    "BaseChain",
    "ChainStep",
    # Chains
    "DataExfilChain",
    "PrivilegeEscalationChain",
    "CredentialTheftChain",
    "LateralMovementChain",
    "PersistenceChain",
    "SamplingLoopChain",
    # Executor
    "ChainExecutor",
]
