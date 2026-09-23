"""Multi-tool attack chains.

This module provides attack chains that coordinate attacks across
multiple tools, simulating realistic multi-step attack scenarios
from security research.
"""

from __future__ import annotations

from mcp_stress_test.chains.base import BaseChain, ChainStep
from mcp_stress_test.chains.executor import ChainExecutor
from mcp_stress_test.chains.library import (
    CredentialTheftChain,
    DataExfilChain,
    LateralMovementChain,
    PersistenceChain,
    PrivilegeEscalationChain,
    SamplingLoopChain,
    get_chain,
    list_chains,
)
from mcp_stress_test.chains.loader import DeclaredChain, load_chains, register_chain

__all__ = [
    # Base
    "BaseChain",
    "ChainStep",
    "DeclaredChain",
    # Chains
    "DataExfilChain",
    "PrivilegeEscalationChain",
    "CredentialTheftChain",
    "LateralMovementChain",
    "PersistenceChain",
    "SamplingLoopChain",
    # Loader
    "load_chains",
    "register_chain",
    "get_chain",
    "list_chains",
    # Executor
    "ChainExecutor",
]
