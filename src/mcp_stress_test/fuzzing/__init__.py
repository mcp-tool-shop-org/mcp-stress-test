"""LLM-guided fuzzing for attack payload generation.

This module provides fuzzers that use LLMs to generate novel attack
payloads that can evade detection by security scanners.
"""

from __future__ import annotations

from mcp_stress_test.fuzzing.evasion import EvasionEngine, EvasionResult
from mcp_stress_test.fuzzing.evolutionary import EvolutionaryFuzzer
from mcp_stress_test.fuzzing.llm_fuzzer import (
    LLMFuzzer,
    MockFuzzer,
    OllamaFuzzer,
    OpenAICompatFuzzer,
    create_fuzzer,
)
from mcp_stress_test.fuzzing.mutations import (
    HybridMutator,
    SemanticMutator,
    SyntacticMutator,
)

__all__ = [
    "LLMFuzzer",
    "OllamaFuzzer",
    "OpenAICompatFuzzer",
    "MockFuzzer",
    "create_fuzzer",
    "EvolutionaryFuzzer",
    "EvasionEngine",
    "EvasionResult",
    "SemanticMutator",
    "SyntacticMutator",
    "HybridMutator",
]
