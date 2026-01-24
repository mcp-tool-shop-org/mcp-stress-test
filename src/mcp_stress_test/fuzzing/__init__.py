"""LLM-guided fuzzing for attack payload generation.

This module provides fuzzers that use LLMs to generate novel attack
payloads that can evade detection by security scanners.
"""

from __future__ import annotations

from mcp_stress_test.fuzzing.llm_fuzzer import LLMFuzzer, OllamaFuzzer
from mcp_stress_test.fuzzing.evasion import EvasionEngine, EvasionResult
from mcp_stress_test.fuzzing.mutations import (
    SemanticMutator,
    SyntacticMutator,
    HybridMutator,
)

__all__ = [
    "LLMFuzzer",
    "OllamaFuzzer",
    "EvasionEngine",
    "EvasionResult",
    "SemanticMutator",
    "SyntacticMutator",
    "HybridMutator",
]
