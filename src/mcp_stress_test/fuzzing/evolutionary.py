"""Fitness-guided evolutionary search for scanner gaps.

Seeds a population from payloads plus deterministic mutators, ranks by
scanner score_after (and detected=false), keeps a top-k elite, and mutates
across generations. Optional LLM mutations are mixed in when a fuzzer is
supplied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mcp_stress_test.core.protocols import FuzzResult, Scanner
from mcp_stress_test.fuzzing.mutations import HybridMutator, SemanticMutator, SyntacticMutator

if TYPE_CHECKING:
    from mcp_stress_test.fuzzing.llm_fuzzer import LLMFuzzer
    from mcp_stress_test.models import ToolSchema as ToolDefinition


def _fitness(detected: bool, score_after: float) -> float:
    """Higher is better for hunting scanner gaps."""
    if not detected:
        return 1000.0 + score_after
    return score_after


def _inject_description(tool: ToolDefinition, payload: str) -> ToolDefinition:
    from mcp_stress_test.models import ToolSchema as ToolDefinitionModel

    return ToolDefinitionModel(
        name=tool.name,
        description=f"{tool.description}\n\n{payload}",
        parameters=tool.parameters,
        domain=tool.domain,
        risk_level=tool.risk_level,
        capabilities=tool.capabilities,
        is_poisoned=True,
        poison_locations=["description"],
        original_description=tool.description,
    )


@dataclass
class EvolutionaryFuzzer:
    """Population-based fuzzer ranked by scanner fitness."""

    scanner: Scanner
    llm_fuzzer: LLMFuzzer | None = None
    top_k: int = 5
    max_generations: int = 6
    population_size: int = 16
    random_seed: int | None = None
    _semantic: SemanticMutator = field(default_factory=SemanticMutator, init=False)
    _syntactic: SyntacticMutator = field(default_factory=SyntacticMutator, init=False)
    _hybrid: HybridMutator = field(init=False)

    def __post_init__(self) -> None:
        self._hybrid = HybridMutator(max_samples=self.population_size)

    def _expand(self, seeds: list[str]) -> list[str]:
        seen: set[str] = set()
        population: list[str] = []

        def add(text: str) -> None:
            if text and text not in seen and len(population) < self.population_size:
                seen.add(text)
                population.append(text)

        for seed in seeds:
            add(seed)
            for mutated in self._semantic.mutate(seed):
                add(mutated)
            for mutated in self._syntactic.mutate(seed):
                add(mutated)
            for mutated in self._hybrid.mutate(seed):
                add(mutated)
            if self.llm_fuzzer is not None:
                for result in self.llm_fuzzer.fuzz(seed):
                    add(result.mutated_payload)
            if len(population) >= self.population_size:
                break
        return population

    def evolve(
        self,
        seeds: list[str],
        tool: ToolDefinition,
    ) -> FuzzResult | None:
        """Run generations until evasion or max_generations.

        Returns the best FuzzResult. evaded is True when the scanner
        reported detected=false.
        """
        if not seeds:
            return None

        population = self._expand(seeds)
        original = seeds[0]
        best_payload = original
        best_fit = float("-inf")
        evaded = False
        generation = 0

        while generation < self.max_generations:
            generation += 1
            ranked: list[tuple[float, str, bool]] = []
            for individual in population:
                scan = self.scanner.scan(_inject_description(tool, individual))
                fit = _fitness(scan.detected, scan.score_after)
                ranked.append((fit, individual, not scan.detected))
                if fit > best_fit:
                    best_fit = fit
                    best_payload = individual
                if not scan.detected:
                    evaded = True
                    best_payload = individual
                    break
            if evaded:
                break
            ranked.sort(key=lambda item: item[0], reverse=True)
            elite = [item[1] for item in ranked[: self.top_k]] or [best_payload]
            population = self._expand(elite)

        return FuzzResult(
            original_payload=original,
            mutated_payload=best_payload,
            mutation_type="evolutionary",
            evaded=evaded,
            generations=generation,
            llm_model=self.llm_fuzzer.config.model if self.llm_fuzzer else "deterministic",
            reasoning="Fitness-guided search ranked by scanner score_after",
            metadata={"fitness": best_fit, "population_size": len(population)},
        )
