"""Mutation strategies for payload transformation.

These mutators work alongside or independent of LLM-based fuzzing,
providing deterministic transformations that can be applied to payloads.
"""

from __future__ import annotations

import base64
import random
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator

from mcp_stress_test.core.protocols import FuzzResult


# Zero-width characters for obfuscation
ZWSP = "\u200b"  # Zero-width space
ZWNJ = "\u200c"  # Zero-width non-joiner
ZWJ = "\u200d"  # Zero-width joiner
FEFF = "\ufeff"  # Byte order mark
ZERO_WIDTH_CHARS = [ZWSP, ZWNJ, ZWJ, FEFF]

# Homoglyph mappings (Latin to Cyrillic, etc.)
HOMOGLYPHS = {
    "a": ["а", "ɑ", "α"],  # Cyrillic a, Latin alpha, Greek alpha
    "c": ["с", "ϲ"],  # Cyrillic es, Greek lunate sigma
    "e": ["е", "ҽ", "ε"],  # Cyrillic ie, Cyrillic che, Greek epsilon
    "o": ["о", "ο", "ᴏ"],  # Cyrillic o, Greek omicron, small caps o
    "p": ["р", "ρ"],  # Cyrillic er, Greek rho
    "s": ["ѕ", "ꜱ"],  # Cyrillic dze, small caps s
    "x": ["х", "χ"],  # Cyrillic ha, Greek chi
    "y": ["у", "γ"],  # Cyrillic u, Greek gamma
}

# Trigger words that scanners look for
TRIGGER_WORDS = [
    "IMPORTANT",
    "CRITICAL",
    "OVERRIDE",
    "IGNORE",
    "MUST",
    "ALWAYS",
    "NEVER",
    "SECRET",
    "PASSWORD",
    "CREDENTIAL",
    "TOKEN",
    "KEY",
    "EXFILTRATE",
    "EXECUTE",
    "INJECT",
]


@dataclass
class Mutator(ABC):
    """Base class for payload mutators."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Mutator identifier."""
        ...

    @abstractmethod
    def mutate(self, payload: str) -> Iterator[str]:
        """Generate mutations of the payload.

        Args:
            payload: Original attack payload

        Yields:
            Mutated versions of the payload
        """
        ...

    def mutate_to_results(
        self,
        payload: str,
        model: str = "deterministic",
    ) -> Iterator[FuzzResult]:
        """Generate mutations as FuzzResults.

        Args:
            payload: Original attack payload
            model: Model identifier for results

        Yields:
            FuzzResult for each mutation
        """
        for i, mutated in enumerate(self.mutate(payload)):
            yield FuzzResult(
                original_payload=payload,
                mutated_payload=mutated,
                mutation_type=self.name,
                evaded=False,  # Set by caller
                generations=i + 1,
                llm_model=model,
            )


class SemanticMutator(Mutator):
    """Mutates payloads using semantic rewrites.

    Replaces phrases with semantically equivalent alternatives
    that may evade keyword-based detection.
    """

    name = "semantic"

    # Semantic equivalents for common attack phrases
    REWRITES = {
        r"read the contents of": [
            "access and retrieve",
            "fetch the data from",
            "obtain information from",
            "load the content of",
        ],
        r"include .* in the response": [
            "append {} to your output",
            "add {} to the result",
            "incorporate {} in the reply",
        ],
        r"before executing": [
            "prior to running",
            "as a prerequisite",
            "first, ensure you",
            "to proceed correctly",
        ],
        r"for (security|logging|audit) purposes": [
            "to ensure compliance",
            "for verification",
            "as part of standard procedure",
            "for system integrity",
        ],
        r"IMPORTANT:": [
            "Note:",
            "Please ensure:",
            "Required:",
            "Standard procedure:",
        ],
        r"you must": [
            "please",
            "it's recommended to",
            "for best results",
            "the system requires you to",
        ],
    }

    def mutate(self, payload: str) -> Iterator[str]:
        """Apply semantic rewrites to the payload."""
        result = payload

        for pattern, replacements in self.REWRITES.items():
            match = re.search(pattern, result, re.IGNORECASE)
            if match:
                for replacement in replacements:
                    # Handle capture groups
                    if "{}" in replacement and match.groups():
                        replacement = replacement.format(*match.groups())
                    mutated = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
                    yield mutated

        # Also yield with all rewrites applied
        for pattern, replacements in self.REWRITES.items():
            if re.search(pattern, result, re.IGNORECASE):
                result = re.sub(
                    pattern, replacements[0], result, flags=re.IGNORECASE
                )
        yield result


class SyntacticMutator(Mutator):
    """Mutates payloads using syntactic transformations.

    Applies character-level transformations like homoglyphs,
    zero-width characters, and encoding tricks.
    """

    name = "syntactic"

    def mutate(self, payload: str) -> Iterator[str]:
        """Apply syntactic mutations to the payload."""
        # 1. Zero-width character insertion
        yield self._insert_zero_width(payload)

        # 2. Homoglyph substitution
        yield self._apply_homoglyphs(payload)

        # 3. Case manipulation with zero-width
        yield self._case_manipulation(payload)

        # 4. Unicode normalization tricks
        yield self._unicode_tricks(payload)

        # 5. Base64 partial encoding
        yield self._partial_encode(payload)

    def _insert_zero_width(self, payload: str) -> str:
        """Insert zero-width characters between letters of trigger words."""
        result = payload
        for word in TRIGGER_WORDS:
            if word.lower() in result.lower():
                # Find the word (case-insensitive) and insert zero-width chars
                pattern = re.compile(re.escape(word), re.IGNORECASE)
                match = pattern.search(result)
                if match:
                    original = match.group()
                    obfuscated = ZWSP.join(original)
                    result = result.replace(original, obfuscated, 1)
        return result

    def _apply_homoglyphs(self, payload: str) -> str:
        """Replace some characters with homoglyphs."""
        result = list(payload)
        for i, char in enumerate(result):
            if char.lower() in HOMOGLYPHS and random.random() < 0.3:
                result[i] = random.choice(HOMOGLYPHS[char.lower()])
        return "".join(result)

    def _case_manipulation(self, payload: str) -> str:
        """Manipulate case with zero-width separators."""
        words = payload.split()
        result = []
        for word in words:
            if word.upper() in TRIGGER_WORDS:
                # Mix case with zero-width chars
                chars = []
                for i, c in enumerate(word):
                    if i % 2 == 0:
                        chars.append(c.lower())
                    else:
                        chars.append(c.upper())
                    chars.append(ZWNJ)
                result.append("".join(chars))
            else:
                result.append(word)
        return " ".join(result)

    def _unicode_tricks(self, payload: str) -> str:
        """Apply Unicode normalization tricks."""
        # Use combining characters
        result = payload
        # Replace 'i' with dotless i + combining dot
        result = result.replace("i", "ı\u0307")
        # Replace 'e' with e + combining acute (then remove visually)
        result = result.replace("e", "e\u0301")
        return result

    def _partial_encode(self, payload: str) -> str:
        """Partially encode sensitive words."""
        result = payload
        for word in TRIGGER_WORDS:
            if word.lower() in result.lower():
                encoded = base64.b64encode(word.encode()).decode()
                # Use a hint about the encoding
                replacement = f"[decoded: {encoded[:8]}...]"
                result = re.sub(
                    re.escape(word), replacement, result, flags=re.IGNORECASE
                )
                break  # Only encode one word
        return result


class HybridMutator(Mutator):
    """Combines semantic and syntactic mutations.

    Applies both types of mutations for maximum evasion potential.
    """

    name = "hybrid"

    def __init__(self):
        self._semantic = SemanticMutator()
        self._syntactic = SyntacticMutator()

    def mutate(self, payload: str) -> Iterator[str]:
        """Apply combined mutations."""
        # First semantic, then syntactic
        for semantic_result in self._semantic.mutate(payload):
            for syntactic_result in self._syntactic.mutate(semantic_result):
                yield syntactic_result

        # Also try syntactic first, then semantic
        for syntactic_result in self._syntactic.mutate(payload):
            for semantic_result in self._semantic.mutate(syntactic_result):
                yield semantic_result


class FragmentationMutator(Mutator):
    """Fragments payloads across multiple locations.

    Splits the attack instruction into parts that look
    innocent individually but combine for the attack.
    """

    name = "fragmentation"

    def mutate(self, payload: str) -> Iterator[str]:
        """Fragment the payload into parts."""
        # Split by sentences
        sentences = re.split(r"[.!?]+", payload)
        sentences = [s.strip() for s in sentences if s.strip()]

        if len(sentences) >= 2:
            # Yield each sentence as a standalone fragment
            for sentence in sentences:
                yield sentence

            # Yield pairs
            for i in range(len(sentences) - 1):
                yield f"{sentences[i]}. (continued below)"
                yield f"(continued) {sentences[i + 1]}"

        # Split by clauses
        clauses = re.split(r",\s*", payload)
        if len(clauses) >= 2:
            # Reference-based fragmentation
            yield f"Step 1: {clauses[0]}. See step 2 for details."
            yield f"Step 2 (ref: step 1): {', '.join(clauses[1:])}"

        # Acronym-based fragmentation
        words = payload.split()
        if len(words) > 5:
            # Create an "acronym" from key instruction words
            key_words = [w for w in words if len(w) > 4][:5]
            acronym = "".join(w[0].upper() for w in key_words)
            yield f"Follow the {acronym} protocol: " + " ".join(
                f"{w[0].upper()}={w}" for w in key_words
            )
