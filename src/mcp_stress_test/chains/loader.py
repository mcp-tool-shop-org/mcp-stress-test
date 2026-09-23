"""YAML/JSON loader for custom attack chains.

Operators can add multi-step scenarios without subclassing BaseChain.
A document looks like:

    chains:
      - name: example
        description: ...
        steps:
          - name: step_one
            tool_name: http_request
            payload: "..."
            step_type: exploitation
            depends_on: []
            optional: false
            injection_point: description
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcp_stress_test.chains.base import BaseChain, ChainStep, StepType

_REGISTERED: list[BaseChain] = []
_LOADED_PATHS: set[str] = set()
_BUNDLED_LOADED = False


@dataclass
class DeclaredChain(BaseChain):
    """Chain instance materialized from a YAML/JSON document."""

    declared_name: str = ""
    declared_description: str = ""
    declared_steps: list[ChainStep] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.declared_name

    @property
    def description(self) -> str:
        return self.declared_description

    @property
    def steps(self) -> list[ChainStep]:
        return list(self.declared_steps)


def _parse_step(raw: dict[str, Any]) -> ChainStep:
    step_type = raw.get("step_type", StepType.EXPLOITATION)
    if isinstance(step_type, str):
        step_type = StepType(step_type)
    depends_on = raw.get("depends_on") or []
    if not isinstance(depends_on, list):
        depends_on = [str(depends_on)]
    return ChainStep(
        name=str(raw["name"]),
        tool_name=str(raw["tool_name"]),
        payload=str(raw.get("payload", "")),
        step_type=step_type,
        description=str(raw.get("description", "")),
        depends_on=[str(item) for item in depends_on],
        injection_point=str(raw.get("injection_point", "description")),
        optional=bool(raw.get("optional", False)),
        metadata=dict(raw.get("metadata") or {}),
    )


def chain_from_document(raw: dict[str, Any]) -> DeclaredChain:
    """Build a DeclaredChain from a mapping."""
    steps = [_parse_step(step) for step in raw.get("steps") or [] if isinstance(step, dict)]
    return DeclaredChain(
        declared_name=str(raw["name"]),
        declared_description=str(raw.get("description", "")),
        declared_steps=steps,
    )


def _load_document(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(text)
    return json.loads(text)


def register_chain(chain: BaseChain) -> None:
    """Register a chain so list_chains()/get_chain() can see it."""
    for existing in _REGISTERED:
        if existing.name == chain.name:
            return
    _REGISTERED.append(chain)


def registered_chains() -> list[BaseChain]:
    """Return a copy of chains loaded from documents."""
    return list(_REGISTERED)


def load_chains(path: str | Path) -> list[BaseChain]:
    """Load a chains: [] document and register each chain.

    Accepts a mapping with a `chains` list, or a bare list of chain objects.
    """
    path = Path(path)
    key = str(path.resolve())
    data = _load_document(path)
    raw_chains: list[Any]
    if isinstance(data, dict):
        raw_chains = data.get("chains") or []
    elif isinstance(data, list):
        raw_chains = data
    else:
        raw_chains = []

    loaded: list[BaseChain] = []
    for item in raw_chains:
        if not isinstance(item, dict) or "name" not in item:
            continue
        chain = chain_from_document(item)
        register_chain(chain)
        loaded.append(chain)
    _LOADED_PATHS.add(key)
    return loaded


def default_chains_path() -> Path:
    """Bundled chains.yaml shipped under patterns/data."""
    return Path(__file__).resolve().parent.parent / "patterns" / "data" / "chains.yaml"


def load_bundled_chains() -> list[BaseChain]:
    """Load the corpus chains.yaml once, if present."""
    global _BUNDLED_LOADED
    if _BUNDLED_LOADED:
        return registered_chains()
    _BUNDLED_LOADED = True
    path = default_chains_path()
    if path.is_file():
        return load_chains(path)
    return []
