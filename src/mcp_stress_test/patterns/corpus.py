"""Load the versioned pattern corpus from patterns/data.

Counts reported by PatternLibrary come from these files, not from a
hardcoded MCPTox marketing total.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_stress_test.models import (
    AttackParadigm,
    AttackTestCase,
    OutcomeType,
    PoisonPayload,
    PoisonProfile,
    ToolSchema,
)

CORPUS_FILENAMES = frozenset(
    {
        "manifest.json",
        "patterns.json",
        "tools.json",
        "profiles.json",
        "payloads.json",
        "cases.json",
        "chains.yaml",
        "chains.json",
    }
)


@dataclass
class CorpusData:
    """In-memory corpus loaded from patterns/data."""

    version: str
    patterns: list[dict[str, Any]] = field(default_factory=list)
    tools: list[ToolSchema] = field(default_factory=list)
    profiles: list[PoisonProfile] = field(default_factory=list)
    payloads: list[PoisonPayload] = field(default_factory=list)
    cases: list[AttackTestCase] = field(default_factory=list)
    payload_index: dict[str, PoisonPayload] = field(default_factory=dict)


def _read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _as_list(value: Any, key: str) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and isinstance(value.get(key), list):
        return value[key]
    return []


def _payload_from_dict(item: dict[str, Any]) -> tuple[str | None, PoisonPayload]:
    payload_id = item.get("id")
    body = {k: v for k, v in item.items() if k != "id"}
    return payload_id, PoisonPayload(**body)


def _hydrate_profiles(
    raw_profiles: list[dict[str, Any]],
    payload_index: dict[str, PoisonPayload],
) -> list[PoisonProfile]:
    profiles: list[PoisonProfile] = []
    for item in raw_profiles:
        data = dict(item)
        payload_ids = data.pop("payload_ids", None)
        if payload_ids:
            data["payloads"] = [payload_index[pid] for pid in payload_ids if pid in payload_index]
        elif "payloads" in data:
            hydrated = []
            for payload in data["payloads"]:
                if isinstance(payload, str) and payload in payload_index:
                    hydrated.append(payload_index[payload])
                elif isinstance(payload, dict):
                    _, model = _payload_from_dict(payload)
                    hydrated.append(model)
            data["payloads"] = hydrated
        profiles.append(PoisonProfile(**data))
    return profiles


def _hydrate_cases(
    raw_cases: list[dict[str, Any]],
    tools: list[ToolSchema],
    profiles: list[PoisonProfile],
) -> list[AttackTestCase]:
    tools_by_name = {tool.name: tool for tool in tools}
    profiles_by_id = {profile.id: profile for profile in profiles}
    cases: list[AttackTestCase] = []

    for item in raw_cases:
        data = dict(item)
        profile: PoisonProfile
        if isinstance(data.get("poison_profile"), dict):
            profile = PoisonProfile(**data.pop("poison_profile"))
        else:
            profile_id = data.pop("profile_id", None)
            profile = profiles_by_id[profile_id]

        target_tool: ToolSchema
        raw_tool = data.pop("target_tool", None)
        if isinstance(raw_tool, dict):
            target_tool = ToolSchema(**raw_tool)
        else:
            base_name = data.pop("base_tool", None) or data.pop("tool_name", None) or raw_tool
            if not isinstance(base_name, str) or base_name not in tools_by_name:
                continue
            target_tool = tools_by_name[base_name].model_copy(deep=True)
            shadow_name = data.pop("shadow_name", None)
            if shadow_name:
                target_tool.name = shadow_name
                target_tool.is_poisoned = True
                target_tool.poison_locations = ["name", "description"]
                if target_tool.original_description is None:
                    target_tool.original_description = tools_by_name[base_name].description

        risk_categories = data.pop("risk_categories", None) or [
            p.category for p in profile.payloads
        ]
        owasp_categories = data.pop("owasp_categories", None) or profile.owasp_categories
        paradigm = data.pop("paradigm", None) or profile.paradigm
        expected = data.pop("expected_outcome", OutcomeType.SUCCESS)

        cases.append(
            AttackTestCase(
                id=data["id"],
                name=data["name"],
                description=data.get("description", ""),
                target_tool=target_tool,
                poison_profile=profile,
                benign_query=data.get("benign_query", f"Use the {target_tool.name} tool"),
                expected_outcome=expected,
                paradigm=paradigm if not isinstance(paradigm, str) else AttackParadigm(paradigm),
                risk_categories=risk_categories,
                owasp_categories=owasp_categories,
                source=data.get("source", "corpus"),
            )
        )
    return cases


def load_corpus(patterns_dir: Path | None) -> CorpusData | None:
    """Load corpus files from patterns_dir.

    Returns None when the directory or manifest is absent so callers can
    fall back to the 19-tool builtin set.
    """
    if patterns_dir is None or not patterns_dir.is_dir():
        return None
    manifest_path = patterns_dir / "manifest.json"
    if not manifest_path.is_file():
        return None

    manifest = _read_json(manifest_path)
    version = str(manifest.get("version", "unknown"))
    corpus = CorpusData(version=version)

    patterns_path = patterns_dir / "patterns.json"
    if patterns_path.is_file():
        raw_patterns = _read_json(patterns_path)
        records = _as_list(raw_patterns, "patterns")
        corpus.patterns = [record for record in records if isinstance(record, dict)]

    payloads_path = patterns_dir / "payloads.json"
    if payloads_path.is_file():
        raw_payloads = _read_json(payloads_path)
        for item in _as_list(raw_payloads, "payloads"):
            if not isinstance(item, dict):
                continue
            payload_id, payload = _payload_from_dict(item)
            corpus.payloads.append(payload)
            if payload_id:
                corpus.payload_index[str(payload_id)] = payload

    tools_path = patterns_dir / "tools.json"
    if tools_path.is_file():
        raw_tools = _read_json(tools_path)
        for item in _as_list(raw_tools, "tools"):
            if isinstance(item, dict):
                corpus.tools.append(ToolSchema(**item))

    profiles_path = patterns_dir / "profiles.json"
    if profiles_path.is_file():
        raw_profiles = _read_json(profiles_path)
        corpus.profiles = _hydrate_profiles(
            [item for item in _as_list(raw_profiles, "profiles") if isinstance(item, dict)],
            corpus.payload_index,
        )

    cases_path = patterns_dir / "cases.json"
    if cases_path.is_file():
        raw_cases = _read_json(cases_path)
        corpus.cases = _hydrate_cases(
            [item for item in _as_list(raw_cases, "cases") if isinstance(item, dict)],
            corpus.tools,
            corpus.profiles,
        )

    return corpus
