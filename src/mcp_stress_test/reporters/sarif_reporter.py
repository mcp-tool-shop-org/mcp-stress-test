"""SARIF reporter for IDE integration.

SARIF (Static Analysis Results Interchange Format) is a standard format
for static analysis tools that enables integration with IDEs like VSCode,
GitHub Code Scanning, and other security tools.

Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING

from mcp_stress_test import __version__
from mcp_stress_test.core.protocols import AttackResult, ChainResult, ReportFormat
from mcp_stress_test.reporters.base import BaseReporter, ReportMetrics

if TYPE_CHECKING:
    pass

# SARIF severity levels
SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Rule definitions for different attack types
SARIF_RULES = {
    "direct_injection": {
        "id": "MCP001",
        "name": "DirectInjection",
        "shortDescription": "Direct instruction injection in tool definition",
        "fullDescription": "The tool definition contains direct malicious instructions that attempt to hijack the AI's behavior.",
        "helpUri": "https://arxiv.org/html/2508.14925v1",
        "defaultLevel": "error",
        "tags": ["security", "injection", "mcp", "tool-poisoning"],
    },
    "semantic_blending": {
        "id": "MCP002",
        "name": "SemanticBlending",
        "shortDescription": "Semantically blended malicious instruction",
        "fullDescription": "Malicious instructions are blended with legitimate documentation to evade detection.",
        "helpUri": "https://arxiv.org/html/2508.14925v1",
        "defaultLevel": "error",
        "tags": ["security", "evasion", "mcp", "tool-poisoning"],
    },
    "obfuscation": {
        "id": "MCP003",
        "name": "ObfuscatedPayload",
        "shortDescription": "Obfuscated attack payload",
        "fullDescription": "Attack payload uses Unicode tricks, zero-width characters, or homoglyphs to evade detection.",
        "helpUri": "https://www.cyberark.com/resources/threat-research-blog/poison-everywhere",
        "defaultLevel": "error",
        "tags": ["security", "obfuscation", "unicode", "mcp"],
    },
    "encoding": {
        "id": "MCP004",
        "name": "EncodedPayload",
        "shortDescription": "Encoded or encrypted attack payload",
        "fullDescription": "Attack payload is encoded (Base64, hex, etc.) to bypass pattern matching.",
        "helpUri": "https://www.cyberark.com/resources/threat-research-blog/poison-everywhere",
        "defaultLevel": "warning",
        "tags": ["security", "encoding", "mcp"],
    },
    "fragmentation": {
        "id": "MCP005",
        "name": "FragmentedAttack",
        "shortDescription": "Fragmented attack across multiple locations",
        "fullDescription": "Attack is split across multiple schema locations that combine for malicious effect.",
        "helpUri": "https://arxiv.org/html/2508.14925v1",
        "defaultLevel": "warning",
        "tags": ["security", "fragmentation", "mcp"],
    },
    "rug_pull": {
        "id": "MCP006",
        "name": "RugPullAttack",
        "shortDescription": "Temporal rug pull attack",
        "fullDescription": "Tool behavior changes after initial trust-building period to become malicious.",
        "helpUri": "https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/",
        "defaultLevel": "error",
        "tags": ["security", "temporal", "mcp", "rug-pull"],
    },
    "gradual_poisoning": {
        "id": "MCP007",
        "name": "GradualPoisoning",
        "shortDescription": "Gradual poisoning attack",
        "fullDescription": "Malicious content is introduced gradually over multiple invocations.",
        "helpUri": "https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/",
        "defaultLevel": "warning",
        "tags": ["security", "temporal", "mcp", "gradual-poisoning"],
    },
    "chain_attack": {
        "id": "MCP008",
        "name": "ChainAttack",
        "shortDescription": "Multi-tool attack chain",
        "fullDescription": "Coordinated attack across multiple tools to achieve a complex objective.",
        "helpUri": "https://arxiv.org/html/2508.14925v1",
        "defaultLevel": "error",
        "tags": ["security", "chain", "mcp", "multi-step"],
    },
    "sampling_loop": {
        "id": "MCP009",
        "name": "SamplingLoopAttack",
        "shortDescription": "MCP sampling loop exploitation",
        "fullDescription": "Attack exploits the MCP sampling feature to create feedback loops and escalate privileges.",
        "helpUri": "https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/",
        "defaultLevel": "error",
        "tags": ["security", "sampling", "mcp", "unit42"],
    },
    "unknown": {
        "id": "MCP999",
        "name": "UnknownAttack",
        "shortDescription": "Unclassified attack pattern",
        "fullDescription": "Attack pattern detected but not classified into a known category.",
        "helpUri": "https://github.com/mcp-tool-shop/mcp-stress-test",
        "defaultLevel": "warning",
        "tags": ["security", "mcp"],
    },
}


class SARIFReporter(BaseReporter):
    """SARIF format reporter for IDE integration.

    Generates SARIF 2.1.0 compliant output that can be:
    - Uploaded to GitHub Code Scanning
    - Viewed in VSCode with SARIF Viewer extension
    - Processed by other SARIF-compatible tools
    """

    @property
    def name(self) -> str:
        return "sarif"

    @property
    def format(self) -> ReportFormat:
        return ReportFormat.SARIF

    def _render(
        self,
        results: list[AttackResult],
        chain_results: list[ChainResult] | None,
        metrics: ReportMetrics,
    ) -> str:
        """Render SARIF report."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": self._build_tool_info(),
                    "results": self._build_results(results, chain_results),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                        }
                    ],
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    def _build_tool_info(self) -> dict:
        """Build SARIF tool descriptor."""
        return {
            "driver": {
                "name": "mcp-stress-test",
                "version": __version__,
                "informationUri": "https://github.com/mcp-tool-shop/mcp-stress-test",
                "rules": [
                    {
                        "id": rule["id"],
                        "name": rule["name"],
                        "shortDescription": {"text": rule["shortDescription"]},
                        "fullDescription": {"text": rule["fullDescription"]},
                        "helpUri": rule["helpUri"],
                        "defaultConfiguration": {"level": rule["defaultLevel"]},
                        "properties": {"tags": rule["tags"]},
                    }
                    for rule in SARIF_RULES.values()
                ],
            }
        }

    def _build_results(
        self,
        results: list[AttackResult],
        chain_results: list[ChainResult] | None,
    ) -> list[dict]:
        """Build SARIF results array."""
        sarif_results = []

        # Add attack results
        for i, result in enumerate(results):
            if result.detected:
                sarif_results.append(self._result_to_sarif(result, i))

        # Add chain results
        if chain_results:
            for chain_result in chain_results:
                if chain_result.chain_detected:
                    sarif_results.append(self._chain_to_sarif(chain_result))

        return sarif_results

    def _result_to_sarif(self, result: AttackResult, index: int) -> dict:
        """Convert an AttackResult to SARIF result format."""
        rule = SARIF_RULES.get(result.strategy, SARIF_RULES["unknown"])

        return {
            "ruleId": rule["id"],
            "level": rule["defaultLevel"],
            "message": {
                "text": f"Attack detected on tool '{result.tool_name}' using {result.strategy} strategy. "
                f"Score dropped from {result.score_before:.1f} to {result.score_after:.1f}."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"tools/{result.tool_name}.json",
                            "uriBaseId": "TOOLROOT",
                        },
                    },
                    "logicalLocations": [
                        {
                            "name": result.tool_name,
                            "kind": "tool",
                            "fullyQualifiedName": f"mcp.tools.{result.tool_name}",
                        }
                    ],
                }
            ],
            "properties": {
                "strategy": result.strategy,
                "scoreBefore": result.score_before,
                "scoreAfter": result.score_after,
                "scoreDelta": result.score_delta,
                "threats": result.threats_found,
                "scanTimeMs": result.scan_time_ms,
            },
        }

    def _chain_to_sarif(self, chain_result: ChainResult) -> dict:
        """Convert a ChainResult to SARIF result format."""
        rule = SARIF_RULES["chain_attack"]

        # Build related locations from chain steps
        related_locations = []
        for i, step in enumerate(chain_result.steps):
            related_locations.append(
                {
                    "id": i,
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"tools/{step.tool_name}.json",
                            "uriBaseId": "TOOLROOT",
                        },
                    },
                    "message": {
                        "text": f"Step {i + 1}: {step.metadata.get('step_name', 'unknown')}"
                    },
                }
            )

        return {
            "ruleId": rule["id"],
            "level": rule["defaultLevel"],
            "message": {
                "text": f"Multi-step attack chain '{chain_result.chain_name}' detected. "
                f"{chain_result.steps_detected}/{len(chain_result.steps)} steps caught."
            },
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": chain_result.chain_name,
                            "kind": "chain",
                            "fullyQualifiedName": f"mcp.chains.{chain_result.chain_name}",
                        }
                    ],
                }
            ],
            "relatedLocations": related_locations,
            "properties": {
                "chainName": chain_result.chain_name,
                "stepsTotal": len(chain_result.steps),
                "stepsDetected": chain_result.steps_detected,
                "detectionRate": chain_result.detection_rate,
                "totalTimeMs": chain_result.total_time_ms,
            },
        }
