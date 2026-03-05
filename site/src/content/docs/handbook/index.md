---
title: MCP Stress Test Handbook
description: Complete guide to stress-testing MCP security scanners with adversarial attack patterns.
---

Welcome to the **MCP Stress Test** handbook. This guide covers everything you need to test whether your MCP security scanner can detect sophisticated attacks.

## Contents

- [Getting Started](./getting-started/) — Installation, first run, and basic usage
- [Reference](./reference/) — CLI commands, mutation strategies, architecture, and security model

## What is MCP Stress Test?

MCP Stress Test is an offensive security framework that generates adversarial MCP tool configurations based on cutting-edge 2025 research. It fires **1,312 attack patterns** from three paradigms — explicit hijacking, implicit hijacking, and parameter tampering — and measures your scanner's detection rate.

### Use cases

- Test scanner detection rates against known attack patterns
- Find evasions using LLM-guided fuzzing
- Benchmark scanner performance across attack paradigms
- Execute multi-tool attack chains that simulate real-world coordinated attacks
- Generate SARIF reports for IDE integration

### Research sources

The attack patterns are drawn from peer-reviewed and industry research:

- **[MCPTox](https://arxiv.org/html/2508.14925v1)** — 1,312 patterns across 3 paradigms (the largest public MCP poisoning dataset)
- **[Palo Alto Unit42](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)** — Sampling loop exploits and tool-shadowing attacks
- **[CyberArk](https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe)** — Full-schema poisoning research
