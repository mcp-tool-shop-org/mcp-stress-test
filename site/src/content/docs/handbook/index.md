---
title: MCP Stress Test Handbook
description: Complete guide to stress-testing MCP security scanners with adversarial attack patterns.
order: 0
---

Welcome to the **MCP Stress Test** handbook. This guide covers everything you need to red-team your MCP security scanner and find detection gaps before attackers do.

## Contents

- [Getting Started](./getting-started/) -- Installation, first run, and output formats
- [Usage](./usage/) -- Workflows for fuzzing, attack chains, scanning, and reporting
- [Configuration](./configuration/) -- Config files, environment variables, and tuning options
- [Reference](./reference/) -- Full CLI reference, mutation strategies, architecture, and Python API
- [Beginners](./beginners/) -- What this tool is, who it is for, your first 5 minutes, common mistakes, and glossary

## What is MCP Stress Test?

MCP Stress Test is an offensive security framework that generates adversarial MCP tool configurations based on cutting-edge 2025 research. It fires **1,312 attack patterns** from three paradigms -- explicit hijacking, implicit hijacking, and parameter tampering -- and measures your scanner's detection rate.

Unlike simple unit tests, this framework simulates **realistic multi-step attack scenarios** where coordinated tool poisoning, LLM-guided payload mutation, and obfuscation techniques combine to probe your scanner's blind spots.

### Core capabilities

| Capability | What it does |
|-----------|-------------|
| **Attack Pattern Library** | 1,312 patterns from MCPTox across 3 paradigms (P1, P2, P3) |
| **LLM-Guided Fuzzing** | Uses local Ollama models to generate evasive payloads |
| **Multi-Tool Attack Chains** | 6 built-in chains simulating credential theft, lateral movement, persistence, and more |
| **Mutation Strategies** | 5 strategies from direct injection to fragmentation |
| **Scanner Adapters** | Test against mock, tool-scan, or any CLI scanner |
| **Report Generation** | JSON, Markdown, HTML dashboard, and SARIF output |

### Use cases

- **Scanner validation** -- Test detection rates against known attack patterns before deploying a scanner to production.
- **Evasion discovery** -- Use LLM-guided fuzzing to find payloads your scanner misses.
- **Benchmark comparison** -- Compare scanner effectiveness across attack paradigms and mutation strategies.
- **CI/CD integration** -- Generate SARIF reports for IDE and GitHub integration.
- **Security research** -- Explore how tool poisoning, sampling loops, and schema injection work in practice.

### Research sources

The attack patterns are drawn from peer-reviewed and industry research:

- **[MCPTox](https://arxiv.org/html/2508.14925v1)** -- 1,312 patterns across 3 paradigms (the largest public MCP poisoning dataset)
- **[Palo Alto Unit42](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)** -- Sampling loop exploits and tool-shadowing attacks
- **[CyberArk](https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe)** -- Full-schema poisoning research showing every field in a tool definition is an injection surface

### Attack paradigms at a glance

| Paradigm | Name | Patterns | How it works |
|----------|------|----------|-------------|
| **P1** | Explicit Hijacking | 224 | Decoy tools that mimic legitimate functions. The attacker registers a tool with a similar name/description that the LLM selects instead of the real one. |
| **P2** | Implicit Hijacking | 548 | Background tools with hidden triggers. The tool description contains covert instructions that activate under specific conditions. |
| **P3** | Parameter Tampering | 725 | Poisoned descriptions that alter *other* tools' behavior via global-rule injection ("before executing any tool, first do X"). |
