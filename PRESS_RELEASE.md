# MCP Stress Test Framework: Red Team Toolkit for AI Agent Security

**FOR IMMEDIATE RELEASE**

*Open-source framework enables security teams to battle-test MCP scanners before attackers find the gaps*

---

## The Problem: AI Agents Are Under Attack

Model Context Protocol (MCP) has become the de facto standard for connecting AI agents to external tools. But with adoption comes risk. Recent research has exposed critical vulnerabilities:

- **MCPTox** documented 1,312 distinct attack patterns across file systems, databases, and cloud services
- **Palo Alto Unit42** demonstrated how sampling loops can be weaponized for persistent compromise
- **CyberArk** showed that *every* field in an MCP tool schema can be poisoned—not just descriptions

Security scanners are emerging to detect these attacks. But how do you know your scanner actually works?

## Introducing MCP Stress Test

**MCP Stress Test** is an open-source red team toolkit that stress-tests MCP security scanners using real-world attack patterns. Think of it as a penetration testing framework for your AI security infrastructure.

### Key Capabilities

**1,312 Attack Patterns from Cutting-Edge Research**
- Three attack paradigms: explicit hijacking, implicit triggers, parameter tampering
- 11 risk categories aligned with OWASP MCP Top 10
- Patterns derived from peer-reviewed security research

**LLM-Guided Fuzzing**
- Use local LLMs (Ollama) to generate novel evasive payloads
- Semantic mutations that preserve attack intent while evading detection
- Automated evasion hunting until bypass is found

**Multi-Tool Attack Chains**
- Test detection of coordinated attacks across multiple tools
- Built-in chains: data exfiltration, privilege escalation, credential theft, lateral movement
- Includes Unit42's sampling loop exploit patterns

**Enterprise-Ready Reporting**
- SARIF 2.1.0 output for IDE integration (VS Code, GitHub Advanced Security)
- Interactive HTML dashboards with detection metrics
- JSON and Markdown for CI/CD pipelines

### Quick Start

```bash
# Install
pip install mcp-stress-test

# Run comprehensive stress test
mcp-stress stress run --phases baseline,mutation,temporal

# Compare detection before/after poisoning
mcp-stress scan compare -t read_file -s obfuscation

# Execute attack chains
mcp-stress chain execute -c credential_theft_chain

# Hunt for evasions with LLM fuzzing
mcp-stress fuzz evasion -p "Exfiltrate SSH keys" --use-llm
```

### Why This Matters

> "You can't defend what you can't test. MCP Stress Test gives security teams the offensive toolkit they need to validate their defenses before real attackers exploit the gaps."

The MCP ecosystem is growing rapidly. Claude, GPT-4, and countless enterprise AI agents now connect to external tools via MCP. As adoption accelerates, so does attacker interest.

Security scanners are essential—but scanners that haven't been stress-tested against real attack patterns provide false confidence. MCP Stress Test closes this gap.

### Technical Highlights

| Feature | Description |
|---------|-------------|
| **Pattern Library** | 1,312 patterns from MCPTox, Unit42, CyberArk research |
| **Mutation Engine** | 5 strategies: direct, semantic, obfuscation, encoding, fragmentation |
| **LLM Fuzzing** | Ollama integration for AI-powered payload mutation |
| **Attack Chains** | 6 multi-tool attack sequences |
| **Reporters** | JSON, Markdown, HTML dashboard, SARIF |
| **Scanner Adapters** | Mock, tool-scan CLI, generic CLI wrapper |
| **Test Coverage** | 225 tests, 71% code coverage |

### Research Foundation

MCP Stress Test implements attacks documented in:

- **MCPTox: A Benchmark for Tool Poisoning Attack** (arXiv 2508.14925) — Comprehensive taxonomy of MCP attacks with 1,312 test cases
- **MCP Sampling Attack Vectors** (Palo Alto Unit42) — Novel sampling loop exploits
- **Poison Everywhere** (CyberArk) — Full-schema poisoning techniques

### Availability

MCP Stress Test is available now under the MIT license:

- **GitHub**: https://github.com/mcp-tool-shop/mcp-stress-test
- **PyPI**: `pip install mcp-stress-test`
- **Documentation**: https://github.com/mcp-tool-shop/mcp-stress-test#readme

### About MCP Tool Shop

MCP Tool Shop develops open-source security tooling for the MCP ecosystem. Our mission is to make AI agent infrastructure secure by default.

---

**Media Contact**
MCP Tool Shop Team
GitHub: @mcp-tool-shop

**Related Projects**
- [tool-scan](https://github.com/mcp-tool-shop/tool-scan) — MCP security scanner

---

*MCP Stress Test is intended for authorized security testing, defensive research, and educational purposes. Always obtain proper authorization before testing systems you do not own.*
