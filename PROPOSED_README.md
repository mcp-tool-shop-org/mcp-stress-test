# MCP Stress Test

Load-testing and stress-testing utilities for MCP servers and tool ecosystems.

MCP Stress Test helps you answer one critical question:

**"Will my MCP stack still behave correctly under real load?"**

---

## What problem does this solve?

MCP systems often fail under pressure:

- concurrent tool calls overload servers
- latency spikes cascade across agents
- memory usage grows unpredictably
- error handling behaves differently at scale
- regressions appear only in production

MCP Stress Test exposes these failures early.

---

## Core capabilities

- Concurrent MCP client simulation
- Tool-call load generation
- Scenario-based stress profiles
- Latency and throughput measurement
- Error-rate tracking
- Deterministic replay of load scenarios

This tool does not test correctness of outputs — it tests **system behavior under stress**.

---

## Quick start

```bash
pip install mcp-stress-test

mcp-stress-test run \
  --server http://localhost:3333 \
  --scenario basic.json \
  --clients 50
```

(Commands illustrative — see repo for exact CLI.)

---

## Example scenarios

- Burst tool invocation
- Sustained concurrency
- Agent swarm simulation
- Long-running memory pressure
- Tool timeout recovery

---

## When to use MCP Stress Test

- Before deploying MCP servers
- When adding new tools
- Before scaling agent concurrency
- During performance regression testing
- In CI performance gates

## When not to use it

- Unit testing
- Functional correctness testing
- Single-request debugging

---

## Design goals

- **Reproducible load**
- **Deterministic scenarios**
- **Clear metrics output**
- **Minimal environment assumptions**
- **CI-friendly execution**

---

## Project status

**Beta**

Core load engine is stable.
Scenario formats may evolve.

---

## Ecosystem

Part of the [MCP Tool Shop](https://github.com/mcp-tool-shop) ecosystem.

Works especially well with:

- **Tool Scan** (capability discovery)
- **Tool Compass** (tool selection)
- **Dev Brain** (orchestration)
- **Aspire AI** (evaluation loops)

---

## License

MIT
