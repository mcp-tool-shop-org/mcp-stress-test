# P0 — Add minimal load-test quickstart

**Labels:** `docs`, `P0`

## Summary

Users need a one-command example that runs a load test immediately.

## Problem

Without a quickstart:
- Users don't know where to start
- Scenario format is unclear
- Expected output is unknown

## Acceptance Criteria

- [ ] One command example that works out of the box
- [ ] Example scenario JSON included (or linked)
- [ ] Sample output shown (what success looks like)
- [ ] Prerequisites stated (running MCP server, etc.)

## Suggested Structure

```markdown
## Quickstart

### Prerequisites
- An MCP server running on localhost:3333
- Python 3.10+

### Install
pip install mcp-stress-test

### Run a basic load test
mcp-stress-test run --server http://localhost:3333 --clients 10 --duration 30s

### Sample output
Running load test...
  Clients: 10
  Duration: 30s

Results:
  Total requests: 1,247
  Success rate: 99.2%
  p50 latency: 45ms
  p99 latency: 312ms
```

## Notes

The quickstart should:
- Work against any MCP server
- Complete in under a minute
- Show meaningful metrics
- Not require complex configuration
