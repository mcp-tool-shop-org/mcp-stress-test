# P2 — Add performance regression testing guidance

**Labels:** `performance`, `P2`

## Summary

Users need guidance on using MCP Stress Test for CI-based regression detection.

## Problem

Without regression guidance:
- Baselines are not established
- Thresholds are arbitrary
- CI integration is unclear

## Acceptance Criteria

- [ ] Baseline comparison method documented
- [ ] Threshold definitions explained
- [ ] CI integration example provided
- [ ] Failure criteria clarified

## Suggested Content

### Establishing Baselines

```bash
# Run baseline test
mcp-stress-test run --scenario baseline.json --output baseline-results.json

# Compare future runs
mcp-stress-test compare baseline-results.json current-results.json
```

### Threshold Definitions

```json
{
  "thresholds": {
    "p99_latency_ms": 500,
    "error_rate": 0.01,
    "min_rps": 100
  }
}
```

### CI Integration (GitHub Actions)

```yaml
- name: Run performance test
  run: |
    mcp-stress-test run \
      --scenario ci-test.json \
      --thresholds thresholds.json \
      --fail-on-threshold
```

### Failure Criteria

The test fails if:
- Any threshold is exceeded
- Error rate exceeds limit
- p99 latency regresses by >20%

## Location

`docs/regression-testing.md`
