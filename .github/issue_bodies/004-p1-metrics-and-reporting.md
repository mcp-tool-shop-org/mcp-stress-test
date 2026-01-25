# P1 — Document metrics output and reports

**Labels:** `docs`, `P1`

## Summary

Users need to understand what metrics are collected and how to interpret them.

## Problem

Without metrics documentation:
- Results are hard to interpret
- Threshold setting is guesswork
- Comparisons are inconsistent

## Acceptance Criteria

- [ ] Latency percentiles explained (p50, p95, p99)
- [ ] Error-rate metrics defined
- [ ] Throughput definitions clarified
- [ ] Report formats documented (JSON, human-readable)

## Suggested Content

### Latency Metrics

| Metric | Description |
|--------|-------------|
| p50 | Median response time |
| p95 | 95th percentile (most users) |
| p99 | 99th percentile (worst case) |
| max | Maximum observed latency |

### Error Metrics

| Metric | Description |
|--------|-------------|
| error_rate | Failed requests / total requests |
| timeout_rate | Timed-out requests / total |
| error_types | Breakdown by error category |

### Throughput

| Metric | Description |
|--------|-------------|
| rps | Requests per second (sustained) |
| peak_rps | Maximum achieved RPS |
| total_requests | Total requests completed |

### Report Formats

```bash
# Human-readable (default)
mcp-stress-test run --scenario test.json

# JSON for CI
mcp-stress-test run --scenario test.json --format json > results.json
```

## Location

`docs/metrics.md`
