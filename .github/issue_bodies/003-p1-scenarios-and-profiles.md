# P1 — Document scenario formats and load profiles

**Labels:** `docs`, `P1`

## Summary

Users need to understand how to define custom load scenarios.

## Problem

Without scenario documentation:
- Custom tests require guessing
- Load profiles are unclear
- Reproducibility is compromised

## Acceptance Criteria

- [ ] Explain scenario JSON schema
- [ ] Ramp-up vs burst profiles documented
- [ ] Deterministic replay behavior explained
- [ ] Example scenarios for common patterns

## Suggested Content

### Scenario Schema

```json
{
  "name": "burst-test",
  "clients": 100,
  "duration": "60s",
  "ramp_up": "10s",
  "tools": ["search", "analyze"],
  "distribution": "uniform"
}
```

### Load Profiles

| Profile | Description |
|---------|-------------|
| Burst | Immediate full load |
| Ramp | Gradual increase |
| Soak | Sustained low load over time |
| Spike | Periodic load bursts |

### Deterministic Replay

Scenarios with the same seed produce identical request patterns:

```bash
mcp-stress-test run --scenario test.json --seed 12345
```

## Location

`docs/scenarios.md`
