# P0 — Clarify MCP Stress Test positioning and scope

**Labels:** `docs`, `marketing`, `P0`

## Summary

The README needs to clearly distinguish load testing from correctness testing.

## Problem

Users may expect:
- Output validation
- Functional correctness checks
- Unit test capabilities

MCP Stress Test does none of these. It tests **behavior under load**.

## Acceptance Criteria

- [ ] README explains difference between load testing and correctness testing
- [ ] Clear definition of stress vs soak tests
- [ ] Example scenario visible on first screen
- [ ] "When not to use" section included

## Key Messages

1. **Tests behavior, not correctness** — latency, throughput, error rates
2. **Reproducible load** — same scenario = same load pattern
3. **Finds production failures early** — before real users do
4. **CI-friendly** — can run in pipelines

## Context

See `PROPOSED_README.md` in the safe overlay package for reference positioning.
