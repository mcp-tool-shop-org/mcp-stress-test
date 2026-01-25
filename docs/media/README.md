# Media Assets Guidance

## Recommended Visuals

Performance tools communicate best through charts and metrics visualizations.

### Priority assets to create:

1. **Load Profile Timeline**
   - X-axis: time
   - Y-axis: concurrent clients / requests per second
   - Show ramp-up, plateau, ramp-down phases

2. **Concurrency Ramp Diagram**
   - Illustrate how load increases over time
   - Mark key thresholds (saturation, failure)

3. **Latency Histogram**
   - Distribution of response times
   - Mark p50, p95, p99 percentiles
   - Show tail latency behavior

4. **Error Rate Over Time**
   - Errors vs load correlation
   - Identify breaking points

## Format Recommendations

| Format | Use Case |
|--------|----------|
| PNG | Charts with data |
| SVG | Diagrams and flows |
| Markdown tables | Quick metrics summaries |

## Chart Style

- Use consistent color coding (green=healthy, yellow=warning, red=failure)
- Always label axes
- Include percentile markers on latency charts
- Show baseline vs stressed comparison

## Why Charts

Screenshots of terminals don't convey:
- Load progression
- Statistical distributions
- Threshold violations

Charts communicate performance behavior clearly.
