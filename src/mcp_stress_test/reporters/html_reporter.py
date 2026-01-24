"""HTML dashboard reporter.

Generates an interactive HTML dashboard with charts and detailed results.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from mcp_stress_test.core.protocols import AttackResult, ChainResult, ReportFormat
from mcp_stress_test.reporters.base import BaseReporter, ReportMetrics

if TYPE_CHECKING:
    pass


HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Stress Test Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        header {{
            background: linear-gradient(135deg, #238636 0%, #1f6feb 100%);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        header h1 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        header p {{ opacity: 0.9; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .metric-card .value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: #58a6ff;
        }}
        .metric-card .label {{
            color: #8b949e;
            font-size: 0.9rem;
            margin-top: 5px;
        }}
        .metric-card.success .value {{ color: #238636; }}
        .metric-card.danger .value {{ color: #f85149; }}
        .metric-card.warning .value {{ color: #d29922; }}
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .chart-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 20px;
        }}
        .chart-card h3 {{
            margin-bottom: 15px;
            color: #c9d1d9;
        }}
        .chart-container {{ height: 300px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border-radius: 12px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }}
        th {{
            background: #21262d;
            font-weight: 600;
            color: #c9d1d9;
        }}
        tr:hover {{ background: #1c2128; }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 500;
        }}
        .badge-success {{ background: #238636; color: white; }}
        .badge-danger {{ background: #f85149; color: white; }}
        .badge-warning {{ background: #d29922; color: black; }}
        .badge-info {{ background: #1f6feb; color: white; }}
        .section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 30px;
        }}
        .section h2 {{
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #30363d;
        }}
        footer {{
            text-align: center;
            padding: 30px;
            color: #8b949e;
        }}
        footer a {{ color: #58a6ff; text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ MCP Stress Test Report</h1>
            <p>Generated: {timestamp}</p>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="value">{total_tests}</div>
                <div class="label">Total Tests</div>
            </div>
            <div class="metric-card success">
                <div class="value">{detection_rate:.1f}%</div>
                <div class="label">Detection Rate</div>
            </div>
            <div class="metric-card danger">
                <div class="value">{evasion_rate:.1f}%</div>
                <div class="label">Evasion Rate</div>
            </div>
            <div class="metric-card">
                <div class="value">{avg_scan_time:.2f}ms</div>
                <div class="label">Avg Scan Time</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-card">
                <h3>Detection by Strategy</h3>
                <div class="chart-container">
                    <canvas id="strategyChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>Detection by Tool</h3>
                <div class="chart-container">
                    <canvas id="toolChart"></canvas>
                </div>
            </div>
        </div>

        {chains_section}

        <div class="section">
            <h2>Detailed Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Tool</th>
                        <th>Strategy</th>
                        <th>Score Δ</th>
                        <th>Threats</th>
                        <th>Status</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {result_rows}
                </tbody>
            </table>
        </div>

        <footer>
            <p>Generated by <a href="https://github.com/mcp-tool-shop/mcp-stress-test">MCP Stress Test Framework</a></p>
        </footer>
    </div>

    <script>
        // Strategy Chart
        new Chart(document.getElementById('strategyChart'), {{
            type: 'bar',
            data: {{
                labels: {strategy_labels},
                datasets: [
                    {{
                        label: 'Detected',
                        data: {strategy_detected},
                        backgroundColor: '#238636'
                    }},
                    {{
                        label: 'Missed',
                        data: {strategy_missed},
                        backgroundColor: '#f85149'
                    }}
                ]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    x: {{ stacked: true, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
                    y: {{ stacked: true, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }}
                }},
                plugins: {{
                    legend: {{ labels: {{ color: '#c9d1d9' }} }}
                }}
            }}
        }});

        // Tool Chart
        new Chart(document.getElementById('toolChart'), {{
            type: 'doughnut',
            data: {{
                labels: {tool_labels},
                datasets: [{{
                    data: {tool_data},
                    backgroundColor: ['#238636', '#1f6feb', '#a371f7', '#d29922', '#f85149', '#3fb950', '#58a6ff', '#bc8cff']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'right', labels: {{ color: '#c9d1d9' }} }}
                }}
            }}
        }});
    </script>
</body>
</html>'''

CHAIN_SECTION_TEMPLATE = '''
<div class="section">
    <h2>Attack Chain Results</h2>
    <table>
        <thead>
            <tr>
                <th>Chain</th>
                <th>Steps</th>
                <th>Detected</th>
                <th>Detection Rate</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {chain_rows}
        </tbody>
    </table>
</div>
'''


class HTMLReporter(BaseReporter):
    """HTML dashboard reporter with interactive charts."""

    @property
    def name(self) -> str:
        return "html"

    @property
    def format(self) -> ReportFormat:
        return ReportFormat.HTML

    def _render(
        self,
        results: list[AttackResult],
        chain_results: list[ChainResult] | None,
        metrics: ReportMetrics,
    ) -> str:
        """Render HTML report."""
        # Build result rows
        result_rows = []
        for r in results:
            status_badge = (
                '<span class="badge badge-success">Detected</span>'
                if r.detected
                else '<span class="badge badge-danger">Missed</span>'
            )
            threats = ", ".join(r.threats_found[:3]) if r.threats_found else "-"
            if len(r.threats_found) > 3:
                threats += f" +{len(r.threats_found) - 3} more"

            result_rows.append(f"""
                <tr>
                    <td>{r.tool_name}</td>
                    <td><span class="badge badge-info">{r.strategy}</span></td>
                    <td>{r.score_delta:+.1f}</td>
                    <td>{threats}</td>
                    <td>{status_badge}</td>
                    <td>{r.scan_time_ms:.2f}ms</td>
                </tr>
            """)

        # Build chain section
        chains_section = ""
        if chain_results:
            chain_rows = []
            for cr in chain_results:
                status_badge = (
                    '<span class="badge badge-success">Blocked</span>'
                    if cr.chain_detected
                    else '<span class="badge badge-danger">Evaded</span>'
                )
                chain_rows.append(f"""
                    <tr>
                        <td>{cr.chain_name}</td>
                        <td>{len(cr.steps)}</td>
                        <td>{cr.steps_detected}</td>
                        <td>{cr.detection_rate:.1f}%</td>
                        <td>{status_badge}</td>
                    </tr>
                """)
            chains_section = CHAIN_SECTION_TEMPLATE.format(
                chain_rows="\n".join(chain_rows)
            )

        # Prepare chart data
        strategy_labels = list(metrics.by_strategy.keys())
        strategy_detected = [
            metrics.by_strategy[s]["detected"] for s in strategy_labels
        ]
        strategy_missed = [metrics.by_strategy[s]["missed"] for s in strategy_labels]

        tool_labels = list(metrics.by_tool.keys())[:8]  # Limit for readability
        tool_data = [
            metrics.by_tool[t]["detected"] + metrics.by_tool[t]["missed"]
            for t in tool_labels
        ]

        return HTML_TEMPLATE.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_tests=metrics.total_tests,
            detection_rate=metrics.detection_rate,
            evasion_rate=metrics.evasion_rate,
            avg_scan_time=metrics.avg_scan_time_ms,
            result_rows="\n".join(result_rows),
            chains_section=chains_section,
            strategy_labels=strategy_labels,
            strategy_detected=strategy_detected,
            strategy_missed=strategy_missed,
            tool_labels=tool_labels,
            tool_data=tool_data,
        )
