"""HTML Reporter Module - Generate HTML format reports."""

from typing import Optional, List, Dict, Any, TYPE_CHECKING

from .base_reporter import BaseReporter, ReportData

if TYPE_CHECKING:
    from ..core.issue_processor import ProcessedResults, UniqueProblem


class HTMLReporter(BaseReporter):
    """Generate reports in HTML format."""

    def __init__(
        self,
        output_dir: Optional[str] = None,
        include_styles: bool = True,
        include_charts: bool = True,
    ):
        """Initialize the HTML reporter.

        Args:
            output_dir: Directory to save reports
            include_styles: Include embedded CSS styles
            include_charts: Include embedded charts
        """
        super().__init__(output_dir)
        self.include_styles = include_styles
        self.include_charts = include_charts

    @property
    def format(self) -> str:
        return "html"

    @property
    def extension(self) -> str:
        return "html"

    def generate(self, report_data: ReportData) -> bytes:
        """Generate HTML report.

        Args:
            report_data: Data to include in the report

        Returns:
            HTML content as bytes
        """
        html = self._build_html(report_data)
        return html.encode("utf-8")

    def _build_html(self, report_data: ReportData) -> str:
        """Build the complete HTML document.

        Args:
            report_data: Report data

        Returns:
            HTML string
        """
        styles = self._get_styles() if self.include_styles else ""
        chart_js = self._get_chart_script() if self.include_charts else ""

        # Build issue rows
        issue_rows = []
        for issue in sorted(
            report_data.all_issues,
            key=lambda x: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity.value, 5)
            )
        ):
            issue_rows.append(self._build_issue_row(issue))

        # Build category score rows
        category_rows = []
        for name, cat_score in report_data.score.category_scores.items():
            category_rows.append(self._build_category_row(name, cat_score))

        # Build AI insights section
        ai_section = ""
        if report_data.ai_insights:
            ai_section = self._build_ai_insights_section(report_data.ai_insights)

        # Build grouped problems section (new)
        grouped_problems_section = ""
        if report_data.processed_results:
            grouped_problems_section = self._build_grouped_problems_section(report_data.processed_results)

        # Determine status class
        if report_data.score.is_production_ready:
            status_class = "status-ready" if report_data.score.overall_score >= 80 else "status-acceptable"
        else:
            status_class = "status-not-ready"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Production Readiness Report - {report_data.project_name}</title>
    {styles}
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>Production Readiness Assessment Report</h1>
            <p class="subtitle">{report_data.project_name}</p>
            <p class="timestamp">Generated: {report_data.generated_at.strftime("%Y-%m-%d %H:%M:%S")}</p>
        </header>

        <section class="summary-section">
            <div class="score-card {status_class}">
                <div class="score-value">{report_data.score.overall_score:.1f}</div>
                <div class="score-label">Overall Score</div>
                <div class="score-grade">Grade: {report_data.score.grade}</div>
            </div>
            <div class="summary-details">
                <div class="summary-item">
                    <span class="label">Status:</span>
                    <span class="value {status_class}">{report_data.score.status}</span>
                </div>
                <div class="summary-item">
                    <span class="label">Total Issues:</span>
                    <span class="value">{report_data.total_issues}</span>
                </div>
                <div class="summary-item">
                    <span class="label">Blocking Issues:</span>
                    <span class="value critical">{report_data.score.blocking_issues}</span>
                </div>
                <div class="summary-item">
                    <span class="label">Production Ready:</span>
                    <span class="value {'ready' if report_data.score.is_production_ready else 'not-ready'}">
                        {'Yes' if report_data.score.is_production_ready else 'No'}
                    </span>
                </div>
            </div>
        </section>

        <section class="severity-section">
            <h2>Issue Severity Distribution</h2>
            <div class="severity-grid">
                <div class="severity-item critical">
                    <span class="count">{report_data.critical_count}</span>
                    <span class="label">Critical</span>
                </div>
                <div class="severity-item high">
                    <span class="count">{report_data.high_count}</span>
                    <span class="label">High</span>
                </div>
                <div class="severity-item medium">
                    <span class="count">{sum(r.medium_count for r in report_data.scan_results)}</span>
                    <span class="label">Medium</span>
                </div>
                <div class="severity-item low">
                    <span class="count">{sum(r.low_count for r in report_data.scan_results)}</span>
                    <span class="label">Low</span>
                </div>
                <div class="severity-item info">
                    <span class="count">{sum(r.info_count for r in report_data.scan_results)}</span>
                    <span class="label">Info</span>
                </div>
            </div>
        </section>

        <section class="categories-section">
            <h2>Category Scores</h2>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Score</th>
                        <th>Grade</th>
                        <th>Issues</th>
                        <th>Critical</th>
                        <th>High</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(category_rows)}
                </tbody>
            </table>
        </section>

        {ai_section}

        {grouped_problems_section}

        <section class="issues-section">
            <h2>Detailed Issues ({report_data.total_issues} total)</h2>
            <table class="data-table issues-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Category</th>
                        <th>File</th>
                        <th>Fixable</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(issue_rows)}
                </tbody>
            </table>
        </section>

        <section class="scan-info-section">
            <h2>Scan Information</h2>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Scanner</th>
                        <th>Type</th>
                        <th>Duration</th>
                        <th>Issues Found</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {self._build_scan_info_rows(report_data.scan_results)}
                </tbody>
            </table>
        </section>

        <footer class="footer">
            <p>Production Readiness Checker v1.0.0</p>
            <p>Report generated automatically. For questions, contact your DevOps team.</p>
        </footer>
    </div>
    {chart_js}
</body>
</html>"""

    def _build_issue_row(self, issue) -> str:
        """Build an HTML table row for an issue."""
        file_info = issue.file_path or "N/A"
        if issue.line_number:
            file_info += f":{issue.line_number}"

        return f"""
        <tr class="issue-row severity-{issue.severity.value}">
            <td><span class="severity-badge {issue.severity.value}">{issue.severity.value.upper()}</span></td>
            <td>
                <div class="issue-title">{issue.title}</div>
                <div class="issue-description">{issue.description[:200]}{'...' if len(issue.description) > 200 else ''}</div>
                {f'<div class="issue-remediation"><strong>Fix:</strong> {issue.remediation[:150]}...</div>' if issue.remediation else ''}
            </td>
            <td>{issue.category.value}</td>
            <td class="file-path">{file_info}</td>
            <td>{'Yes' if issue.auto_fixable else 'No'}</td>
        </tr>"""

    def _build_category_row(self, name: str, cat_score) -> str:
        """Build an HTML table row for a category score."""
        score_class = "good" if cat_score.score >= 80 else "warning" if cat_score.score >= 60 else "danger"
        return f"""
        <tr>
            <td><strong>{name.title()}</strong></td>
            <td><span class="score-badge {score_class}">{cat_score.score:.1f}</span></td>
            <td>{cat_score.grade}</td>
            <td>{cat_score.issues_count}</td>
            <td class="critical-count">{cat_score.critical_count}</td>
            <td class="high-count">{cat_score.high_count}</td>
        </tr>"""

    def _build_scan_info_rows(self, scan_results) -> str:
        """Build HTML table rows for scan information."""
        rows = []
        for result in scan_results:
            status_class = "success" if result.success else "error"
            rows.append(f"""
            <tr>
                <td>{result.scanner_name}</td>
                <td>{result.scan_type}</td>
                <td>{result.scan_duration_ms}ms</td>
                <td>{result.issue_count}</td>
                <td><span class="status-badge {status_class}">{'Success' if result.success else 'Failed'}</span></td>
            </tr>""")
        return "".join(rows)

    def _build_ai_insights_section(self, ai_insights) -> str:
        """Build the AI insights section."""
        findings_html = "".join(f"<li>{f}</li>" for f in ai_insights.key_findings)
        actions_html = "".join(
            f"""<div class="action-item priority-{a['priority']}">
                <span class="priority-badge">{a['priority'].upper()}</span>
                <span class="action-text">{a['action']}</span>
                <span class="effort">{a.get('effort', '')}</span>
            </div>"""
            for a in ai_insights.priority_actions
        )

        return f"""
        <section class="ai-insights-section">
            <h2>AI-Powered Insights</h2>
            <div class="executive-summary">
                <h3>Executive Summary</h3>
                <p>{ai_insights.executive_summary}</p>
            </div>
            <div class="key-findings">
                <h3>Key Findings</h3>
                <ul>{findings_html}</ul>
            </div>
            <div class="priority-actions">
                <h3>Priority Actions</h3>
                {actions_html}
            </div>
            <div class="risk-overview">
                <h3>Risk Overview</h3>
                <p>{ai_insights.risk_overview}</p>
            </div>
        </section>"""

    def _build_grouped_problems_section(self, processed_results: "ProcessedResults") -> str:
        """Build the grouped problems section organized by dimension."""
        if not processed_results or not processed_results.unique_problems:
            return ""

        dimension_icons = {
            "security": "🔒",
            "performance": "⚡",
            "reliability": "🛡️",
            "monitoring": "📊",
        }

        dimension_colors = {
            "security": "#dc2626",
            "performance": "#f59e0b",
            "reliability": "#2563eb",
            "monitoring": "#8b5cf6",
        }

        dimensions_html = []

        for dimension in ["security", "performance", "reliability", "monitoring"]:
            problems = processed_results.problems_by_dimension.get(dimension, [])
            if not problems:
                continue

            icon = dimension_icons.get(dimension, "📋")
            color = dimension_colors.get(dimension, "#6b7280")
            summary = processed_results.dimension_summary.get(dimension, {})

            # Build problems list for this dimension
            problems_html = []
            for problem in problems:
                files_preview = ", ".join(problem.affected_files[:3])
                if len(problem.affected_files) > 3:
                    files_preview += f" (+{len(problem.affected_files) - 3} more)"

                explanation_html = ""
                if problem.explanation:
                    explanation_html = f'<div class="problem-explanation">{problem.explanation}</div>'

                recommendation_html = ""
                if problem.recommendation:
                    recommendation_html = f'<div class="problem-recommendation"><strong>Recommendation:</strong> {problem.recommendation}</div>'

                problems_html.append(f"""
                <div class="problem-card severity-{problem.final_severity.value}">
                    <div class="problem-header">
                        <span class="severity-badge {problem.final_severity.value}">{problem.final_severity.value.upper()}</span>
                        <span class="problem-title">{problem.title}</span>
                        <span class="occurrence-badge">{problem.occurrence_count} occurrence{'s' if problem.occurrence_count > 1 else ''}</span>
                    </div>
                    <div class="problem-body">
                        <div class="problem-key"><code>{problem.problem_key}</code></div>
                        <div class="problem-description">{problem.description[:300]}{'...' if len(problem.description) > 300 else ''}</div>
                        {explanation_html}
                        {recommendation_html}
                        <div class="problem-files">
                            <strong>Affected files:</strong> {files_preview}
                        </div>
                        <div class="problem-meta">
                            <span>Scanners: {', '.join(problem.scanners) if problem.scanners else 'N/A'}</span>
                            <span>Rules: {', '.join(problem.rule_ids[:3]) if problem.rule_ids else 'N/A'}</span>
                        </div>
                    </div>
                </div>
                """)

            severity_counts = summary.get("severity_counts", {})
            dimensions_html.append(f"""
            <div class="dimension-group" style="border-left: 4px solid {color};">
                <div class="dimension-header">
                    <span class="dimension-icon">{icon}</span>
                    <span class="dimension-name">{dimension.title()}</span>
                    <span class="dimension-stats">
                        {summary.get('unique_problem_count', 0)} unique problems |
                        {summary.get('total_occurrences', 0)} total occurrences
                    </span>
                    <span class="dimension-severity-summary">
                        {f'<span class="critical">{severity_counts.get("critical", 0)} Critical</span>' if severity_counts.get("critical", 0) > 0 else ''}
                        {f'<span class="high">{severity_counts.get("high", 0)} High</span>' if severity_counts.get("high", 0) > 0 else ''}
                        {f'<span class="medium">{severity_counts.get("medium", 0)} Medium</span>' if severity_counts.get("medium", 0) > 0 else ''}
                    </span>
                </div>
                <div class="dimension-problems">
                    {''.join(problems_html)}
                </div>
            </div>
            """)

        return f"""
        <section class="grouped-problems-section">
            <h2>Issues by Dimension ({processed_results.total_unique_problems} unique problems from {processed_results.total_issues} instances)</h2>
            <p class="section-description">
                Issues are grouped by type. Multiple occurrences of the same problem are consolidated into a single entry.
            </p>
            {''.join(dimensions_html)}
        </section>
        """

    def _get_styles(self) -> str:
        """Get embedded CSS styles."""
        return """
    <style>
        :root {
            --primary-color: #2563eb;
            --success-color: #16a34a;
            --warning-color: #f59e0b;
            --danger-color: #dc2626;
            --critical-color: #7c2d12;
            --high-color: #dc2626;
            --medium-color: #f59e0b;
            --low-color: #2563eb;
            --info-color: #6b7280;
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #1e293b;
            --border-color: #e2e8f0;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid var(--border-color);
        }

        .header h1 {
            color: var(--primary-color);
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }

        .subtitle {
            font-size: 1.25rem;
            color: var(--text-color);
        }

        .timestamp {
            color: var(--info-color);
            font-size: 0.875rem;
        }

        section {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        section h2 {
            color: var(--text-color);
            font-size: 1.25rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }

        .summary-section {
            display: flex;
            gap: 2rem;
            align-items: center;
        }

        .score-card {
            text-align: center;
            padding: 1.5rem 2rem;
            border-radius: 8px;
            min-width: 150px;
        }

        .score-card.status-ready {
            background: linear-gradient(135deg, #16a34a, #22c55e);
            color: white;
        }

        .score-card.status-acceptable {
            background: linear-gradient(135deg, #f59e0b, #fbbf24);
            color: white;
        }

        .score-card.status-not-ready {
            background: linear-gradient(135deg, #dc2626, #ef4444);
            color: white;
        }

        .score-value {
            font-size: 3rem;
            font-weight: bold;
        }

        .score-label {
            font-size: 0.875rem;
            opacity: 0.9;
        }

        .score-grade {
            font-size: 1.25rem;
            margin-top: 0.5rem;
        }

        .summary-details {
            flex: 1;
        }

        .summary-item {
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border-color);
        }

        .summary-item .label {
            font-weight: 500;
        }

        .summary-item .value.critical { color: var(--critical-color); }
        .summary-item .value.ready { color: var(--success-color); }
        .summary-item .value.not-ready { color: var(--danger-color); }

        .severity-grid {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .severity-item {
            flex: 1;
            min-width: 100px;
            text-align: center;
            padding: 1rem;
            border-radius: 8px;
            color: white;
        }

        .severity-item.critical { background: var(--critical-color); }
        .severity-item.high { background: var(--high-color); }
        .severity-item.medium { background: var(--medium-color); }
        .severity-item.low { background: var(--low-color); }
        .severity-item.info { background: var(--info-color); }

        .severity-item .count {
            font-size: 2rem;
            font-weight: bold;
            display: block;
        }

        .data-table {
            width: 100%;
            border-collapse: collapse;
        }

        .data-table th,
        .data-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        .data-table th {
            background: var(--bg-color);
            font-weight: 600;
        }

        .data-table tr:hover {
            background: var(--bg-color);
        }

        .severity-badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
            text-transform: uppercase;
        }

        .severity-badge.critical { background: var(--critical-color); }
        .severity-badge.high { background: var(--high-color); }
        .severity-badge.medium { background: var(--medium-color); }
        .severity-badge.low { background: var(--low-color); }
        .severity-badge.info { background: var(--info-color); }

        .score-badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-weight: 600;
        }

        .score-badge.good { background: #dcfce7; color: var(--success-color); }
        .score-badge.warning { background: #fef3c7; color: var(--warning-color); }
        .score-badge.danger { background: #fee2e2; color: var(--danger-color); }

        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
        }

        .status-badge.success { background: #dcfce7; color: var(--success-color); }
        .status-badge.error { background: #fee2e2; color: var(--danger-color); }

        .issue-title {
            font-weight: 500;
            margin-bottom: 0.25rem;
        }

        .issue-description {
            font-size: 0.875rem;
            color: var(--info-color);
        }

        .issue-remediation {
            font-size: 0.8rem;
            color: var(--success-color);
            margin-top: 0.25rem;
        }

        .file-path {
            font-family: monospace;
            font-size: 0.8rem;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .critical-count { color: var(--critical-color); font-weight: 600; }
        .high-count { color: var(--high-color); font-weight: 600; }

        /* Grouped Problems Section Styles */
        .grouped-problems-section {
            background: var(--card-bg);
        }

        .section-description {
            color: var(--info-color);
            font-size: 0.9rem;
            margin-bottom: 1.5rem;
        }

        .dimension-group {
            background: var(--bg-color);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            padding: 1rem;
        }

        .dimension-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }

        .dimension-icon {
            font-size: 1.5rem;
        }

        .dimension-name {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-color);
        }

        .dimension-stats {
            color: var(--info-color);
            font-size: 0.875rem;
        }

        .dimension-severity-summary {
            margin-left: auto;
            display: flex;
            gap: 0.75rem;
            font-size: 0.75rem;
        }

        .dimension-severity-summary .critical { color: var(--critical-color); font-weight: 600; }
        .dimension-severity-summary .high { color: var(--high-color); font-weight: 600; }
        .dimension-severity-summary .medium { color: var(--medium-color); font-weight: 600; }

        .dimension-problems {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .problem-card {
            background: var(--card-bg);
            border-radius: 6px;
            padding: 1rem;
            border-left: 3px solid var(--info-color);
        }

        .problem-card.severity-critical { border-left-color: var(--critical-color); }
        .problem-card.severity-high { border-left-color: var(--high-color); }
        .problem-card.severity-medium { border-left-color: var(--medium-color); }
        .problem-card.severity-low { border-left-color: var(--low-color); }
        .problem-card.severity-info { border-left-color: var(--info-color); }

        .problem-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
            flex-wrap: wrap;
        }

        .problem-title {
            font-weight: 600;
            color: var(--text-color);
        }

        .occurrence-badge {
            background: var(--bg-color);
            padding: 0.2rem 0.5rem;
            border-radius: 12px;
            font-size: 0.75rem;
            color: var(--info-color);
        }

        .problem-body {
            font-size: 0.9rem;
        }

        .problem-key {
            margin-bottom: 0.5rem;
        }

        .problem-key code {
            background: var(--bg-color);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.8rem;
            color: var(--primary-color);
        }

        .problem-description {
            color: var(--text-color);
            margin-bottom: 0.75rem;
            line-height: 1.5;
        }

        .problem-explanation {
            background: #f0f9ff;
            padding: 0.75rem;
            border-radius: 4px;
            margin-bottom: 0.75rem;
            font-size: 0.85rem;
            color: #1e40af;
        }

        .problem-recommendation {
            background: #f0fdf4;
            padding: 0.75rem;
            border-radius: 4px;
            margin-bottom: 0.75rem;
            font-size: 0.85rem;
            color: #166534;
        }

        .problem-files {
            font-size: 0.8rem;
            color: var(--info-color);
            margin-bottom: 0.5rem;
            font-family: monospace;
        }

        .problem-meta {
            display: flex;
            gap: 1.5rem;
            font-size: 0.75rem;
            color: var(--info-color);
        }

        .ai-insights-section {
            background: linear-gradient(135deg, #f0f9ff, #e0f2fe);
        }

        .executive-summary p {
            margin-bottom: 1rem;
            white-space: pre-line;
        }

        .key-findings ul {
            margin-left: 1.5rem;
        }

        .key-findings li {
            margin-bottom: 0.5rem;
        }

        .action-item {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            border-radius: 4px;
            background: white;
        }

        .priority-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .action-item.priority-high .priority-badge {
            background: var(--high-color);
            color: white;
        }

        .action-item.priority-medium .priority-badge {
            background: var(--medium-color);
            color: white;
        }

        .action-item.priority-low .priority-badge {
            background: var(--low-color);
            color: white;
        }

        .effort {
            margin-left: auto;
            color: var(--info-color);
            font-size: 0.875rem;
        }

        .footer {
            text-align: center;
            padding: 1.5rem;
            color: var(--info-color);
            font-size: 0.875rem;
            border-top: 1px solid var(--border-color);
        }

        @media (max-width: 768px) {
            .summary-section {
                flex-direction: column;
            }

            .severity-grid {
                flex-direction: column;
            }

            .data-table {
                display: block;
                overflow-x: auto;
            }
        }

        @media print {
            body { background: white; }
            .container { max-width: none; padding: 0; }
            section { box-shadow: none; border: 1px solid var(--border-color); }
        }
    </style>"""

    def _get_chart_script(self) -> str:
        """Get embedded chart JavaScript (optional enhancement)."""
        return """
    <script>
        // Charts can be added here using Chart.js or similar library
        // For now, we use CSS-based visualizations
    </script>"""
