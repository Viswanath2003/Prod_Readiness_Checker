"""JSON Reporter Module - Generate JSON format reports."""

import json
from typing import Any, Dict, Optional

from .base_reporter import BaseReporter, ReportData


class JSONReporter(BaseReporter):
    """Generate reports in JSON format."""

    def __init__(
        self,
        output_dir: Optional[str] = None,
        indent: int = 2,
        include_metadata: bool = True,
    ):
        """Initialize the JSON reporter.

        Args:
            output_dir: Directory to save reports
            indent: JSON indentation level
            include_metadata: Include metadata in the report
        """
        super().__init__(output_dir)
        self.indent = indent
        self.include_metadata = include_metadata

    @property
    def format(self) -> str:
        return "json"

    @property
    def extension(self) -> str:
        return "json"

    def generate(self, report_data: ReportData) -> bytes:
        """Generate JSON report.

        Args:
            report_data: Data to include in the report

        Returns:
            JSON content as bytes
        """
        report_dict = self._build_report_structure(report_data)
        json_str = json.dumps(report_dict, indent=self.indent, ensure_ascii=False)
        return json_str.encode("utf-8")

    def _build_report_structure(self, report_data: ReportData) -> Dict[str, Any]:
        """Build the JSON report structure.

        Args:
            report_data: Report data

        Returns:
            Dictionary for JSON serialization
        """
        report = {
            "report_info": {
                "title": "Production Readiness Assessment Report",
                "project_name": report_data.project_name,
                "project_path": report_data.project_path,
                "generated_at": report_data.generated_at.isoformat(),
                "report_format": self.format,
                "version": "1.0.0",
            },
            "summary": {
                "overall_score": round(report_data.score.overall_score, 2),
                "grade": report_data.score.grade,
                "status": report_data.score.status,
                "is_production_ready": report_data.score.is_production_ready,
                "readiness_threshold": report_data.score.readiness_threshold,
                "total_issues": report_data.total_issues,
                "blocking_issues": report_data.score.blocking_issues,
                "severity_distribution": {
                    "critical": report_data.critical_count,
                    "high": report_data.high_count,
                    "medium": sum(r.medium_count for r in report_data.scan_results),
                    "low": sum(r.low_count for r in report_data.scan_results),
                    "info": sum(r.info_count for r in report_data.scan_results),
                },
            },
            "category_scores": {
                name: {
                    "score": round(cat_score.score, 2),
                    "grade": cat_score.grade,
                    "status": cat_score.status,
                    "weight": cat_score.weight,
                    "issues": {
                        "total": cat_score.issues_count,
                        "critical": cat_score.critical_count,
                        "high": cat_score.high_count,
                        "medium": cat_score.medium_count,
                        "low": cat_score.low_count,
                        "info": cat_score.info_count,
                    },
                }
                for name, cat_score in report_data.score.category_scores.items()
            },
            "scan_results": [
                self._format_scan_result(result)
                for result in report_data.scan_results
            ],
            "issues": [
                self._format_issue(issue)
                for issue in report_data.all_issues
            ],
        }

        # Add AI insights if available
        if report_data.ai_insights:
            report["ai_insights"] = report_data.ai_insights.to_dict()

        # Add processed results (unique problems grouped by dimension)
        if report_data.processed_results:
            report["processed_results"] = {
                "total_issues": report_data.processed_results.total_issues,
                "total_unique_problems": report_data.processed_results.total_unique_problems,
                "dimension_summary": report_data.processed_results.dimension_summary,
                "problems_by_dimension": {
                    dimension: [
                        {
                            "problem_key": p.problem_key,
                            "title": p.title,
                            "description": p.description,
                            "final_severity": p.final_severity.value,
                            "occurrence_count": p.occurrence_count,
                            "affected_files": p.affected_files,
                            "explanation": p.explanation,
                            "recommendation": p.recommendation,
                            "rule_ids": p.rule_ids,
                            "scanners": p.scanners,
                        }
                        for p in problems
                    ]
                    for dimension, problems in report_data.processed_results.problems_by_dimension.items()
                },
            }

        # Add metadata if requested
        if self.include_metadata:
            report["metadata"] = report_data.metadata

        return report

    def _format_scan_result(self, result) -> Dict[str, Any]:
        """Format a scan result for the report.

        Args:
            result: ScanResult object

        Returns:
            Formatted dictionary
        """
        return {
            "scanner": result.scanner_name,
            "scan_type": result.scan_type,
            "target": result.target_path,
            "success": result.success,
            "duration_ms": result.scan_duration_ms,
            "issue_count": result.issue_count,
            "severity_counts": {
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "info": result.info_count,
            },
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        }

    def _format_issue(self, issue) -> Dict[str, Any]:
        """Format an issue for the report.

        Args:
            issue: Issue object

        Returns:
            Formatted dictionary
        """
        return {
            "id": issue.id,
            "title": issue.title,
            "description": issue.description,
            "severity": issue.severity.value,
            "category": issue.category.value,
            "location": {
                "file": issue.file_path,
                "line": issue.line_number,
            },
            "rule_id": issue.rule_id,
            "scanner": issue.scanner,
            "remediation": issue.remediation,
            "auto_fixable": issue.auto_fixable,
            "fix_suggestion": issue.fix_suggestion,
            "references": issue.references,
        }
