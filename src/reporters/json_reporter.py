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
        """Build the JSON report structure matching the expected schema.

        Expected schema:
        {
          "report_info": { ... },
          "summary": { ... },
          "dimensions": {
            "security": { score, grade, status, total_unique_problems, problems: [...] },
            "performance": { ... },
            "reliability": { ... },
            "monitoring": { ... }
          }
        }

        Args:
            report_data: Report data

        Returns:
            Dictionary for JSON serialization
        """
        # Calculate total unique problems and blocking problems
        total_unique_problems = 0
        blocking_problems = 0

        if report_data.processed_results:
            total_unique_problems = report_data.processed_results.total_unique_problems
            # Count blocking problems (CRITICAL + HIGH severity)
            for problems in report_data.processed_results.problems_by_dimension.values():
                for p in problems:
                    if p.final_severity.value in ["critical", "high"]:
                        blocking_problems += 1

        # Build the main report structure
        report = {
            "report_info": {
                "project_name": report_data.project_name,
                "project_path": report_data.project_path,
                "generated_at": report_data.generated_at.isoformat(),
                "version": "1.0.0",
            },
            "summary": {
                "overall_score": round(report_data.score.overall_score, 2),
                "grade": report_data.score.grade,
                "status": report_data.score.status,
                "total_unique_problems": total_unique_problems,
                "blocking_problems": blocking_problems,
                "is_production_ready": report_data.score.is_production_ready,
                "readiness_threshold": report_data.score.readiness_threshold,
            },
            "dimensions": self._build_dimensions(report_data),
        }

        # Add severity distribution for overall view
        report["summary"]["severity_distribution"] = {
            "critical": report_data.critical_count,
            "high": report_data.high_count,
            "medium": sum(r.medium_count for r in report_data.scan_results),
            "low": sum(r.low_count for r in report_data.scan_results),
            "info": sum(r.info_count for r in report_data.scan_results),
        }

        # Add AI insights if available
        if report_data.ai_insights:
            report["ai_insights"] = report_data.ai_insights.to_dict()

        # Add metadata if requested
        if self.include_metadata:
            report["metadata"] = report_data.metadata

        return report

    def _build_dimensions(self, report_data: ReportData) -> Dict[str, Any]:
        """Build the dimensions section with problems grouped correctly.

        Args:
            report_data: Report data

        Returns:
            Dimensions dictionary
        """
        dimensions = {}
        dimension_names = ["security", "performance", "reliability", "monitoring"]

        for dim_name in dimension_names:
            # Get category score if available
            cat_score = report_data.score.category_scores.get(dim_name)

            # Get problems for this dimension
            problems = []
            if report_data.processed_results:
                dim_problems = report_data.processed_results.problems_by_dimension.get(dim_name, [])
                problems = [self._format_problem(p) for p in dim_problems]

            dimensions[dim_name] = {
                "score": round(cat_score.score, 2) if cat_score else 100.0,
                "grade": cat_score.grade if cat_score else "A",
                "status": self._get_status_from_score(cat_score.score if cat_score else 100.0),
                "total_unique_problems": len(problems),
                "problems": problems,
            }

        return dimensions

    def _format_problem(self, problem) -> Dict[str, Any]:
        """Format a unique problem according to the expected schema.

        Args:
            problem: UniqueProblem object

        Returns:
            Formatted problem dictionary
        """
        # Build example instances (first 3 occurrences with file and line info)
        example_instances = []
        for issue in problem.original_issues[:3]:
            instance = {"file": issue.file_path}
            if hasattr(issue.original_issue, 'line_number') and issue.original_issue.line_number:
                instance["line"] = issue.original_issue.line_number
            example_instances.append(instance)

        return {
            "problem_key": problem.problem_key,
            "title": problem.title,
            "dimension": problem.dimension,
            "severity": problem.final_severity.value.upper(),
            "confidence": "HIGH",  # Default to HIGH as issues come from scanners
            "occurrence_count": problem.occurrence_count,
            "affected_files_count": len(problem.affected_files),
            "explanation": problem.explanation or problem.description,
            "recommendation": problem.recommendation or "",
            "affected_files": problem.affected_files,
            "metadata": {
                "detected_by_scanners": problem.scanners,
                "rule_ids": problem.rule_ids,
                "example_instances": example_instances,
            },
        }

    def _get_status_from_score(self, score: float) -> str:
        """Get status text from score.

        Args:
            score: Numeric score

        Returns:
            Status string
        """
        if score >= 90:
            return "Excellent"
        elif score >= 80:
            return "Good"
        elif score >= 60:
            return "Warning"
        else:
            return "Critical"

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
