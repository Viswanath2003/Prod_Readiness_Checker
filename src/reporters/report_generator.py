"""Report Generator Module - Orchestrates report generation across multiple formats."""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .base_reporter import BaseReporter, ReportData
from .json_reporter import JSONReporter
from .html_reporter import HTMLReporter
from .pdf_reporter import PDFReporter
from ..core.scanner import ScanResult
from ..core.scorer import Score
from ..api.ai_insights import AIInsightsGenerator, ReportInsights


class ReportGenerator:
    """Orchestrates report generation across multiple formats with AI insights."""

    SUPPORTED_FORMATS = ["json", "html", "pdf"]

    def __init__(
        self,
        output_dir: Optional[str] = None,
        enable_ai_insights: bool = True,
        openai_api_key: Optional[str] = None,
    ):
        """Initialize the report generator.

        Args:
            output_dir: Directory to save reports
            enable_ai_insights: Enable AI-powered insights
            openai_api_key: OpenAI API key for AI insights
        """
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.enable_ai_insights = enable_ai_insights

        # Initialize AI insights generator
        if enable_ai_insights:
            self.ai_generator = AIInsightsGenerator(api_key=openai_api_key)
        else:
            self.ai_generator = None

        # Initialize reporters
        self.reporters: Dict[str, BaseReporter] = {
            "json": JSONReporter(str(self.output_dir)),
            "html": HTMLReporter(str(self.output_dir)),
        }

        # Try to add PDF reporter
        try:
            self.reporters["pdf"] = PDFReporter(str(self.output_dir))
        except ImportError:
            pass  # PDF not available

    def get_available_formats(self) -> List[str]:
        """Get list of available report formats.

        Returns:
            List of format names
        """
        return list(self.reporters.keys())

    async def generate_reports(
        self,
        project_name: str,
        project_path: str,
        scan_results: List[ScanResult],
        score: Score,
        formats: Optional[List[str]] = None,
        include_ai: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        """Generate reports in multiple formats.

        Args:
            project_name: Name of the project
            project_path: Path to the project
            scan_results: List of scan results
            score: Overall score
            formats: List of formats to generate (default: all available)
            include_ai: Include AI insights (if enabled)
            metadata: Additional metadata for the report

        Returns:
            Dictionary mapping format to report path
        """
        formats = formats or self.get_available_formats()

        # Validate formats
        invalid_formats = [f for f in formats if f not in self.reporters]
        if invalid_formats:
            raise ValueError(f"Unsupported formats: {invalid_formats}")

        # Generate AI insights if enabled
        ai_insights = None
        if include_ai and self.enable_ai_insights and self.ai_generator:
            ai_insights = await self._generate_ai_insights(scan_results, score)

        # Create report data
        report_data = ReportData(
            project_name=project_name,
            project_path=project_path,
            scan_results=scan_results,
            score=score,
            ai_insights=ai_insights,
            generated_at=datetime.now(),
            metadata=metadata or {},
        )

        # Generate reports
        report_paths = {}
        for format_name in formats:
            reporter = self.reporters[format_name]
            try:
                path = reporter.save(report_data)
                report_paths[format_name] = path
            except Exception as e:
                print(f"Error generating {format_name} report: {e}")

        return report_paths

    def generate_reports_sync(
        self,
        project_name: str,
        project_path: str,
        scan_results: List[ScanResult],
        score: Score,
        formats: Optional[List[str]] = None,
        include_ai: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        """Synchronous wrapper for generate_reports.

        Args:
            project_name: Name of the project
            project_path: Path to the project
            scan_results: List of scan results
            score: Overall score
            formats: List of formats to generate
            include_ai: Include AI insights
            metadata: Additional metadata

        Returns:
            Dictionary mapping format to report path
        """
        return asyncio.run(self.generate_reports(
            project_name=project_name,
            project_path=project_path,
            scan_results=scan_results,
            score=score,
            formats=formats,
            include_ai=include_ai,
            metadata=metadata,
        ))

    async def _generate_ai_insights(
        self,
        scan_results: List[ScanResult],
        score: Score,
    ) -> Optional[ReportInsights]:
        """Generate AI insights for the report.

        Args:
            scan_results: List of scan results
            score: Overall score

        Returns:
            ReportInsights or None
        """
        try:
            return await self.ai_generator.generate_report_insights(
                scan_results, score
            )
        except Exception as e:
            print(f"Error generating AI insights: {e}")
            return None

    def generate_single_report(
        self,
        project_name: str,
        project_path: str,
        scan_results: List[ScanResult],
        score: Score,
        format_name: str,
        ai_insights: Optional[ReportInsights] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate a single report in the specified format.

        Args:
            project_name: Name of the project
            project_path: Path to the project
            scan_results: List of scan results
            score: Overall score
            format_name: Format to generate
            ai_insights: Pre-generated AI insights
            metadata: Additional metadata

        Returns:
            Path to the generated report
        """
        if format_name not in self.reporters:
            raise ValueError(f"Unsupported format: {format_name}")

        report_data = ReportData(
            project_name=project_name,
            project_path=project_path,
            scan_results=scan_results,
            score=score,
            ai_insights=ai_insights,
            generated_at=datetime.now(),
            metadata=metadata or {},
        )

        reporter = self.reporters[format_name]
        return reporter.save(report_data)

    def get_report_content(
        self,
        project_name: str,
        project_path: str,
        scan_results: List[ScanResult],
        score: Score,
        format_name: str,
        ai_insights: Optional[ReportInsights] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """Get report content without saving to file.

        Args:
            project_name: Name of the project
            project_path: Path to the project
            scan_results: List of scan results
            score: Overall score
            format_name: Format to generate
            ai_insights: Pre-generated AI insights
            metadata: Additional metadata

        Returns:
            Report content as bytes
        """
        if format_name not in self.reporters:
            raise ValueError(f"Unsupported format: {format_name}")

        report_data = ReportData(
            project_name=project_name,
            project_path=project_path,
            scan_results=scan_results,
            score=score,
            ai_insights=ai_insights,
            generated_at=datetime.now(),
            metadata=metadata or {},
        )

        reporter = self.reporters[format_name]
        return reporter.generate(report_data)
