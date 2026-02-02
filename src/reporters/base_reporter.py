"""Base Reporter Module - Abstract base class for report generators."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ..core.scanner import ScanResult
from ..core.scorer import Score
from ..api.ai_insights import ReportInsights

if TYPE_CHECKING:
    from ..core.issue_processor import ProcessedResults


@dataclass
class ReportData:
    """Data structure containing all information for a report."""
    project_name: str
    project_path: str
    scan_results: List[ScanResult]
    score: Score
    ai_insights: Optional[ReportInsights] = None
    processed_results: Optional["ProcessedResults"] = None  # Grouped problems
    generated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "project_name": self.project_name,
            "project_path": self.project_path,
            "scan_results": [r.to_dict() for r in self.scan_results],
            "score": self.score.to_dict(),
            "ai_insights": self.ai_insights.to_dict() if self.ai_insights else None,
            "processed_results": self.processed_results.to_dict() if self.processed_results else None,
            "generated_at": self.generated_at.isoformat(),
            "metadata": self.metadata,
        }

    @property
    def total_issues(self) -> int:
        """Get total issue count."""
        return sum(r.issue_count for r in self.scan_results)

    @property
    def critical_count(self) -> int:
        """Get critical issue count."""
        return sum(r.critical_count for r in self.scan_results)

    @property
    def high_count(self) -> int:
        """Get high severity issue count."""
        return sum(r.high_count for r in self.scan_results)

    @property
    def all_issues(self) -> List[Any]:
        """Get all issues from all scan results."""
        issues = []
        for result in self.scan_results:
            issues.extend(result.issues)
        return issues


class BaseReporter(ABC):
    """Abstract base class for report generators."""

    def __init__(self, output_dir: Optional[str] = None):
        """Initialize the reporter.

        Args:
            output_dir: Directory to save reports (default: current directory)
        """
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @property
    @abstractmethod
    def format(self) -> str:
        """Report format identifier (e.g., 'json', 'html', 'pdf')."""
        pass

    @property
    @abstractmethod
    def extension(self) -> str:
        """File extension for the report format."""
        pass

    @abstractmethod
    def generate(self, report_data: ReportData) -> bytes:
        """Generate the report content.

        Args:
            report_data: Data to include in the report

        Returns:
            Report content as bytes
        """
        pass

    def generate_filename(
        self,
        project_name: str,
        timestamp: Optional[datetime] = None,
    ) -> str:
        """Generate a filename for the report.

        Args:
            project_name: Name of the project
            timestamp: Timestamp for the report (default: now)

        Returns:
            Generated filename
        """
        ts = timestamp or datetime.now()
        ts_str = ts.strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(c if c.isalnum() else "_" for c in project_name)
        return f"prc_report_{safe_name}_{ts_str}.{self.extension}"

    def save(
        self,
        report_data: ReportData,
        filename: Optional[str] = None,
    ) -> str:
        """Generate and save the report to a file.

        Args:
            report_data: Data to include in the report
            filename: Custom filename (default: auto-generated)

        Returns:
            Path to the saved report
        """
        content = self.generate(report_data)

        if not filename:
            filename = self.generate_filename(
                report_data.project_name,
                report_data.generated_at,
            )

        output_path = self.output_dir / filename

        with open(output_path, "wb") as f:
            f.write(content)

        return str(output_path)
