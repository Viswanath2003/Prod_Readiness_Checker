"""Base Scanner Module - Defines base classes and data models for scanners."""

import asyncio
import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """Severity levels for issues."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        """Get numeric weight for severity."""
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return weights[self]

    @property
    def color(self) -> str:
        """Get color code for severity."""
        colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "gray",
        }
        return colors[self]


class IssueCategory(Enum):
    """Categories of issues."""
    SECURITY = "security"
    PERFORMANCE = "performance"
    RELIABILITY = "reliability"
    MONITORING = "monitoring"
    BEST_PRACTICE = "best_practice"
    CONFIGURATION = "configuration"


@dataclass
class Issue:
    """Represents a single issue found during scanning."""
    id: str
    title: str
    description: str
    severity: Severity
    category: IssueCategory
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    rule_id: Optional[str] = None
    scanner: str = ""
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    auto_fixable: bool = False
    fix_suggestion: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert issue to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "rule_id": self.rule_id,
            "scanner": self.scanner,
            "remediation": self.remediation,
            "references": self.references,
            "metadata": self.metadata,
            "auto_fixable": self.auto_fixable,
            "fix_suggestion": self.fix_suggestion,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Issue":
        """Create issue from dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            severity=Severity(data["severity"]),
            category=IssueCategory(data["category"]),
            file_path=data.get("file_path"),
            line_number=data.get("line_number"),
            rule_id=data.get("rule_id"),
            scanner=data.get("scanner", ""),
            remediation=data.get("remediation"),
            references=data.get("references", []),
            metadata=data.get("metadata", {}),
            auto_fixable=data.get("auto_fixable", False),
            fix_suggestion=data.get("fix_suggestion"),
        )


@dataclass
class ScanResult:
    """Result of a scan operation."""
    scanner_name: str
    scan_type: str
    target_path: str
    issues: List[Issue] = field(default_factory=list)
    scan_duration_ms: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    success: bool = True
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def issue_count(self) -> int:
        """Get total number of issues."""
        return len(self.issues)

    @property
    def critical_count(self) -> int:
        """Get count of critical issues."""
        return len([i for i in self.issues if i.severity == Severity.CRITICAL])

    @property
    def high_count(self) -> int:
        """Get count of high severity issues."""
        return len([i for i in self.issues if i.severity == Severity.HIGH])

    @property
    def medium_count(self) -> int:
        """Get count of medium severity issues."""
        return len([i for i in self.issues if i.severity == Severity.MEDIUM])

    @property
    def low_count(self) -> int:
        """Get count of low severity issues."""
        return len([i for i in self.issues if i.severity == Severity.LOW])

    @property
    def info_count(self) -> int:
        """Get count of info severity issues."""
        return len([i for i in self.issues if i.severity == Severity.INFO])

    def get_issues_by_severity(self, severity: Severity) -> List[Issue]:
        """Get all issues of a specific severity."""
        return [i for i in self.issues if i.severity == severity]

    def get_issues_by_category(self, category: IssueCategory) -> List[Issue]:
        """Get all issues of a specific category."""
        return [i for i in self.issues if i.category == category]

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "scanner_name": self.scanner_name,
            "scan_type": self.scan_type,
            "target_path": self.target_path,
            "issues": [i.to_dict() for i in self.issues],
            "issue_count": self.issue_count,
            "severity_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "scan_duration_ms": self.scan_duration_ms,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "success": self.success,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        """Create scan result from dictionary."""
        result = cls(
            scanner_name=data["scanner_name"],
            scan_type=data["scan_type"],
            target_path=data["target_path"],
            scan_duration_ms=data.get("scan_duration_ms", 0),
            success=data.get("success", True),
            error_message=data.get("error_message"),
            metadata=data.get("metadata", {}),
        )
        result.issues = [Issue.from_dict(i) for i in data.get("issues", [])]
        if data.get("started_at"):
            result.started_at = datetime.fromisoformat(data["started_at"])
        if data.get("completed_at"):
            result.completed_at = datetime.fromisoformat(data["completed_at"])
        return result


class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    def __init__(self, name: str, scan_type: str):
        """Initialize the scanner.

        Args:
            name: Name of the scanner
            scan_type: Type of scan (e.g., "security", "performance")
        """
        self.name = name
        self.scan_type = scan_type

    @abstractmethod
    async def scan(self, target_path: str | Path) -> ScanResult:
        """Perform the scan operation.

        Args:
            target_path: Path to scan

        Returns:
            ScanResult containing all issues found
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the scanner tool is available.

        Returns:
            True if the scanner can be used
        """
        pass

    def _create_result(
        self,
        target_path: str | Path,
        started_at: datetime,
    ) -> ScanResult:
        """Create a new scan result.

        Args:
            target_path: Path being scanned
            started_at: When the scan started

        Returns:
            New ScanResult instance
        """
        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target_path=str(target_path),
            started_at=started_at,
        )

    def _complete_result(
        self,
        result: ScanResult,
        started_at: datetime,
        success: bool = True,
        error_message: Optional[str] = None,
    ) -> ScanResult:
        """Complete a scan result with timing info.

        Args:
            result: The scan result to complete
            started_at: When the scan started
            success: Whether the scan succeeded
            error_message: Error message if failed

        Returns:
            Updated ScanResult
        """
        completed_at = datetime.now()
        result.completed_at = completed_at
        result.scan_duration_ms = int(
            (completed_at - started_at).total_seconds() * 1000
        )
        result.success = success
        result.error_message = error_message
        return result

    async def _run_command(
        self,
        command: List[str],
        timeout: int = 300,
        cwd: Optional[str] = None,
    ) -> tuple[int, str, str]:
        """Run a shell command asynchronously.

        Args:
            command: Command and arguments as list
            timeout: Timeout in seconds
            cwd: Working directory for the command

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )

            return (
                process.returncode or 0,
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
            )
        except asyncio.TimeoutError:
            if process:
                process.kill()
            return (-1, "", f"Command timed out after {timeout} seconds")
        except Exception as e:
            return (-1, "", str(e))

    def _check_tool_available(self, tool_name: str) -> bool:
        """Check if a command-line tool is available.

        Args:
            tool_name: Name of the tool to check

        Returns:
            True if tool is available
        """
        try:
            result = subprocess.run(
                ["which", tool_name],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _parse_json_output(self, output: str) -> Optional[Dict[str, Any]]:
        """Parse JSON output from a command.

        Args:
            output: JSON string to parse

        Returns:
            Parsed dictionary or None if parsing fails
        """
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return None
