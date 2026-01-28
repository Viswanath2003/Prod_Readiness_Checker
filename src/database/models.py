"""Database models for local storage."""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ProjectRecord:
    """Record representing a scanned project."""
    id: Optional[int] = None
    name: str = ""
    path: str = ""
    description: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "path": self.path,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProjectRecord":
        """Create from dictionary."""
        return cls(
            id=data.get("id"),
            name=data.get("name", ""),
            path=data.get("path", ""),
            description=data.get("description"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.now(),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ScanRecord:
    """Record representing a scan execution."""
    id: Optional[int] = None
    project_id: Optional[int] = None
    scan_type: str = ""
    scanner_name: str = ""
    target_path: str = ""
    overall_score: float = 0.0
    is_production_ready: bool = False
    total_issues: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    duration_ms: int = 0
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    success: bool = True
    error_message: Optional[str] = None
    category_scores: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    report_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "scan_type": self.scan_type,
            "scanner_name": self.scanner_name,
            "target_path": self.target_path,
            "overall_score": self.overall_score,
            "is_production_ready": self.is_production_ready,
            "total_issues": self.total_issues,
            "severity_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "duration_ms": self.duration_ms,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "success": self.success,
            "error_message": self.error_message,
            "category_scores": self.category_scores,
            "metadata": self.metadata,
            "report_path": self.report_path,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanRecord":
        """Create from dictionary."""
        severity = data.get("severity_counts", {})
        return cls(
            id=data.get("id"),
            project_id=data.get("project_id"),
            scan_type=data.get("scan_type", ""),
            scanner_name=data.get("scanner_name", ""),
            target_path=data.get("target_path", ""),
            overall_score=data.get("overall_score", 0.0),
            is_production_ready=data.get("is_production_ready", False),
            total_issues=data.get("total_issues", 0),
            critical_count=severity.get("critical", 0),
            high_count=severity.get("high", 0),
            medium_count=severity.get("medium", 0),
            low_count=severity.get("low", 0),
            info_count=severity.get("info", 0),
            duration_ms=data.get("duration_ms", 0),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else datetime.now(),
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            success=data.get("success", True),
            error_message=data.get("error_message"),
            category_scores=data.get("category_scores", {}),
            metadata=data.get("metadata", {}),
            report_path=data.get("report_path"),
        )


@dataclass
class IssueRecord:
    """Record representing a single issue found during scanning."""
    id: Optional[int] = None
    scan_id: Optional[int] = None
    issue_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = ""
    category: str = ""
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    rule_id: Optional[str] = None
    scanner: str = ""
    remediation: Optional[str] = None
    ai_insights: Optional[str] = None
    auto_fixable: bool = False
    fix_suggestion: Optional[str] = None
    status: str = "open"  # open, acknowledged, fixed, ignored
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "issue_id": self.issue_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "rule_id": self.rule_id,
            "scanner": self.scanner,
            "remediation": self.remediation,
            "ai_insights": self.ai_insights,
            "auto_fixable": self.auto_fixable,
            "fix_suggestion": self.fix_suggestion,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IssueRecord":
        """Create from dictionary."""
        return cls(
            id=data.get("id"),
            scan_id=data.get("scan_id"),
            issue_id=data.get("issue_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=data.get("severity", ""),
            category=data.get("category", ""),
            file_path=data.get("file_path"),
            line_number=data.get("line_number"),
            rule_id=data.get("rule_id"),
            scanner=data.get("scanner", ""),
            remediation=data.get("remediation"),
            ai_insights=data.get("ai_insights"),
            auto_fixable=data.get("auto_fixable", False),
            fix_suggestion=data.get("fix_suggestion"),
            status=data.get("status", "open"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.now(),
            metadata=data.get("metadata", {}),
        )


@dataclass
class TrendData:
    """Data for tracking score trends over time."""
    project_id: int
    date: datetime
    overall_score: float
    security_score: float = 0.0
    performance_score: float = 0.0
    reliability_score: float = 0.0
    monitoring_score: float = 0.0
    total_issues: int = 0
    critical_count: int = 0
    high_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "project_id": self.project_id,
            "date": self.date.isoformat(),
            "overall_score": self.overall_score,
            "category_scores": {
                "security": self.security_score,
                "performance": self.performance_score,
                "reliability": self.reliability_score,
                "monitoring": self.monitoring_score,
            },
            "total_issues": self.total_issues,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
        }
