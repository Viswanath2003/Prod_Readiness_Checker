"""Local Storage Module - SQLite-based storage for scan results and metadata."""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from .models import IssueRecord, ProjectRecord, ScanRecord, TrendData


class LocalStorage:
    """Local storage manager using SQLite for scan results and metadata."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        data_dir: Optional[str] = None,
    ):
        """Initialize local storage.

        Args:
            db_path: Path to SQLite database file
            data_dir: Base directory for storing data (default: ~/.prc)
        """
        if data_dir:
            self.data_dir = Path(data_dir)
        else:
            self.data_dir = Path.home() / ".prc"

        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        self.reports_dir = self.data_dir / "reports"
        self.reports_dir.mkdir(exist_ok=True)

        self.cache_dir = self.data_dir / "cache"
        self.cache_dir.mkdir(exist_ok=True)

        self.metadata_dir = self.data_dir / "metadata"
        self.metadata_dir.mkdir(exist_ok=True)

        # Database path
        self.db_path = db_path or str(self.data_dir / "prc.db")

        # Initialize database
        self._init_database()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get a database connection.

        Yields:
            SQLite connection
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_database(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Projects table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL UNIQUE,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT DEFAULT '{}'
                )
            """)

            # Scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER,
                    scan_type TEXT NOT NULL,
                    scanner_name TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    overall_score REAL DEFAULT 0.0,
                    is_production_ready INTEGER DEFAULT 0,
                    total_issues INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    info_count INTEGER DEFAULT 0,
                    duration_ms INTEGER DEFAULT 0,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    success INTEGER DEFAULT 1,
                    error_message TEXT,
                    category_scores TEXT DEFAULT '{}',
                    metadata TEXT DEFAULT '{}',
                    report_path TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id)
                )
            """)

            # Issues table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS issues (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    issue_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    file_path TEXT,
                    line_number INTEGER,
                    rule_id TEXT,
                    scanner TEXT,
                    remediation TEXT,
                    ai_insights TEXT,
                    auto_fixable INTEGER DEFAULT 0,
                    fix_suggestion TEXT,
                    status TEXT DEFAULT 'open',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)

            # Trends table for tracking score history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS trends (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    date DATE NOT NULL,
                    overall_score REAL DEFAULT 0.0,
                    security_score REAL DEFAULT 0.0,
                    performance_score REAL DEFAULT 0.0,
                    reliability_score REAL DEFAULT 0.0,
                    monitoring_score REAL DEFAULT 0.0,
                    total_issues INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    FOREIGN KEY (project_id) REFERENCES projects(id),
                    UNIQUE(project_id, date)
                )
            """)

            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_issues_scan ON issues(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_issues_severity ON issues(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_trends_project ON trends(project_id)")

    # Project methods
    def create_project(self, project: ProjectRecord) -> ProjectRecord:
        """Create or update a project record.

        Args:
            project: Project to create/update

        Returns:
            Created/updated project with ID
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if project exists
            cursor.execute(
                "SELECT id FROM projects WHERE path = ?",
                (project.path,)
            )
            existing = cursor.fetchone()

            if existing:
                # Update existing
                cursor.execute("""
                    UPDATE projects SET
                        name = ?,
                        description = ?,
                        updated_at = ?,
                        metadata = ?
                    WHERE id = ?
                """, (
                    project.name,
                    project.description,
                    datetime.now().isoformat(),
                    json.dumps(project.metadata),
                    existing["id"],
                ))
                project.id = existing["id"]
            else:
                # Create new
                cursor.execute("""
                    INSERT INTO projects (name, path, description, metadata)
                    VALUES (?, ?, ?, ?)
                """, (
                    project.name,
                    project.path,
                    project.description,
                    json.dumps(project.metadata),
                ))
                project.id = cursor.lastrowid

        return project

    def get_project(self, project_id: int) -> Optional[ProjectRecord]:
        """Get a project by ID.

        Args:
            project_id: Project ID

        Returns:
            Project record or None
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
            row = cursor.fetchone()

            if row:
                return self._row_to_project(row)
            return None

    def get_project_by_path(self, path: str) -> Optional[ProjectRecord]:
        """Get a project by path.

        Args:
            path: Project path

        Returns:
            Project record or None
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM projects WHERE path = ?", (path,))
            row = cursor.fetchone()

            if row:
                return self._row_to_project(row)
            return None

    def list_projects(self) -> List[ProjectRecord]:
        """List all projects.

        Returns:
            List of project records
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM projects ORDER BY updated_at DESC")
            rows = cursor.fetchall()
            return [self._row_to_project(row) for row in rows]

    # Scan methods
    def save_scan(self, scan: ScanRecord) -> ScanRecord:
        """Save a scan record.

        Args:
            scan: Scan record to save

        Returns:
            Saved scan with ID
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO scans (
                    project_id, scan_type, scanner_name, target_path,
                    overall_score, is_production_ready, total_issues,
                    critical_count, high_count, medium_count, low_count, info_count,
                    duration_ms, started_at, completed_at, success, error_message,
                    category_scores, metadata, report_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan.project_id,
                scan.scan_type,
                scan.scanner_name,
                scan.target_path,
                scan.overall_score,
                1 if scan.is_production_ready else 0,
                scan.total_issues,
                scan.critical_count,
                scan.high_count,
                scan.medium_count,
                scan.low_count,
                scan.info_count,
                scan.duration_ms,
                scan.started_at.isoformat(),
                scan.completed_at.isoformat() if scan.completed_at else None,
                1 if scan.success else 0,
                scan.error_message,
                json.dumps(scan.category_scores),
                json.dumps(scan.metadata),
                scan.report_path,
            ))

            scan.id = cursor.lastrowid

        return scan

    def get_scan(self, scan_id: int) -> Optional[ScanRecord]:
        """Get a scan by ID.

        Args:
            scan_id: Scan ID

        Returns:
            Scan record or None
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()

            if row:
                return self._row_to_scan(row)
            return None

    def get_scans_for_project(
        self,
        project_id: int,
        limit: int = 50,
    ) -> List[ScanRecord]:
        """Get scans for a project.

        Args:
            project_id: Project ID
            limit: Maximum number of scans to return

        Returns:
            List of scan records
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scans
                WHERE project_id = ?
                ORDER BY started_at DESC
                LIMIT ?
            """, (project_id, limit))
            rows = cursor.fetchall()
            return [self._row_to_scan(row) for row in rows]

    def get_latest_scan(self, project_id: int) -> Optional[ScanRecord]:
        """Get the latest scan for a project.

        Args:
            project_id: Project ID

        Returns:
            Latest scan record or None
        """
        scans = self.get_scans_for_project(project_id, limit=1)
        return scans[0] if scans else None

    # Issue methods
    def save_issues(self, issues: List[IssueRecord]) -> List[IssueRecord]:
        """Save multiple issue records.

        Args:
            issues: List of issues to save

        Returns:
            Saved issues with IDs
        """
        if not issues:
            return []

        with self._get_connection() as conn:
            cursor = conn.cursor()

            for issue in issues:
                cursor.execute("""
                    INSERT INTO issues (
                        scan_id, issue_id, title, description, severity, category,
                        file_path, line_number, rule_id, scanner, remediation,
                        ai_insights, auto_fixable, fix_suggestion, status, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    issue.scan_id,
                    issue.issue_id,
                    issue.title,
                    issue.description,
                    issue.severity,
                    issue.category,
                    issue.file_path,
                    issue.line_number,
                    issue.rule_id,
                    issue.scanner,
                    issue.remediation,
                    issue.ai_insights,
                    1 if issue.auto_fixable else 0,
                    issue.fix_suggestion,
                    issue.status,
                    json.dumps(issue.metadata),
                ))
                issue.id = cursor.lastrowid

        return issues

    def get_issues_for_scan(self, scan_id: int) -> List[IssueRecord]:
        """Get all issues for a scan.

        Args:
            scan_id: Scan ID

        Returns:
            List of issue records
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM issues
                WHERE scan_id = ?
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END
            """, (scan_id,))
            rows = cursor.fetchall()
            return [self._row_to_issue(row) for row in rows]

    def update_issue_status(
        self,
        issue_id: int,
        status: str,
    ) -> bool:
        """Update an issue's status.

        Args:
            issue_id: Issue ID
            status: New status

        Returns:
            True if updated successfully
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE issues SET
                    status = ?,
                    updated_at = ?
                WHERE id = ?
            """, (status, datetime.now().isoformat(), issue_id))
            return cursor.rowcount > 0

    def update_issue_ai_insights(
        self,
        issue_id: int,
        ai_insights: str,
    ) -> bool:
        """Update an issue's AI insights.

        Args:
            issue_id: Issue ID
            ai_insights: AI-generated insights

        Returns:
            True if updated successfully
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE issues SET
                    ai_insights = ?,
                    updated_at = ?
                WHERE id = ?
            """, (ai_insights, datetime.now().isoformat(), issue_id))
            return cursor.rowcount > 0

    # Trend methods
    def save_trend(self, trend: TrendData) -> None:
        """Save trend data.

        Args:
            trend: Trend data to save
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO trends (
                    project_id, date, overall_score, security_score,
                    performance_score, reliability_score, monitoring_score,
                    total_issues, critical_count, high_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                trend.project_id,
                trend.date.date().isoformat(),
                trend.overall_score,
                trend.security_score,
                trend.performance_score,
                trend.reliability_score,
                trend.monitoring_score,
                trend.total_issues,
                trend.critical_count,
                trend.high_count,
            ))

    def get_trends(
        self,
        project_id: int,
        days: int = 30,
    ) -> List[TrendData]:
        """Get trend data for a project.

        Args:
            project_id: Project ID
            days: Number of days to include

        Returns:
            List of trend data
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            start_date = (datetime.now() - timedelta(days=days)).date().isoformat()

            cursor.execute("""
                SELECT * FROM trends
                WHERE project_id = ? AND date >= ?
                ORDER BY date ASC
            """, (project_id, start_date))

            rows = cursor.fetchall()
            return [self._row_to_trend(row) for row in rows]

    # Report storage methods
    def save_report_file(
        self,
        scan_id: int,
        content: bytes,
        format: str,
    ) -> str:
        """Save a report file.

        Args:
            scan_id: Associated scan ID
            content: Report content
            format: Report format (json, html, pdf)

        Returns:
            Path to saved report
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{scan_id}_{timestamp}.{format}"
        report_path = self.reports_dir / filename

        with open(report_path, "wb") as f:
            f.write(content)

        # Update scan record with report path
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE scans SET report_path = ? WHERE id = ?",
                (str(report_path), scan_id)
            )

        return str(report_path)

    def get_report_path(self, scan_id: int) -> Optional[str]:
        """Get report path for a scan.

        Args:
            scan_id: Scan ID

        Returns:
            Report path or None
        """
        scan = self.get_scan(scan_id)
        return scan.report_path if scan else None

    # Statistics methods
    def get_project_statistics(self, project_id: int) -> Dict[str, Any]:
        """Get statistics for a project.

        Args:
            project_id: Project ID

        Returns:
            Statistics dictionary
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Get scan count
            cursor.execute(
                "SELECT COUNT(*) as count FROM scans WHERE project_id = ?",
                (project_id,)
            )
            scan_count = cursor.fetchone()["count"]

            # Get latest scan
            cursor.execute("""
                SELECT overall_score, is_production_ready, total_issues,
                       critical_count, high_count, started_at
                FROM scans
                WHERE project_id = ?
                ORDER BY started_at DESC
                LIMIT 1
            """, (project_id,))
            latest = cursor.fetchone()

            # Get average score over last 30 days
            cursor.execute("""
                SELECT AVG(overall_score) as avg_score
                FROM scans
                WHERE project_id = ?
                AND started_at >= date('now', '-30 days')
            """, (project_id,))
            avg_score = cursor.fetchone()["avg_score"] or 0

            # Get trend (comparing with 7 days ago)
            cursor.execute("""
                SELECT overall_score FROM trends
                WHERE project_id = ?
                ORDER BY date DESC
                LIMIT 2
            """, (project_id,))
            trend_rows = cursor.fetchall()

            trend = 0
            if len(trend_rows) >= 2:
                trend = trend_rows[0]["overall_score"] - trend_rows[1]["overall_score"]

            return {
                "scan_count": scan_count,
                "latest_score": latest["overall_score"] if latest else 0,
                "is_production_ready": bool(latest["is_production_ready"]) if latest else False,
                "latest_issues": latest["total_issues"] if latest else 0,
                "latest_critical": latest["critical_count"] if latest else 0,
                "latest_high": latest["high_count"] if latest else 0,
                "average_score_30d": round(avg_score, 2),
                "score_trend": round(trend, 2),
                "last_scan": latest["started_at"] if latest else None,
            }

    # Helper methods
    def _row_to_project(self, row: sqlite3.Row) -> ProjectRecord:
        """Convert database row to ProjectRecord."""
        return ProjectRecord(
            id=row["id"],
            name=row["name"],
            path=row["path"],
            description=row["description"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(),
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else datetime.now(),
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )

    def _row_to_scan(self, row: sqlite3.Row) -> ScanRecord:
        """Convert database row to ScanRecord."""
        return ScanRecord(
            id=row["id"],
            project_id=row["project_id"],
            scan_type=row["scan_type"],
            scanner_name=row["scanner_name"],
            target_path=row["target_path"],
            overall_score=row["overall_score"],
            is_production_ready=bool(row["is_production_ready"]),
            total_issues=row["total_issues"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            medium_count=row["medium_count"],
            low_count=row["low_count"],
            info_count=row["info_count"],
            duration_ms=row["duration_ms"],
            started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else datetime.now(),
            completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
            success=bool(row["success"]),
            error_message=row["error_message"],
            category_scores=json.loads(row["category_scores"]) if row["category_scores"] else {},
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            report_path=row["report_path"],
        )

    def _row_to_issue(self, row: sqlite3.Row) -> IssueRecord:
        """Convert database row to IssueRecord."""
        return IssueRecord(
            id=row["id"],
            scan_id=row["scan_id"],
            issue_id=row["issue_id"],
            title=row["title"],
            description=row["description"],
            severity=row["severity"],
            category=row["category"],
            file_path=row["file_path"],
            line_number=row["line_number"],
            rule_id=row["rule_id"],
            scanner=row["scanner"],
            remediation=row["remediation"],
            ai_insights=row["ai_insights"],
            auto_fixable=bool(row["auto_fixable"]),
            fix_suggestion=row["fix_suggestion"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(),
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else datetime.now(),
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )

    def _row_to_trend(self, row: sqlite3.Row) -> TrendData:
        """Convert database row to TrendData."""
        return TrendData(
            project_id=row["project_id"],
            date=datetime.fromisoformat(row["date"]),
            overall_score=row["overall_score"],
            security_score=row["security_score"],
            performance_score=row["performance_score"],
            reliability_score=row["reliability_score"],
            monitoring_score=row["monitoring_score"],
            total_issues=row["total_issues"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
        )
