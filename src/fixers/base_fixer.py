"""Base Fixer Module - Abstract base class for automated fix generators."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.scanner import Issue


class FixStatus(Enum):
    """Status of a fix application."""
    PENDING = "pending"
    APPLIED = "applied"
    FAILED = "failed"
    SKIPPED = "skipped"
    REQUIRES_REVIEW = "requires_review"


@dataclass
class Fix:
    """Represents a proposed fix for an issue."""
    issue_id: str
    file_path: str
    description: str
    original_content: str
    fixed_content: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    confidence: float = 1.0  # 0.0 to 1.0
    requires_review: bool = False
    review_notes: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "issue_id": self.issue_id,
            "file_path": self.file_path,
            "description": self.description,
            "original_content": self.original_content,
            "fixed_content": self.fixed_content,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "confidence": self.confidence,
            "requires_review": self.requires_review,
            "review_notes": self.review_notes,
            "metadata": self.metadata,
        }

    def get_diff(self) -> str:
        """Get a simple diff representation."""
        original_lines = self.original_content.splitlines()
        fixed_lines = self.fixed_content.splitlines()

        diff_lines = []
        diff_lines.append(f"--- {self.file_path} (original)")
        diff_lines.append(f"+++ {self.file_path} (fixed)")

        # Simple line-by-line diff
        max_lines = max(len(original_lines), len(fixed_lines))
        for i in range(max_lines):
            orig = original_lines[i] if i < len(original_lines) else ""
            fixed = fixed_lines[i] if i < len(fixed_lines) else ""

            if orig != fixed:
                if orig:
                    diff_lines.append(f"- {orig}")
                if fixed:
                    diff_lines.append(f"+ {fixed}")
            else:
                diff_lines.append(f"  {orig}")

        return "\n".join(diff_lines)


@dataclass
class FixResult:
    """Result of applying a fix."""
    fix: Fix
    status: FixStatus
    applied_at: Optional[datetime] = None
    error_message: Optional[str] = None
    backup_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "fix": self.fix.to_dict(),
            "status": self.status.value,
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
            "error_message": self.error_message,
            "backup_path": self.backup_path,
        }


class BaseFixer(ABC):
    """Abstract base class for automated fix generators."""

    def __init__(self, backup_dir: Optional[str] = None):
        """Initialize the fixer.

        Args:
            backup_dir: Directory for backup files (default: .prc_backups)
        """
        self.backup_dir = Path(backup_dir) if backup_dir else Path(".prc_backups")

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the fixer."""
        pass

    @property
    @abstractmethod
    def supported_rules(self) -> List[str]:
        """List of rule IDs this fixer can handle."""
        pass

    def can_fix(self, issue: Issue) -> bool:
        """Check if this fixer can handle the given issue.

        Args:
            issue: Issue to check

        Returns:
            True if the fixer can handle this issue
        """
        if not issue.rule_id:
            return False

        # Check if rule is in supported list
        for pattern in self.supported_rules:
            if pattern.endswith("*"):
                if issue.rule_id.startswith(pattern[:-1]):
                    return True
            elif issue.rule_id == pattern:
                return True

        return False

    @abstractmethod
    def generate_fix(self, issue: Issue) -> Optional[Fix]:
        """Generate a fix for the given issue.

        Args:
            issue: Issue to fix

        Returns:
            Fix object or None if no fix can be generated
        """
        pass

    def apply_fix(self, fix: Fix, dry_run: bool = False) -> FixResult:
        """Apply a fix to the file.

        Args:
            fix: Fix to apply
            dry_run: If True, don't actually modify the file

        Returns:
            FixResult with status
        """
        file_path = Path(fix.file_path)

        # Check if file exists
        if not file_path.exists():
            return FixResult(
                fix=fix,
                status=FixStatus.FAILED,
                error_message=f"File not found: {file_path}",
            )

        try:
            # Read current content
            current_content = file_path.read_text()

            # Verify original content matches
            if fix.original_content not in current_content:
                return FixResult(
                    fix=fix,
                    status=FixStatus.FAILED,
                    error_message="Original content not found in file (may have been modified)",
                )

            if dry_run:
                return FixResult(
                    fix=fix,
                    status=FixStatus.PENDING,
                )

            # Create backup
            backup_path = self._create_backup(file_path)

            # Apply fix
            new_content = current_content.replace(
                fix.original_content,
                fix.fixed_content,
                1,  # Only replace first occurrence
            )

            file_path.write_text(new_content)

            return FixResult(
                fix=fix,
                status=FixStatus.APPLIED,
                applied_at=datetime.now(),
                backup_path=backup_path,
            )

        except Exception as e:
            return FixResult(
                fix=fix,
                status=FixStatus.FAILED,
                error_message=str(e),
            )

    def _create_backup(self, file_path: Path) -> str:
        """Create a backup of the file.

        Args:
            file_path: Path to the file

        Returns:
            Path to the backup file
        """
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{file_path.name}.{timestamp}.bak"
        backup_path = self.backup_dir / backup_name

        backup_path.write_text(file_path.read_text())

        return str(backup_path)

    def rollback(self, result: FixResult) -> bool:
        """Rollback an applied fix.

        Args:
            result: FixResult containing backup information

        Returns:
            True if rollback successful
        """
        if result.status != FixStatus.APPLIED:
            return False

        if not result.backup_path:
            return False

        backup_path = Path(result.backup_path)
        if not backup_path.exists():
            return False

        try:
            file_path = Path(result.fix.file_path)
            file_path.write_text(backup_path.read_text())
            return True
        except Exception:
            return False

    def _read_file_content(self, file_path: str) -> Optional[str]:
        """Read content from a file.

        Args:
            file_path: Path to the file

        Returns:
            File content or None if read fails
        """
        try:
            return Path(file_path).read_text()
        except Exception:
            return None

    def _get_lines(
        self,
        content: str,
        start_line: int,
        end_line: Optional[int] = None,
    ) -> str:
        """Get specific lines from content.

        Args:
            content: File content
            start_line: Starting line number (1-indexed)
            end_line: Ending line number (inclusive, 1-indexed)

        Returns:
            Extracted lines
        """
        lines = content.splitlines()
        start_idx = start_line - 1

        if end_line:
            end_idx = end_line
            return "\n".join(lines[start_idx:end_idx])
        else:
            return lines[start_idx] if start_idx < len(lines) else ""
