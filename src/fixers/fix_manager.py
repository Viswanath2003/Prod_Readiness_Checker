"""Fix Manager Module - Orchestrates automated fix generation and application."""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base_fixer import BaseFixer, Fix, FixResult, FixStatus
from .dockerfile_fixer import DockerfileFixer
from .kubernetes_fixer import KubernetesFixer
from .config_fixer import ConfigFixer
from ..core.scanner import Issue, ScanResult


class FixManager:
    """Manages automated fix generation and application across all fixers."""

    def __init__(self, backup_dir: Optional[str] = None):
        """Initialize the fix manager.

        Args:
            backup_dir: Directory for backup files
        """
        self.backup_dir = Path(backup_dir) if backup_dir else Path(".prc_backups")

        # Initialize fixers
        self.fixers: List[BaseFixer] = [
            DockerfileFixer(str(self.backup_dir)),
            KubernetesFixer(str(self.backup_dir)),
            ConfigFixer(str(self.backup_dir)),
        ]

        # Registry of generated fixes
        self.generated_fixes: Dict[str, Fix] = {}
        self.applied_results: Dict[str, FixResult] = {}

    def get_available_fixers(self) -> List[str]:
        """Get list of available fixer names.

        Returns:
            List of fixer names
        """
        return [f.name for f in self.fixers]

    def can_fix(self, issue: Issue) -> bool:
        """Check if any fixer can handle the given issue.

        Args:
            issue: Issue to check

        Returns:
            True if a fixer is available
        """
        return any(fixer.can_fix(issue) for fixer in self.fixers)

    def get_fixer_for_issue(self, issue: Issue) -> Optional[BaseFixer]:
        """Get the appropriate fixer for an issue.

        Args:
            issue: Issue to fix

        Returns:
            Fixer instance or None
        """
        for fixer in self.fixers:
            if fixer.can_fix(issue):
                return fixer
        return None

    def generate_fix(self, issue: Issue) -> Optional[Fix]:
        """Generate a fix for a single issue.

        Args:
            issue: Issue to fix

        Returns:
            Fix object or None
        """
        fixer = self.get_fixer_for_issue(issue)
        if not fixer:
            return None

        fix = fixer.generate_fix(issue)
        if fix:
            self.generated_fixes[issue.id] = fix

        return fix

    def generate_fixes_for_results(
        self,
        scan_results: List[ScanResult],
        auto_fixable_only: bool = True,
    ) -> List[Tuple[Issue, Optional[Fix]]]:
        """Generate fixes for all issues in scan results.

        Args:
            scan_results: List of scan results
            auto_fixable_only: Only generate fixes for auto-fixable issues

        Returns:
            List of (issue, fix) tuples
        """
        results = []

        for scan_result in scan_results:
            for issue in scan_result.issues:
                if auto_fixable_only and not issue.auto_fixable:
                    continue

                fix = self.generate_fix(issue)
                results.append((issue, fix))

        return results

    def preview_fixes(
        self,
        scan_results: List[ScanResult],
    ) -> List[Dict[str, Any]]:
        """Preview all available fixes without applying them.

        Args:
            scan_results: List of scan results

        Returns:
            List of fix preview dictionaries
        """
        previews = []

        for scan_result in scan_results:
            for issue in scan_result.issues:
                if not self.can_fix(issue):
                    continue

                fix = self.generate_fix(issue)
                if fix:
                    preview = {
                        "issue_id": issue.id,
                        "issue_title": issue.title,
                        "severity": issue.severity.value,
                        "file": issue.file_path,
                        "line": issue.line_number,
                        "fix_description": fix.description,
                        "confidence": fix.confidence,
                        "requires_review": fix.requires_review,
                        "review_notes": fix.review_notes,
                        "diff": fix.get_diff() if fix.original_content else None,
                    }
                    previews.append(preview)

        return previews

    def apply_fix(
        self,
        issue_id: str,
        dry_run: bool = False,
    ) -> Optional[FixResult]:
        """Apply a previously generated fix.

        Args:
            issue_id: ID of the issue to fix
            dry_run: If True, don't actually modify files

        Returns:
            FixResult or None if fix not found
        """
        fix = self.generated_fixes.get(issue_id)
        if not fix:
            return None

        # Find the appropriate fixer
        fixer = None
        for f in self.fixers:
            if f.can_fix(type("Issue", (), {"rule_id": fix.metadata.get("rule_id", ""), "file_path": fix.file_path})()):
                fixer = f
                break

        if not fixer:
            fixer = self.fixers[0]  # Use first fixer as fallback

        result = fixer.apply_fix(fix, dry_run=dry_run)
        self.applied_results[issue_id] = result

        return result

    def apply_all_fixes(
        self,
        confidence_threshold: float = 0.8,
        skip_review_required: bool = True,
        dry_run: bool = False,
    ) -> List[FixResult]:
        """Apply all generated fixes that meet criteria.

        Args:
            confidence_threshold: Minimum confidence level
            skip_review_required: Skip fixes that require review
            dry_run: If True, don't actually modify files

        Returns:
            List of FixResult objects
        """
        results = []

        for issue_id, fix in self.generated_fixes.items():
            # Skip if already applied
            if issue_id in self.applied_results:
                continue

            # Check confidence
            if fix.confidence < confidence_threshold:
                continue

            # Check review requirement
            if skip_review_required and fix.requires_review:
                continue

            result = self.apply_fix(issue_id, dry_run=dry_run)
            if result:
                results.append(result)

        return results

    def rollback_fix(self, issue_id: str) -> bool:
        """Rollback a previously applied fix.

        Args:
            issue_id: ID of the issue to rollback

        Returns:
            True if rollback successful
        """
        result = self.applied_results.get(issue_id)
        if not result:
            return False

        # Find the fixer
        for fixer in self.fixers:
            if fixer.rollback(result):
                # Update result status
                result.status = FixStatus.PENDING
                return True

        return False

    def rollback_all(self) -> int:
        """Rollback all applied fixes.

        Returns:
            Number of successful rollbacks
        """
        count = 0
        for issue_id in list(self.applied_results.keys()):
            if self.rollback_fix(issue_id):
                count += 1
        return count

    def get_fix_summary(self) -> Dict[str, Any]:
        """Get summary of fixes.

        Returns:
            Summary dictionary
        """
        total_generated = len(self.generated_fixes)
        total_applied = len([r for r in self.applied_results.values() if r.status == FixStatus.APPLIED])
        total_failed = len([r for r in self.applied_results.values() if r.status == FixStatus.FAILED])
        review_required = len([f for f in self.generated_fixes.values() if f.requires_review])

        # Group by confidence
        high_confidence = len([f for f in self.generated_fixes.values() if f.confidence >= 0.9])
        medium_confidence = len([f for f in self.generated_fixes.values() if 0.7 <= f.confidence < 0.9])
        low_confidence = len([f for f in self.generated_fixes.values() if f.confidence < 0.7])

        return {
            "total_fixes_generated": total_generated,
            "total_applied": total_applied,
            "total_failed": total_failed,
            "pending": total_generated - total_applied - total_failed,
            "review_required": review_required,
            "confidence_breakdown": {
                "high": high_confidence,
                "medium": medium_confidence,
                "low": low_confidence,
            },
        }

    def export_fixes(self, output_path: str) -> str:
        """Export fixes to a JSON file.

        Args:
            output_path: Path to output file

        Returns:
            Path to the exported file
        """
        import json

        export_data = {
            "generated_at": datetime.now().isoformat(),
            "summary": self.get_fix_summary(),
            "fixes": [
                {
                    "issue_id": issue_id,
                    "fix": fix.to_dict(),
                    "status": self.applied_results.get(issue_id, FixResult(fix, FixStatus.PENDING)).status.value,
                }
                for issue_id, fix in self.generated_fixes.items()
            ],
        }

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2)

        return str(output_path)
