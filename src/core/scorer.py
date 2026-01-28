"""Scorer Module - Calculates production readiness scores."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .scanner import Issue, IssueCategory, ScanResult, Severity


@dataclass
class CategoryScore:
    """Score for a specific category."""
    category: str
    score: float  # 0-100
    max_score: float = 100.0
    issues_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    weight: float = 1.0
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def grade(self) -> str:
        """Get letter grade for the score."""
        if self.score >= 90:
            return "A"
        elif self.score >= 80:
            return "B"
        elif self.score >= 70:
            return "C"
        elif self.score >= 60:
            return "D"
        else:
            return "F"

    @property
    def status(self) -> str:
        """Get status text for the score."""
        if self.score >= 90:
            return "Excellent"
        elif self.score >= 80:
            return "Good"
        elif self.score >= 70:
            return "Acceptable"
        elif self.score >= 60:
            return "Needs Improvement"
        else:
            return "Critical"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category": self.category,
            "score": round(self.score, 2),
            "max_score": self.max_score,
            "grade": self.grade,
            "status": self.status,
            "issues_count": self.issues_count,
            "severity_breakdown": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "weight": self.weight,
            "details": self.details,
        }


@dataclass
class Score:
    """Overall production readiness score."""
    overall_score: float  # 0-100
    category_scores: Dict[str, CategoryScore] = field(default_factory=dict)
    total_issues: int = 0
    blocking_issues: int = 0  # Critical + High
    is_production_ready: bool = False
    readiness_threshold: float = 70.0
    calculated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def grade(self) -> str:
        """Get letter grade for overall score."""
        if self.overall_score >= 90:
            return "A"
        elif self.overall_score >= 80:
            return "B"
        elif self.overall_score >= 70:
            return "C"
        elif self.overall_score >= 60:
            return "D"
        else:
            return "F"

    @property
    def status(self) -> str:
        """Get overall status text."""
        if self.is_production_ready:
            if self.overall_score >= 90:
                return "Production Ready - Excellent"
            elif self.overall_score >= 80:
                return "Production Ready - Good"
            else:
                return "Production Ready - Acceptable"
        else:
            if self.blocking_issues > 0:
                return f"Not Ready - {self.blocking_issues} Blocking Issues"
            else:
                return f"Not Ready - Score Below {self.readiness_threshold}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "overall_score": round(self.overall_score, 2),
            "grade": self.grade,
            "status": self.status,
            "is_production_ready": self.is_production_ready,
            "readiness_threshold": self.readiness_threshold,
            "total_issues": self.total_issues,
            "blocking_issues": self.blocking_issues,
            "category_scores": {
                k: v.to_dict() for k, v in self.category_scores.items()
            },
            "calculated_at": self.calculated_at.isoformat(),
            "metadata": self.metadata,
        }


class Scorer:
    """Calculates production readiness scores from scan results."""

    # Default weights for each category
    DEFAULT_WEIGHTS: Dict[str, float] = {
        "security": 0.35,
        "performance": 0.25,
        "reliability": 0.25,
        "monitoring": 0.15,
    }

    # Severity penalties (points deducted per issue)
    SEVERITY_PENALTIES: Dict[Severity, float] = {
        Severity.CRITICAL: 25.0,
        Severity.HIGH: 15.0,
        Severity.MEDIUM: 8.0,
        Severity.LOW: 3.0,
        Severity.INFO: 1.0,
    }

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        readiness_threshold: float = 70.0,
        block_on_critical: bool = True,
        block_on_high: bool = False,
        max_critical_allowed: int = 0,
        max_high_allowed: int = 3,
    ):
        """Initialize the scorer.

        Args:
            weights: Custom weights for categories (must sum to 1.0)
            readiness_threshold: Minimum score for production readiness
            block_on_critical: Block if any critical issues exist
            block_on_high: Block if any high severity issues exist
            max_critical_allowed: Maximum critical issues allowed
            max_high_allowed: Maximum high issues allowed for ready status
        """
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        self.readiness_threshold = readiness_threshold
        self.block_on_critical = block_on_critical
        self.block_on_high = block_on_high
        self.max_critical_allowed = max_critical_allowed
        self.max_high_allowed = max_high_allowed

        # Normalize weights to sum to 1.0
        total_weight = sum(self.weights.values())
        if total_weight > 0:
            self.weights = {k: v / total_weight for k, v in self.weights.items()}

    def calculate_score(self, scan_results: List[ScanResult]) -> Score:
        """Calculate overall score from scan results.

        Args:
            scan_results: List of scan results to score

        Returns:
            Score object with overall and category scores
        """
        # Aggregate issues by category
        issues_by_category: Dict[str, List[Issue]] = {}

        for result in scan_results:
            # Map scan type to category
            category = self._map_scan_type_to_category(result.scan_type)

            if category not in issues_by_category:
                issues_by_category[category] = []

            issues_by_category[category].extend(result.issues)

        # Calculate category scores
        category_scores: Dict[str, CategoryScore] = {}

        for category, weight in self.weights.items():
            issues = issues_by_category.get(category, [])
            category_score = self._calculate_category_score(
                category, issues, weight
            )
            category_scores[category] = category_score

        # Calculate overall score (weighted average)
        if category_scores:
            overall_score = sum(
                cs.score * cs.weight for cs in category_scores.values()
            )
        else:
            overall_score = 100.0  # No issues found

        # Count total and blocking issues
        total_issues = sum(cs.issues_count for cs in category_scores.values())
        blocking_issues = sum(
            cs.critical_count + cs.high_count for cs in category_scores.values()
        )

        # Determine production readiness
        is_ready = self._is_production_ready(
            overall_score, category_scores, blocking_issues
        )

        return Score(
            overall_score=overall_score,
            category_scores=category_scores,
            total_issues=total_issues,
            blocking_issues=blocking_issues,
            is_production_ready=is_ready,
            readiness_threshold=self.readiness_threshold,
            metadata={
                "weights": self.weights,
                "scan_count": len(scan_results),
            },
        )

    def _calculate_category_score(
        self,
        category: str,
        issues: List[Issue],
        weight: float,
    ) -> CategoryScore:
        """Calculate score for a specific category.

        Args:
            category: Category name
            issues: List of issues in this category
            weight: Weight of this category

        Returns:
            CategoryScore for the category
        """
        # Count issues by severity
        critical_count = len([i for i in issues if i.severity == Severity.CRITICAL])
        high_count = len([i for i in issues if i.severity == Severity.HIGH])
        medium_count = len([i for i in issues if i.severity == Severity.MEDIUM])
        low_count = len([i for i in issues if i.severity == Severity.LOW])
        info_count = len([i for i in issues if i.severity == Severity.INFO])

        # Calculate penalty
        penalty = (
            critical_count * self.SEVERITY_PENALTIES[Severity.CRITICAL]
            + high_count * self.SEVERITY_PENALTIES[Severity.HIGH]
            + medium_count * self.SEVERITY_PENALTIES[Severity.MEDIUM]
            + low_count * self.SEVERITY_PENALTIES[Severity.LOW]
            + info_count * self.SEVERITY_PENALTIES[Severity.INFO]
        )

        # Score is 100 minus penalties, minimum 0
        score = max(0.0, 100.0 - penalty)

        return CategoryScore(
            category=category,
            score=score,
            issues_count=len(issues),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
            weight=weight,
            details={
                "penalty_applied": penalty,
                "issues_analyzed": len(issues),
            },
        )

    def _is_production_ready(
        self,
        overall_score: float,
        category_scores: Dict[str, CategoryScore],
        blocking_issues: int,
    ) -> bool:
        """Determine if the application is production ready.

        Args:
            overall_score: Overall score
            category_scores: Scores by category
            blocking_issues: Count of critical + high issues

        Returns:
            True if production ready
        """
        # Check score threshold
        if overall_score < self.readiness_threshold:
            return False

        # Check critical issues
        total_critical = sum(cs.critical_count for cs in category_scores.values())
        if self.block_on_critical and total_critical > self.max_critical_allowed:
            return False

        # Check high severity issues
        total_high = sum(cs.high_count for cs in category_scores.values())
        if self.block_on_high and total_high > self.max_high_allowed:
            return False

        return True

    def _map_scan_type_to_category(self, scan_type: str) -> str:
        """Map scan type to category.

        Args:
            scan_type: Type of scan performed

        Returns:
            Category name
        """
        mapping = {
            "security": "security",
            "vulnerability": "security",
            "secrets": "security",
            "iac": "security",
            "performance": "performance",
            "resources": "performance",
            "reliability": "reliability",
            "availability": "reliability",
            "monitoring": "monitoring",
            "observability": "monitoring",
            "logging": "monitoring",
        }
        return mapping.get(scan_type.lower(), scan_type.lower())

    def get_improvement_suggestions(self, score: Score) -> List[Dict[str, Any]]:
        """Get prioritized suggestions for score improvement.

        Args:
            score: Current score

        Returns:
            List of improvement suggestions
        """
        suggestions = []

        # Sort categories by score (lowest first)
        sorted_categories = sorted(
            score.category_scores.items(),
            key=lambda x: x[1].score,
        )

        for category, cat_score in sorted_categories:
            if cat_score.score < 100:
                priority = "high" if cat_score.score < 60 else (
                    "medium" if cat_score.score < 80 else "low"
                )

                suggestion = {
                    "category": category,
                    "current_score": cat_score.score,
                    "priority": priority,
                    "blocking_issues": cat_score.critical_count + cat_score.high_count,
                    "potential_improvement": 100 - cat_score.score,
                    "focus_areas": [],
                }

                if cat_score.critical_count > 0:
                    suggestion["focus_areas"].append(
                        f"Fix {cat_score.critical_count} critical issues first"
                    )
                if cat_score.high_count > 0:
                    suggestion["focus_areas"].append(
                        f"Address {cat_score.high_count} high severity issues"
                    )
                if cat_score.medium_count > 0:
                    suggestion["focus_areas"].append(
                        f"Review {cat_score.medium_count} medium severity issues"
                    )

                suggestions.append(suggestion)

        return suggestions
