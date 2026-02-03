"""Issue Processor Module - Normalize, classify, group, and aggregate issues."""

import asyncio
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from .scanner import Issue, IssueCategory, ScanResult, Severity
from ..api.ai_provider import (
    AIProvider,
    BaseAIProvider,
    get_provider,
    get_available_provider,
)

# Import token tracker
try:
    from ..utils.token_tracker import GlobalTokenTracker
except ImportError:
    class GlobalTokenTracker:
        @classmethod
        def get_tracker(cls):
            return None


# Dimension constants
DIMENSION_SECURITY = "security"
DIMENSION_PERFORMANCE = "performance"
DIMENSION_RELIABILITY = "reliability"
DIMENSION_MONITORING = "monitoring"

ALL_DIMENSIONS = [DIMENSION_SECURITY, DIMENSION_PERFORMANCE, DIMENSION_RELIABILITY, DIMENSION_MONITORING]


@dataclass
class NormalizedIssue:
    """Normalized issue with consistent format across all scanners."""
    original_issue: Issue
    normalized_title: str
    normalized_description: str
    dimension: str  # security, performance, reliability, monitoring
    problem_key: str  # Canonical key like "cpu_limits_missing"
    file_path: str
    scanner_source: str
    severity: Severity
    rule_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "normalized_title": self.normalized_title,
            "normalized_description": self.normalized_description,
            "dimension": self.dimension,
            "problem_key": self.problem_key,
            "file_path": self.file_path,
            "scanner_source": self.scanner_source,
            "severity": self.severity.value,
            "rule_id": self.rule_id,
        }


@dataclass
class UniqueProblem:
    """Represents a unique problem type aggregated from multiple issues."""
    problem_key: str
    dimension: str
    title: str
    description: str
    final_severity: Severity
    occurrence_count: int
    affected_files: List[str]
    original_issues: List[NormalizedIssue]
    explanation: str = ""
    recommendation: str = ""
    rule_ids: List[str] = field(default_factory=list)
    scanners: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "problem_key": self.problem_key,
            "dimension": self.dimension,
            "title": self.title,
            "description": self.description,
            "final_severity": self.final_severity.value,
            "occurrence_count": self.occurrence_count,
            "affected_files": self.affected_files,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "rule_ids": self.rule_ids,
            "scanners": self.scanners,
        }


@dataclass
class ProcessedResults:
    """Container for all processed results."""
    unique_problems: List[UniqueProblem]
    problems_by_dimension: Dict[str, List[UniqueProblem]]
    total_issues: int
    total_unique_problems: int
    dimension_summary: Dict[str, Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "unique_problems": [p.to_dict() for p in self.unique_problems],
            "problems_by_dimension": {
                dim: [p.to_dict() for p in problems]
                for dim, problems in self.problems_by_dimension.items()
            },
            "total_issues": self.total_issues,
            "total_unique_problems": self.total_unique_problems,
            "dimension_summary": self.dimension_summary,
        }


class IssueProcessor:
    """Process raw scanner issues into normalized, classified, and grouped problems.

    Uses AI-based classification for:
    - Dimension mapping (security, performance, reliability, monitoring)
    - Problem key generation (canonical identifiers)

    No hardcoded mappings - all classification is done by AI.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        use_ai_classification: bool = True,
        provider: Optional[Union[str, AIProvider]] = None,
    ):
        """Initialize the issue processor.

        Args:
            api_key: API key for AI provider (optional, uses env var if not provided)
            model: Model to use for AI classification (optional, uses provider default)
            use_ai_classification: Whether to use AI for classification
            provider: AI provider to use (openai, gemini, grok, anthropic, ollama)
        """
        self.use_ai_classification = use_ai_classification
        self.ai_provider: Optional[BaseAIProvider] = None

        if use_ai_classification:
            if provider:
                try:
                    self.ai_provider = get_provider(provider, api_key=api_key, model=model)
                except (ValueError, ImportError) as e:
                    print(f"Warning: Could not initialize provider {provider}: {e}")
            else:
                # Auto-detect available provider
                self.ai_provider = get_available_provider()

    def is_ai_available(self) -> bool:
        """Check if AI is available for classification."""
        return self.ai_provider is not None and self.ai_provider.is_available()

    async def process_scan_results(
        self,
        scan_results: List[ScanResult],
    ) -> ProcessedResults:
        """Process all scan results into grouped unique problems.

        Args:
            scan_results: List of scan results from all scanners

        Returns:
            ProcessedResults with unique problems grouped by dimension
        """
        # Step 1: Collect all issues
        all_issues: List[Issue] = []
        for result in scan_results:
            all_issues.extend(result.issues)

        if not all_issues:
            return ProcessedResults(
                unique_problems=[],
                problems_by_dimension={dim: [] for dim in ALL_DIMENSIONS},
                total_issues=0,
                total_unique_problems=0,
                dimension_summary={dim: {"count": 0, "severity_counts": {}} for dim in ALL_DIMENSIONS},
            )

        # Step 2: Normalize all issues (with placeholder dimension/key)
        normalized_issues = await self._normalize_issues(all_issues)

        # Step 3: AI-based dimension classification for ALL issues
        normalized_issues = await self._classify_dimensions(normalized_issues)

        # Step 4: AI-based problem key generation for ALL issues
        normalized_issues = await self._generate_problem_keys(normalized_issues)

        # Step 5: Group by problem key
        grouped = self._group_by_problem_key(normalized_issues)

        # Step 6: Aggregate severity and create UniqueProblem objects
        unique_problems = self._aggregate_to_unique_problems(grouped)

        # Step 7: Organize by dimension
        problems_by_dimension = self._organize_by_dimension(unique_problems)

        # Step 8: Generate dimension summary
        dimension_summary = self._generate_dimension_summary(problems_by_dimension)

        return ProcessedResults(
            unique_problems=unique_problems,
            problems_by_dimension=problems_by_dimension,
            total_issues=len(all_issues),
            total_unique_problems=len(unique_problems),
            dimension_summary=dimension_summary,
        )

    async def _normalize_issues(self, issues: List[Issue]) -> List[NormalizedIssue]:
        """Normalize all issues to consistent format.

        Args:
            issues: Raw issues from scanners

        Returns:
            List of normalized issues
        """
        normalized = []

        for issue in issues:
            # Clean and normalize title
            normalized_title = self._normalize_text(issue.title)

            # Clean and normalize description
            normalized_description = self._normalize_text(issue.description)

            # Placeholder dimension - will be set by AI
            dimension = "unknown"

            # Placeholder problem key - will be set by AI
            problem_key = self._generate_key_from_title(issue.title)

            normalized.append(NormalizedIssue(
                original_issue=issue,
                normalized_title=normalized_title,
                normalized_description=normalized_description,
                dimension=dimension,
                problem_key=problem_key,
                file_path=issue.file_path or "unknown",
                scanner_source=issue.scanner,
                severity=issue.severity,
                rule_id=issue.rule_id or issue.id,
            ))

        return normalized

    def _normalize_text(self, text: str) -> str:
        """Normalize text by cleaning whitespace and special characters."""
        if not text:
            return ""
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def _generate_key_from_title(self, title: str) -> str:
        """Generate a fallback problem key from issue title.

        Args:
            title: Issue title

        Returns:
            Generated problem key
        """
        if not title:
            return "unknown_issue"

        # Convert to lowercase and replace spaces/special chars with underscores
        key = title.lower()
        key = re.sub(r'[^a-z0-9]+', '_', key)
        key = re.sub(r'_+', '_', key)
        key = key.strip('_')

        # Truncate if too long
        if len(key) > 50:
            key = key[:50].rsplit('_', 1)[0]

        return key or "unknown_issue"

    async def _classify_dimensions(
        self,
        normalized_issues: List[NormalizedIssue],
    ) -> List[NormalizedIssue]:
        """Classify dimensions for ALL issues using AI.

        Args:
            normalized_issues: List of normalized issues

        Returns:
            Issues with AI-classified dimensions
        """
        if not self.use_ai_classification or not self.is_ai_available():
            # Fallback: use scanner category if available
            for issue in normalized_issues:
                issue.dimension = self._fallback_dimension(issue)
            return normalized_issues

        # ALL issues go through AI classification
        try:
            classifications = await self._batch_classify_dimensions(normalized_issues)
            for issue, dimension in zip(normalized_issues, classifications):
                if dimension in ALL_DIMENSIONS:
                    issue.dimension = dimension
                else:
                    issue.dimension = self._fallback_dimension(issue)
        except Exception as e:
            print(f"AI dimension classification failed, using fallback: {e}")
            for issue in normalized_issues:
                issue.dimension = self._fallback_dimension(issue)

        return normalized_issues

    def _fallback_dimension(self, issue: NormalizedIssue) -> str:
        """Fallback dimension based on scanner category when AI unavailable."""
        category_mapping = {
            IssueCategory.SECURITY: DIMENSION_SECURITY,
            IssueCategory.PERFORMANCE: DIMENSION_PERFORMANCE,
            IssueCategory.RELIABILITY: DIMENSION_RELIABILITY,
            IssueCategory.MONITORING: DIMENSION_MONITORING,
        }
        if issue.original_issue.category in category_mapping:
            return category_mapping[issue.original_issue.category]
        return DIMENSION_SECURITY  # Default fallback

    async def _batch_classify_dimensions(
        self,
        issues: List[NormalizedIssue],
    ) -> List[str]:
        """Batch classify dimensions using AI.

        Args:
            issues: Issues to classify

        Returns:
            List of dimension strings
        """
        if not issues:
            return []

        # Process in smaller batches to avoid timeouts (max 10 at a time)
        BATCH_SIZE = 10
        all_dimensions = [self._fallback_dimension(issue) for issue in issues]

        for batch_start in range(0, len(issues), BATCH_SIZE):
            batch_issues = issues[batch_start:batch_start + BATCH_SIZE]
            batch_dimensions = await self._classify_single_batch(batch_issues)

            # Update dimensions for this batch
            for i, dim in enumerate(batch_dimensions):
                if dim in ALL_DIMENSIONS:
                    all_dimensions[batch_start + i] = dim

        return all_dimensions

    async def _classify_single_batch(
        self,
        issues: List[NormalizedIssue],
    ) -> List[str]:
        """Classify a single batch of issues using AI."""
        # Prepare batch prompt with title context
        issues_data = []
        for i, issue in enumerate(issues):
            issues_data.append({
                "index": i,
                "title": issue.normalized_title[:100],
            })

        prompt = f"""Classify each infrastructure/DevOps issue into exactly ONE dimension based on its title:

- security: vulnerabilities, secrets, credentials, permissions, authentication, encryption, access control, privileged access, root user, capabilities
- performance: CPU limits, memory limits, resource requests, scaling, replicas, HPA, timeouts, caching, connection pools, rate limiting
- reliability: health checks, liveness probes, readiness probes, availability, redundancy, PDB, restart policies, circuit breakers, backups
- monitoring: logging, metrics, tracing, alerting, observability, dashboards

Issues to classify:
{json.dumps(issues_data)}

Respond with JSON array only: [{{"index": 0, "dimension": "security"}}]"""

        try:
            response = await asyncio.wait_for(
                self.ai_provider.complete(
                    messages=[
                        {"role": "system", "content": "You are a DevOps expert. Classify each issue into exactly one dimension based on what the issue is about. Respond with valid JSON array only."},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=500,
                    temperature=0.1,
                    json_mode=True,
                ),
                timeout=30.0
            )

            # Track token usage safely
            tracker = GlobalTokenTracker.get_tracker()
            if tracker and response.usage:
                prompt_tokens = response.usage.get('prompt_tokens', 0) if isinstance(response.usage, dict) else 0
                completion_tokens = response.usage.get('completion_tokens', 0) if isinstance(response.usage, dict) else 0
                tracker.add_usage(prompt_tokens, completion_tokens)

            content = response.content.strip()
            if content.startswith("```"):
                content = re.sub(r'^```\w*\n?', '', content)
                content = re.sub(r'\n?```$', '', content)

            results = json.loads(content)

            if not isinstance(results, list):
                return [self._fallback_dimension(issue) for issue in issues]

            dimensions = [self._fallback_dimension(issue) for issue in issues]
            for item in results:
                if not isinstance(item, dict):
                    continue
                idx = item.get("index")
                dim = item.get("dimension", "").lower() if isinstance(item.get("dimension"), str) else ""
                if idx is not None and isinstance(idx, int) and 0 <= idx < len(issues) and dim in ALL_DIMENSIONS:
                    dimensions[idx] = dim

            return dimensions

        except asyncio.TimeoutError:
            print("Dimension classification timeout, using fallback")
            return [self._fallback_dimension(issue) for issue in issues]
        except Exception as e:
            print(f"Batch dimension classification error: {e}")
            return [self._fallback_dimension(issue) for issue in issues]

    async def _generate_problem_keys(
        self,
        normalized_issues: List[NormalizedIssue],
    ) -> List[NormalizedIssue]:
        """Generate canonical problem keys for ALL issues using AI.

        Args:
            normalized_issues: List of normalized issues

        Returns:
            Issues with AI-generated problem keys
        """
        if not self.use_ai_classification or not self.is_ai_available():
            return normalized_issues

        # ALL issues go through AI key generation
        try:
            keys = await self._batch_generate_problem_keys(normalized_issues)
            for issue, key in zip(normalized_issues, keys):
                if key:
                    issue.problem_key = key
        except Exception as e:
            print(f"AI problem key generation failed, using auto-generated: {e}")

        return normalized_issues

    async def _batch_generate_problem_keys(
        self,
        issues: List[NormalizedIssue],
    ) -> List[str]:
        """Batch generate problem keys using AI.

        Args:
            issues: Issues to generate keys for

        Returns:
            List of problem key strings
        """
        if not issues:
            return []

        # Process in smaller batches
        BATCH_SIZE = 10
        all_keys = [issue.problem_key for issue in issues]

        for batch_start in range(0, len(issues), BATCH_SIZE):
            batch_issues = issues[batch_start:batch_start + BATCH_SIZE]
            batch_keys = await self._generate_keys_single_batch(batch_issues)

            for i, key in enumerate(batch_keys):
                if key:
                    all_keys[batch_start + i] = key

        return all_keys

    async def _generate_keys_single_batch(
        self,
        issues: List[NormalizedIssue],
    ) -> List[str]:
        """Generate problem keys for a single batch of issues using AI."""
        issues_data = []
        for i, issue in enumerate(issues):
            issues_data.append({
                "index": i,
                "title": issue.normalized_title[:100],
            })

        prompt = f"""Generate a canonical problem key for each issue. The key should:
- Be snake_case (lowercase with underscores)
- Be 2-4 words describing the core problem
- Group similar issues (e.g., all "missing CPU limit" issues should get same key)

Issues:
{json.dumps(issues_data)}

Examples: cpu_limits_missing, liveness_probe_missing, container_runs_as_root, single_replica_deployment

Respond with JSON array only: [{{"index": 0, "problem_key": "example_key"}}]"""

        try:
            response = await asyncio.wait_for(
                self.ai_provider.complete(
                    messages=[
                        {"role": "system", "content": "Generate canonical problem identifiers that group similar issues. Respond with valid JSON array only."},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=500,
                    temperature=0.1,
                    json_mode=True,
                ),
                timeout=30.0
            )

            tracker = GlobalTokenTracker.get_tracker()
            if tracker and response.usage:
                prompt_tokens = response.usage.get('prompt_tokens', 0) if isinstance(response.usage, dict) else 0
                completion_tokens = response.usage.get('completion_tokens', 0) if isinstance(response.usage, dict) else 0
                tracker.add_usage(prompt_tokens, completion_tokens)

            content = response.content.strip()
            if content.startswith("```"):
                content = re.sub(r'^```\w*\n?', '', content)
                content = re.sub(r'\n?```$', '', content)

            results = json.loads(content)

            if not isinstance(results, list):
                return [issue.problem_key for issue in issues]

            keys = [issue.problem_key for issue in issues]
            for item in results:
                if not isinstance(item, dict):
                    continue
                idx = item.get("index")
                key = item.get("problem_key", "")
                if idx is not None and isinstance(idx, int) and 0 <= idx < len(issues) and key and isinstance(key, str):
                    key = re.sub(r'[^a-z0-9_]', '_', key.lower())
                    key = re.sub(r'_+', '_', key).strip('_')
                    if key:
                        keys[idx] = key

            return keys

        except asyncio.TimeoutError:
            print("Problem key generation timeout, using auto-generated keys")
            return [issue.problem_key for issue in issues]
        except Exception as e:
            print(f"Batch problem key generation error: {e}")
            return [issue.problem_key for issue in issues]

    def _group_by_problem_key(
        self,
        normalized_issues: List[NormalizedIssue],
    ) -> Dict[str, List[NormalizedIssue]]:
        """Group normalized issues by their problem key.

        Args:
            normalized_issues: List of normalized issues

        Returns:
            Dictionary mapping problem_key to list of issues
        """
        grouped: Dict[str, List[NormalizedIssue]] = {}

        for issue in normalized_issues:
            key = issue.problem_key
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(issue)

        return grouped

    def _aggregate_to_unique_problems(
        self,
        grouped: Dict[str, List[NormalizedIssue]],
    ) -> List[UniqueProblem]:
        """Aggregate grouped issues into unique problems.

        Args:
            grouped: Issues grouped by problem key

        Returns:
            List of UniqueProblem objects
        """
        unique_problems = []

        for problem_key, issues in grouped.items():
            if not issues:
                continue

            # Determine final severity (highest among instances)
            final_severity = self._get_highest_severity(issues)

            # Get dimension (use most common if inconsistent)
            dimension = self._get_most_common_dimension(issues)

            # Get unique affected files
            affected_files = list(set(issue.file_path for issue in issues if issue.file_path != "unknown"))

            # Get unique rule IDs
            rule_ids = list(set(issue.rule_id for issue in issues if issue.rule_id))

            # Get unique scanners
            scanners = list(set(issue.scanner_source for issue in issues if issue.scanner_source))

            # Use first issue's title and description as representative
            title = issues[0].normalized_title
            description = issues[0].normalized_description

            unique_problems.append(UniqueProblem(
                problem_key=problem_key,
                dimension=dimension,
                title=title,
                description=description,
                final_severity=final_severity,
                occurrence_count=len(issues),
                affected_files=affected_files,
                original_issues=issues,
                rule_ids=rule_ids,
                scanners=scanners,
            ))

        # Sort by severity (critical first) then by occurrence count
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        unique_problems.sort(key=lambda p: (severity_order.get(p.final_severity, 5), -p.occurrence_count))

        return unique_problems

    def _get_highest_severity(self, issues: List[NormalizedIssue]) -> Severity:
        """Get the highest severity from a list of issues."""
        severity_priority = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }

        if not issues:
            return Severity.INFO

        highest = min(issues, key=lambda i: severity_priority.get(i.severity, 5))
        return highest.severity

    def _get_most_common_dimension(self, issues: List[NormalizedIssue]) -> str:
        """Get the most common dimension from a list of issues."""
        if not issues:
            return DIMENSION_SECURITY

        dimension_counts: Dict[str, int] = {}
        for issue in issues:
            dim = issue.dimension
            dimension_counts[dim] = dimension_counts.get(dim, 0) + 1

        return max(dimension_counts, key=dimension_counts.get)

    def _organize_by_dimension(
        self,
        unique_problems: List[UniqueProblem],
    ) -> Dict[str, List[UniqueProblem]]:
        """Organize unique problems by dimension."""
        by_dimension: Dict[str, List[UniqueProblem]] = {dim: [] for dim in ALL_DIMENSIONS}

        for problem in unique_problems:
            if problem.dimension in by_dimension:
                by_dimension[problem.dimension].append(problem)
            else:
                by_dimension[DIMENSION_SECURITY].append(problem)

        return by_dimension

    def _generate_dimension_summary(
        self,
        problems_by_dimension: Dict[str, List[UniqueProblem]],
    ) -> Dict[str, Dict[str, Any]]:
        """Generate summary statistics per dimension."""
        summary = {}

        for dimension, problems in problems_by_dimension.items():
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }

            total_occurrences = 0
            for problem in problems:
                severity_counts[problem.final_severity.value] += 1
                total_occurrences += problem.occurrence_count

            summary[dimension] = {
                "unique_problem_count": len(problems),
                "total_occurrences": total_occurrences,
                "severity_counts": severity_counts,
            }

        return summary
