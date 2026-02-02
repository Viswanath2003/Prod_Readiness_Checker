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
    """Process raw scanner issues into normalized, classified, and grouped problems."""

    # Known problem key mappings (rule-based, no AI needed for common cases)
    KNOWN_PROBLEM_KEYS = {
        # Security
        "CKV_K8S_1": "privileged_container",
        "CKV_K8S_8": "liveness_probe_missing",
        "CKV_K8S_9": "readiness_probe_missing",
        "CKV_K8S_10": "cpu_limits_missing",
        "CKV_K8S_11": "cpu_requests_missing",
        "CKV_K8S_12": "memory_limits_missing",
        "CKV_K8S_13": "memory_requests_missing",
        "CKV_K8S_14": "image_tag_latest",
        "CKV_K8S_20": "container_runs_as_root",
        "CKV_K8S_21": "default_namespace_used",
        "CKV_K8S_22": "read_only_filesystem_missing",
        "CKV_K8S_23": "host_pid_namespace",
        "CKV_K8S_25": "allow_privilege_escalation",
        "CKV_K8S_28": "capabilities_not_dropped",
        "CKV_K8S_29": "security_context_missing",
        "CKV_K8S_30": "seccomp_profile_missing",
        "CKV_K8S_31": "host_network_namespace",
        "CKV_K8S_35": "secret_in_env_var",
        "CKV_K8S_37": "capability_sys_admin",
        "CKV_K8S_38": "service_account_token_automount",
        "CKV_K8S_40": "pod_service_account_missing",
        "CKV_K8S_43": "image_pull_policy_not_always",
        "CKV_DOCKER_1": "root_user_dockerfile",
        "CKV_DOCKER_2": "healthcheck_missing_dockerfile",
        "CKV_DOCKER_3": "add_instruction_used",
        "CKV_DOCKER_7": "latest_tag_dockerfile",
        "CKV2_DOCKER_1": "multi_stage_build_missing",
        # Performance
        "PERF-NO-CPU-LIMIT": "cpu_limits_missing",
        "PERF-NO-MEMORY-LIMIT": "memory_limits_missing",
        "PERF-SINGLE-REPLICA": "single_replica_deployment",
        "PERF-NO-HPA": "autoscaling_not_configured",
        "PERF-NO-RATE-LIMIT": "rate_limiting_missing",
        "PERF-NO-HTTP-TIMEOUT": "http_timeout_missing",
        "PERF-NO-CONNECTION-POOL": "connection_pool_missing",
        "PERF-NO-CACHE": "caching_not_configured",
        # Reliability
        "REL-NO-LIVENESS": "liveness_probe_missing",
        "REL-NO-READINESS": "readiness_probe_missing",
        "REL-LOW-REPLICAS": "low_replica_count",
        "REL-NO-PDB": "pod_disruption_budget_missing",
        "REL-NO-RESTART-POLICY": "restart_policy_missing",
        "REL-NO-RESOURCE-LIMITS": "resource_limits_missing",
        "REL-NO-CIRCUIT-BREAKER": "circuit_breaker_missing",
        "REL-NO-RETRY": "retry_config_missing",
        "REL-NO-BACKUP": "backup_not_configured",
        # Monitoring
        "MON-NO-LOGGING": "logging_not_configured",
        "MON-NO-METRICS": "metrics_not_configured",
        "MON-NO-TRACING": "tracing_not_configured",
        "MON-NO-ALERTS": "alerting_not_configured",
    }

    # Known dimension mappings based on rule prefixes and keywords
    DIMENSION_KEYWORDS = {
        DIMENSION_SECURITY: [
            "secret", "credential", "password", "token", "key", "auth", "privileged",
            "root", "permission", "vulnerability", "cve", "injection", "xss", "csrf",
            "encryption", "tls", "ssl", "certificate", "seccomp", "capability",
            "escalation", "namespace", "network_policy", "rbac", "service_account"
        ],
        DIMENSION_PERFORMANCE: [
            "cpu", "memory", "resource", "limit", "request", "replica", "scale",
            "autoscal", "hpa", "timeout", "latency", "cache", "pool", "connection",
            "rate_limit", "throttl", "buffer", "queue", "worker", "thread"
        ],
        DIMENSION_RELIABILITY: [
            "liveness", "readiness", "health", "probe", "restart", "availability",
            "redundan", "replica", "pdb", "disruption", "failover", "backup",
            "recovery", "circuit_breaker", "retry", "fallback", "graceful"
        ],
        DIMENSION_MONITORING: [
            "log", "metric", "monitor", "trace", "observ", "alert", "dashboard",
            "prometheus", "grafana", "jaeger", "fluentd", "elk", "apm"
        ],
    }

    # Rule prefix to dimension mapping
    RULE_PREFIX_DIMENSION = {
        "CKV_": DIMENSION_SECURITY,
        "CKV2_": DIMENSION_SECURITY,
        "PERF-": DIMENSION_PERFORMANCE,
        "REL-": DIMENSION_RELIABILITY,
        "MON-": DIMENSION_MONITORING,
        "SEC-": DIMENSION_SECURITY,
        "CVE-": DIMENSION_SECURITY,
        "GHSA-": DIMENSION_SECURITY,
    }

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
            use_ai_classification: Whether to use AI for unknown issues
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

        # Step 2: Normalize all issues
        normalized_issues = await self._normalize_issues(all_issues)

        # Step 3: Classify dimensions for issues that need it
        normalized_issues = await self._classify_dimensions(normalized_issues)

        # Step 4: Generate problem keys for issues that need it
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

            # Get initial dimension (may be refined later)
            dimension = self._get_initial_dimension(issue)

            # Get initial problem key (may be refined later)
            problem_key = self._get_initial_problem_key(issue)

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

    def _get_initial_dimension(self, issue: Issue) -> str:
        """Get initial dimension based on rule-based classification.

        Args:
            issue: The issue to classify

        Returns:
            Dimension string
        """
        # Check by rule ID prefix
        if issue.rule_id:
            for prefix, dimension in self.RULE_PREFIX_DIMENSION.items():
                if issue.rule_id.startswith(prefix):
                    return dimension

        # Check by issue category
        category_mapping = {
            IssueCategory.SECURITY: DIMENSION_SECURITY,
            IssueCategory.PERFORMANCE: DIMENSION_PERFORMANCE,
            IssueCategory.RELIABILITY: DIMENSION_RELIABILITY,
            IssueCategory.MONITORING: DIMENSION_MONITORING,
        }
        if issue.category in category_mapping:
            return category_mapping[issue.category]

        # Check by keywords in title and description
        text = f"{issue.title} {issue.description}".lower()
        dimension_scores = {dim: 0 for dim in ALL_DIMENSIONS}

        for dimension, keywords in self.DIMENSION_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    dimension_scores[dimension] += 1

        # Return dimension with highest score, default to security
        max_dimension = max(dimension_scores, key=dimension_scores.get)
        if dimension_scores[max_dimension] > 0:
            return max_dimension

        # Default to security if no match
        return DIMENSION_SECURITY

    def _get_initial_problem_key(self, issue: Issue) -> str:
        """Get initial problem key based on rule-based mapping.

        Args:
            issue: The issue to map

        Returns:
            Problem key string
        """
        # Check known mappings
        if issue.rule_id and issue.rule_id in self.KNOWN_PROBLEM_KEYS:
            return self.KNOWN_PROBLEM_KEYS[issue.rule_id]

        # Generate key from title if not known
        return self._generate_key_from_title(issue.title)

    def _generate_key_from_title(self, title: str) -> str:
        """Generate a problem key from issue title.

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
        """Classify dimensions for issues using AI if needed.

        Args:
            normalized_issues: List of normalized issues

        Returns:
            Issues with refined dimension classification
        """
        if not self.use_ai_classification or not self.is_ai_available():
            return normalized_issues

        # Find issues that might need AI classification
        # (those classified by fallback keyword matching with low confidence)
        issues_needing_classification = []
        for issue in normalized_issues:
            # If dimension was set from rule prefix, it's reliable
            if issue.rule_id:
                for prefix in self.RULE_PREFIX_DIMENSION:
                    if issue.rule_id.startswith(prefix):
                        break
                else:
                    issues_needing_classification.append(issue)
            else:
                issues_needing_classification.append(issue)

        if not issues_needing_classification:
            return normalized_issues

        # Batch classify with AI
        try:
            classifications = await self._batch_classify_dimensions(issues_needing_classification)
            for issue, dimension in zip(issues_needing_classification, classifications):
                if dimension in ALL_DIMENSIONS:
                    issue.dimension = dimension
        except Exception as e:
            print(f"AI dimension classification failed, using rule-based: {e}")

        return normalized_issues

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

        # Prepare batch prompt
        issues_data = []
        for i, issue in enumerate(issues):
            issues_data.append({
                "index": i,
                "title": issue.normalized_title[:100],
                "description": issue.normalized_description[:200],
                "rule_id": issue.rule_id,
            })

        prompt = f"""Classify each issue into exactly ONE dimension: security, performance, reliability, or monitoring.

Issues to classify:
{json.dumps(issues_data, indent=2)}

Rules:
- security: vulnerabilities, secrets, permissions, authentication, encryption, access control
- performance: resource limits, scaling, caching, timeouts, latency, throughput
- reliability: health checks, availability, redundancy, failover, recovery, probes
- monitoring: logging, metrics, tracing, alerting, observability

Respond with a JSON array of objects with "index" and "dimension" fields only.
Example: [{{"index": 0, "dimension": "security"}}, {{"index": 1, "dimension": "performance"}}]"""

        try:
            response = await self.ai_provider.complete(
                messages=[
                    {"role": "system", "content": "You are a DevOps expert classifying infrastructure issues. Respond only with valid JSON."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=1000,
                temperature=0.1,
                json_mode=True,
            )

            content = response.content
            # Extract JSON from response
            content = content.strip()
            if content.startswith("```"):
                content = re.sub(r'^```\w*\n?', '', content)
                content = re.sub(r'\n?```$', '', content)

            results = json.loads(content)

            # Build result list maintaining order
            dimensions = [issue.dimension for issue in issues]  # Default to existing
            for item in results:
                idx = item.get("index")
                dim = item.get("dimension", "").lower()
                if idx is not None and 0 <= idx < len(issues) and dim in ALL_DIMENSIONS:
                    dimensions[idx] = dim

            return dimensions

        except Exception as e:
            print(f"Batch dimension classification error: {e}")
            return [issue.dimension for issue in issues]

    async def _generate_problem_keys(
        self,
        normalized_issues: List[NormalizedIssue],
    ) -> List[NormalizedIssue]:
        """Generate canonical problem keys for issues.

        Args:
            normalized_issues: List of normalized issues

        Returns:
            Issues with refined problem keys
        """
        if not self.use_ai_classification or not self.is_ai_available():
            return normalized_issues

        # Find issues with auto-generated keys that might need refinement
        issues_needing_keys = []
        for issue in normalized_issues:
            # If key came from known mapping, it's reliable
            if issue.rule_id in self.KNOWN_PROBLEM_KEYS:
                continue
            issues_needing_keys.append(issue)

        if not issues_needing_keys:
            return normalized_issues

        # Batch generate keys with AI
        try:
            keys = await self._batch_generate_problem_keys(issues_needing_keys)
            for issue, key in zip(issues_needing_keys, keys):
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

        # Prepare batch prompt
        issues_data = []
        for i, issue in enumerate(issues):
            issues_data.append({
                "index": i,
                "title": issue.normalized_title[:100],
                "description": issue.normalized_description[:150],
                "dimension": issue.dimension,
            })

        prompt = f"""Generate a canonical problem key for each issue. The key should be:
- lowercase with underscores (snake_case)
- descriptive but concise (2-5 words)
- represent the underlying problem type, not the specific instance

Issues:
{json.dumps(issues_data, indent=2)}

Example keys: cpu_limits_missing, container_runs_as_root, liveness_probe_missing, logging_not_configured

Respond with a JSON array of objects with "index" and "problem_key" fields only.
Example: [{{"index": 0, "problem_key": "cpu_limits_missing"}}]"""

        try:
            response = await self.ai_provider.complete(
                messages=[
                    {"role": "system", "content": "You are a DevOps expert generating canonical problem identifiers. Respond only with valid JSON."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=1000,
                temperature=0.1,
                json_mode=True,
            )

            content = response.content
            content = content.strip()
            if content.startswith("```"):
                content = re.sub(r'^```\w*\n?', '', content)
                content = re.sub(r'\n?```$', '', content)

            results = json.loads(content)

            # Build result list maintaining order
            keys = [issue.problem_key for issue in issues]  # Default to existing
            for item in results:
                idx = item.get("index")
                key = item.get("problem_key", "")
                if idx is not None and 0 <= idx < len(issues) and key:
                    # Normalize the key
                    key = re.sub(r'[^a-z0-9_]', '_', key.lower())
                    key = re.sub(r'_+', '_', key).strip('_')
                    if key:
                        keys[idx] = key

            return keys

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

            # Get dimension (should be consistent, take first)
            dimension = issues[0].dimension

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
        """Get the highest severity from a list of issues.

        Args:
            issues: List of normalized issues

        Returns:
            Highest severity level
        """
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

    def _organize_by_dimension(
        self,
        unique_problems: List[UniqueProblem],
    ) -> Dict[str, List[UniqueProblem]]:
        """Organize unique problems by dimension.

        Args:
            unique_problems: List of unique problems

        Returns:
            Dictionary mapping dimension to list of problems
        """
        by_dimension: Dict[str, List[UniqueProblem]] = {dim: [] for dim in ALL_DIMENSIONS}

        for problem in unique_problems:
            if problem.dimension in by_dimension:
                by_dimension[problem.dimension].append(problem)
            else:
                # Fallback to security if dimension is unknown
                by_dimension[DIMENSION_SECURITY].append(problem)

        return by_dimension

    def _generate_dimension_summary(
        self,
        problems_by_dimension: Dict[str, List[UniqueProblem]],
    ) -> Dict[str, Dict[str, Any]]:
        """Generate summary statistics per dimension.

        Args:
            problems_by_dimension: Problems organized by dimension

        Returns:
            Summary statistics per dimension
        """
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
