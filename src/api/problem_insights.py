"""Problem Insights Module - Generate AI explanations per unique problem."""

import asyncio
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

from ..core.issue_processor import UniqueProblem, ProcessedResults
from ..core.scanner import Severity
from .ai_provider import (
    AIProvider,
    BaseAIProvider,
    get_provider,
    get_available_provider,
)


@dataclass
class ProblemInsight:
    """AI-generated insight for a unique problem."""
    problem_key: str
    explanation: str
    why_it_matters: str
    recommendation: str
    example_fix: Optional[str] = None
    priority_level: str = "medium"
    estimated_effort: str = "varies"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "problem_key": self.problem_key,
            "explanation": self.explanation,
            "why_it_matters": self.why_it_matters,
            "recommendation": self.recommendation,
            "example_fix": self.example_fix,
            "priority_level": self.priority_level,
            "estimated_effort": self.estimated_effort,
        }


class ProblemInsightsGenerator:
    """Generate AI-powered insights for unique problems."""

    # Pre-defined insights for common problems (no AI call needed)
    KNOWN_INSIGHTS = {
        "cpu_limits_missing": ProblemInsight(
            problem_key="cpu_limits_missing",
            explanation="Container CPU limits are not defined, allowing unbounded CPU consumption.",
            why_it_matters="Without CPU limits, a single container can consume all node resources, affecting other workloads and causing node instability.",
            recommendation="Add CPU limits to all containers. Start with conservative limits and adjust based on monitoring.",
            example_fix='resources:\n  limits:\n    cpu: "500m"\n  requests:\n    cpu: "100m"',
            priority_level="high",
            estimated_effort="15 minutes per container",
        ),
        "memory_limits_missing": ProblemInsight(
            problem_key="memory_limits_missing",
            explanation="Container memory limits are not defined, risking OOM kills and node instability.",
            why_it_matters="Containers without memory limits can cause OOM (Out of Memory) kills, affecting the entire node and other workloads.",
            recommendation="Define memory limits for all containers based on application profiling.",
            example_fix='resources:\n  limits:\n    memory: "512Mi"\n  requests:\n    memory: "256Mi"',
            priority_level="high",
            estimated_effort="15 minutes per container",
        ),
        "liveness_probe_missing": ProblemInsight(
            problem_key="liveness_probe_missing",
            explanation="No liveness probe configured to detect and recover from application deadlocks.",
            why_it_matters="Without liveness probes, Kubernetes cannot detect when an application is stuck and needs to be restarted.",
            recommendation="Add liveness probes that check application health. Use HTTP endpoints, TCP checks, or exec commands.",
            example_fix='livenessProbe:\n  httpGet:\n    path: /health\n    port: 8080\n  initialDelaySeconds: 30\n  periodSeconds: 10',
            priority_level="critical",
            estimated_effort="30 minutes per service",
        ),
        "readiness_probe_missing": ProblemInsight(
            problem_key="readiness_probe_missing",
            explanation="No readiness probe configured to control traffic routing to the container.",
            why_it_matters="Without readiness probes, traffic may be sent to containers that aren't ready, causing user-facing errors.",
            recommendation="Add readiness probes that verify the application can serve traffic.",
            example_fix='readinessProbe:\n  httpGet:\n    path: /ready\n    port: 8080\n  initialDelaySeconds: 5\n  periodSeconds: 5',
            priority_level="critical",
            estimated_effort="30 minutes per service",
        ),
        "container_runs_as_root": ProblemInsight(
            problem_key="container_runs_as_root",
            explanation="Container is running as root user, increasing the attack surface.",
            why_it_matters="Running as root means a container compromise gives attackers root access, potentially allowing container escape.",
            recommendation="Configure containers to run as non-root users with minimal permissions.",
            example_fix='securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000\n  runAsGroup: 1000',
            priority_level="high",
            estimated_effort="30 minutes per container",
        ),
        "privileged_container": ProblemInsight(
            problem_key="privileged_container",
            explanation="Container is running in privileged mode with full host access.",
            why_it_matters="Privileged containers have full access to host resources, making container escape trivial.",
            recommendation="Remove privileged mode. Use specific capabilities if host access is needed.",
            example_fix='securityContext:\n  privileged: false\n  capabilities:\n    drop:\n      - ALL',
            priority_level="critical",
            estimated_effort="1 hour (may require application changes)",
        ),
        "single_replica_deployment": ProblemInsight(
            problem_key="single_replica_deployment",
            explanation="Deployment has only one replica, creating a single point of failure.",
            why_it_matters="Single replica means no redundancy. Pod failure = complete service outage.",
            recommendation="Run at least 2-3 replicas for production services. Configure PodDisruptionBudget.",
            example_fix='spec:\n  replicas: 3\n---\napiVersion: policy/v1\nkind: PodDisruptionBudget\nspec:\n  minAvailable: 2',
            priority_level="high",
            estimated_effort="15 minutes",
        ),
        "pod_disruption_budget_missing": ProblemInsight(
            problem_key="pod_disruption_budget_missing",
            explanation="No PodDisruptionBudget configured to ensure availability during voluntary disruptions.",
            why_it_matters="Without PDB, cluster operations like node drains can take down all pods simultaneously.",
            recommendation="Create PodDisruptionBudget to maintain minimum availability during disruptions.",
            example_fix='apiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: my-pdb\nspec:\n  minAvailable: 2\n  selector:\n    matchLabels:\n      app: my-app',
            priority_level="high",
            estimated_effort="15 minutes",
        ),
        "image_tag_latest": ProblemInsight(
            problem_key="image_tag_latest",
            explanation="Container uses 'latest' tag instead of specific version.",
            why_it_matters="Latest tag is mutable and unpredictable. Deployments may behave differently each time.",
            recommendation="Use immutable tags with specific versions or SHA digests.",
            example_fix='image: myapp:v1.2.3\n# or\nimage: myapp@sha256:abc123...',
            priority_level="medium",
            estimated_effort="10 minutes per image",
        ),
        "secret_in_env_var": ProblemInsight(
            problem_key="secret_in_env_var",
            explanation="Secrets are exposed as environment variables instead of secure mounts.",
            why_it_matters="Environment variables can be leaked through logs, crash dumps, or process listings.",
            recommendation="Use Kubernetes secrets mounted as files or external secret managers.",
            example_fix='volumeMounts:\n  - name: secrets\n    mountPath: /etc/secrets\n    readOnly: true\nvolumes:\n  - name: secrets\n    secret:\n      secretName: my-secret',
            priority_level="high",
            estimated_effort="30 minutes per service",
        ),
        "logging_not_configured": ProblemInsight(
            problem_key="logging_not_configured",
            explanation="Application logging configuration is missing or incomplete.",
            why_it_matters="Without proper logging, debugging issues and understanding application behavior becomes impossible.",
            recommendation="Configure structured logging with appropriate log levels and centralized collection.",
            example_fix='# Python example\nimport logging\nlogging.basicConfig(\n    level=logging.INFO,\n    format=\'%(asctime)s %(levelname)s %(name)s %(message)s\'\n)',
            priority_level="high",
            estimated_effort="1-2 hours",
        ),
        "metrics_not_configured": ProblemInsight(
            problem_key="metrics_not_configured",
            explanation="Application metrics are not being collected or exposed.",
            why_it_matters="Without metrics, you cannot monitor application health, performance, or business KPIs.",
            recommendation="Expose Prometheus metrics endpoint and configure scraping.",
            example_fix='# Add metrics endpoint\napiVersion: v1\nkind: Service\nmetadata:\n  annotations:\n    prometheus.io/scrape: "true"\n    prometheus.io/port: "9090"',
            priority_level="high",
            estimated_effort="2-4 hours",
        ),
        "http_timeout_missing": ProblemInsight(
            problem_key="http_timeout_missing",
            explanation="HTTP client/server timeouts are not configured.",
            why_it_matters="Without timeouts, slow requests can hang indefinitely, consuming resources and causing cascading failures.",
            recommendation="Configure appropriate timeouts for all HTTP connections.",
            example_fix='# Nginx example\nproxy_connect_timeout 30s;\nproxy_read_timeout 60s;\nproxy_send_timeout 60s;',
            priority_level="critical",
            estimated_effort="30 minutes",
        ),
        "rate_limiting_missing": ProblemInsight(
            problem_key="rate_limiting_missing",
            explanation="No rate limiting configured to protect against abuse.",
            why_it_matters="Without rate limiting, your service is vulnerable to DoS and resource exhaustion.",
            recommendation="Implement rate limiting at the API gateway or application level.",
            example_fix='# Nginx example\nlimit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\nlimit_req zone=api burst=20 nodelay;',
            priority_level="medium",
            estimated_effort="1-2 hours",
        ),
        "circuit_breaker_missing": ProblemInsight(
            problem_key="circuit_breaker_missing",
            explanation="No circuit breaker pattern implemented for external dependencies.",
            why_it_matters="Without circuit breakers, failures cascade through the system, causing widespread outages.",
            recommendation="Implement circuit breaker pattern for all external service calls.",
            example_fix='# Using resilience4j or similar library\n@CircuitBreaker(name = "backendService", fallbackMethod = "fallback")\npublic String callBackend() { ... }',
            priority_level="medium",
            estimated_effort="2-4 hours per service",
        ),
        "allow_privilege_escalation": ProblemInsight(
            problem_key="allow_privilege_escalation",
            explanation="Container allows privilege escalation through setuid/setgid binaries.",
            why_it_matters="Privilege escalation can allow a compromised process to gain root access.",
            recommendation="Disable privilege escalation in security context.",
            example_fix='securityContext:\n  allowPrivilegeEscalation: false',
            priority_level="high",
            estimated_effort="10 minutes",
        ),
        "capabilities_not_dropped": ProblemInsight(
            problem_key="capabilities_not_dropped",
            explanation="Container capabilities are not restricted, keeping unnecessary privileges.",
            why_it_matters="Linux capabilities grant specific root powers. Keeping all capabilities increases attack surface.",
            recommendation="Drop all capabilities and add back only what's needed.",
            example_fix='securityContext:\n  capabilities:\n    drop:\n      - ALL\n    add:\n      - NET_BIND_SERVICE  # if needed',
            priority_level="medium",
            estimated_effort="30 minutes",
        ),
        "read_only_filesystem_missing": ProblemInsight(
            problem_key="read_only_filesystem_missing",
            explanation="Container filesystem is writable, allowing persistent malware.",
            why_it_matters="Writable filesystems allow attackers to install malware or modify application code.",
            recommendation="Use read-only root filesystem with specific writable mounts where needed.",
            example_fix='securityContext:\n  readOnlyRootFilesystem: true\nvolumeMounts:\n  - name: tmp\n    mountPath: /tmp\nvolumes:\n  - name: tmp\n    emptyDir: {}',
            priority_level="medium",
            estimated_effort="1 hour (may need testing)",
        ),
    }

    SYSTEM_PROMPT = """You are a DevOps and security expert providing actionable guidance for production readiness issues.

For each problem:
1. Explain what the issue is in simple terms
2. Explain why it matters for production systems
3. Provide a clear, specific recommendation
4. Include a code/config example when applicable

Be concise but thorough. Focus on practical fixes."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[Union[str, AIProvider]] = None,
    ):
        """Initialize the problem insights generator.

        Args:
            api_key: API key for AI provider
            model: Model to use for generation
            provider: AI provider to use (openai, gemini, grok, anthropic, ollama)
        """
        self.ai_provider: Optional[BaseAIProvider] = None

        if provider:
            try:
                self.ai_provider = get_provider(provider, api_key=api_key, model=model)
            except (ValueError, ImportError) as e:
                print(f"Warning: Could not initialize provider {provider}: {e}")
        else:
            # Auto-detect available provider
            self.ai_provider = get_available_provider()

    def is_available(self) -> bool:
        """Check if AI is available."""
        return self.ai_provider is not None and self.ai_provider.is_available()

    async def generate_insights(
        self,
        processed_results: ProcessedResults,
    ) -> ProcessedResults:
        """Generate AI insights for all unique problems.

        Args:
            processed_results: Processed results with unique problems

        Returns:
            ProcessedResults with explanation and recommendation filled in
        """
        for problem in processed_results.unique_problems:
            insight = await self.generate_problem_insight(problem)
            if insight:
                problem.explanation = insight.explanation
                problem.recommendation = insight.recommendation

        return processed_results

    async def generate_problem_insight(
        self,
        problem: UniqueProblem,
    ) -> Optional[ProblemInsight]:
        """Generate insight for a single unique problem.

        Args:
            problem: The unique problem to generate insight for

        Returns:
            ProblemInsight or None
        """
        # Check known insights first
        if problem.problem_key in self.KNOWN_INSIGHTS:
            return self.KNOWN_INSIGHTS[problem.problem_key]

        # Try partial match for known insights
        for key, insight in self.KNOWN_INSIGHTS.items():
            if key in problem.problem_key or problem.problem_key in key:
                return insight

        # Generate with AI if available
        if self.is_available():
            try:
                return await self._generate_ai_insight(problem)
            except Exception as e:
                print(f"AI insight generation failed: {e}")

        # Fallback to generic insight
        return self._generate_fallback_insight(problem)

    async def _generate_ai_insight(
        self,
        problem: UniqueProblem,
    ) -> ProblemInsight:
        """Generate insight using AI.

        Args:
            problem: The unique problem

        Returns:
            Generated ProblemInsight
        """
        prompt = f"""Generate a production readiness insight for this problem:

Problem Key: {problem.problem_key}
Dimension: {problem.dimension}
Title: {problem.title}
Description: {problem.description}
Severity: {problem.final_severity.value}
Affected Files: {len(problem.affected_files)} files
Occurrences: {problem.occurrence_count}

Provide a JSON response with:
{{
    "explanation": "Clear explanation of what this issue is",
    "why_it_matters": "Why this matters for production systems",
    "recommendation": "Specific actionable recommendation",
    "example_fix": "Code/config example if applicable, or null",
    "priority_level": "critical/high/medium/low",
    "estimated_effort": "Time estimate to fix"
}}"""

        response = await self.ai_provider.complete(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            max_tokens=800,
            temperature=0.3,
            json_mode=True,
        )

        content = response.content
        # Clean up JSON if needed
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r'^```\w*\n?', '', content)
            content = re.sub(r'\n?```$', '', content)

        data = json.loads(content)

        return ProblemInsight(
            problem_key=problem.problem_key,
            explanation=data.get("explanation", problem.description),
            why_it_matters=data.get("why_it_matters", ""),
            recommendation=data.get("recommendation", "Review and fix this issue."),
            example_fix=data.get("example_fix"),
            priority_level=data.get("priority_level", "medium"),
            estimated_effort=data.get("estimated_effort", "varies"),
        )

    def _generate_fallback_insight(
        self,
        problem: UniqueProblem,
    ) -> ProblemInsight:
        """Generate fallback insight without AI.

        Args:
            problem: The unique problem

        Returns:
            Generic ProblemInsight
        """
        severity_priority = {
            Severity.CRITICAL: "critical",
            Severity.HIGH: "high",
            Severity.MEDIUM: "medium",
            Severity.LOW: "low",
            Severity.INFO: "low",
        }

        severity_effort = {
            Severity.CRITICAL: "1-4 hours",
            Severity.HIGH: "1-2 hours",
            Severity.MEDIUM: "30 minutes - 1 hour",
            Severity.LOW: "15-30 minutes",
            Severity.INFO: "15 minutes",
        }

        why_it_matters_by_dimension = {
            "security": "Security issues can lead to data breaches, unauthorized access, and compliance violations.",
            "performance": "Performance issues can cause slow response times, resource exhaustion, and poor user experience.",
            "reliability": "Reliability issues can cause service outages, data loss, and degraded availability.",
            "monitoring": "Monitoring gaps make it difficult to detect issues, debug problems, and maintain SLAs.",
        }

        return ProblemInsight(
            problem_key=problem.problem_key,
            explanation=problem.description or f"Issue detected: {problem.title}",
            why_it_matters=why_it_matters_by_dimension.get(
                problem.dimension,
                "This issue should be addressed to improve production readiness."
            ),
            recommendation=f"Review and address this {problem.dimension} issue in the affected files.",
            example_fix=None,
            priority_level=severity_priority.get(problem.final_severity, "medium"),
            estimated_effort=severity_effort.get(problem.final_severity, "varies"),
        )

    async def generate_batch_insights(
        self,
        problems: List[UniqueProblem],
        max_concurrent: int = 3,
    ) -> Dict[str, ProblemInsight]:
        """Generate insights for multiple problems efficiently.

        Args:
            problems: List of unique problems
            max_concurrent: Maximum concurrent AI calls

        Returns:
            Dictionary mapping problem_key to ProblemInsight
        """
        insights = {}
        semaphore = asyncio.Semaphore(max_concurrent)

        async def process_problem(problem: UniqueProblem):
            async with semaphore:
                insight = await self.generate_problem_insight(problem)
                return problem.problem_key, insight

        tasks = [process_problem(p) for p in problems]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, tuple):
                key, insight = result
                if insight:
                    insights[key] = insight

        return insights
