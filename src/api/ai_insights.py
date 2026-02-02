"""AI Insights Module - Generate AI-powered insights for security and reliability issues."""

import asyncio
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from openai import AsyncOpenAI, AsyncAzureOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

# Import token tracker
try:
    from ..utils.token_tracker import GlobalTokenTracker
except ImportError:
    # Fallback if tracker not available
    class GlobalTokenTracker:
        @classmethod
        def get_tracker(cls):
            return None

from ..core.scanner import Issue, Severity, ScanResult
from ..core.scorer import Score


@dataclass
class AIInsight:
    """AI-generated insight for an issue."""
    issue_id: str
    summary: str
    detailed_explanation: str
    remediation_steps: List[str]
    code_example: Optional[str] = None
    risk_assessment: str = ""
    priority_score: int = 0
    estimated_effort: str = ""
    references: List[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "issue_id": self.issue_id,
            "summary": self.summary,
            "detailed_explanation": self.detailed_explanation,
            "remediation_steps": self.remediation_steps,
            "code_example": self.code_example,
            "risk_assessment": self.risk_assessment,
            "priority_score": self.priority_score,
            "estimated_effort": self.estimated_effort,
            "references": self.references,
        }


@dataclass
class ReportInsights:
    """AI-generated insights for a full scan report."""
    executive_summary: str
    key_findings: List[str]
    priority_actions: List[Dict[str, Any]]
    risk_overview: str
    improvement_roadmap: List[Dict[str, Any]]
    generated_at: datetime = None

    def __post_init__(self):
        if self.generated_at is None:
            self.generated_at = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "executive_summary": self.executive_summary,
            "key_findings": self.key_findings,
            "priority_actions": self.priority_actions,
            "risk_overview": self.risk_overview,
            "improvement_roadmap": self.improvement_roadmap,
            "generated_at": self.generated_at.isoformat(),
        }


class AIInsightsGenerator:
    """Generate AI-powered insights and remediation suggestions using OpenAI."""

    SYSTEM_PROMPT = """You are an expert security and DevOps engineer specializing in
production readiness assessments. Your role is to analyze security vulnerabilities,
configuration issues, and provide actionable remediation guidance.

When analyzing issues:
1. Provide clear, concise explanations of the risk
2. Give step-by-step remediation instructions
3. Include code examples when helpful
4. Prioritize based on actual risk impact
5. Consider the context of production environments

Always be specific and actionable in your recommendations."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",
        max_tokens: int = 2000,
        temperature: float = 0.3,
    ):
        """Initialize the AI insights generator.

        Args:
            api_key: OpenAI API key (uses OPENAI_API_KEY env var if not provided)
            model: Model to use for generation
            max_tokens: Maximum tokens in response
            temperature: Temperature for generation (0-1)
        """
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        self.azure_api_key = os.getenv("AZURE_OPENAI_KEY")
        self.azure_api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2023-05-15")
        self.azure_deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")
        
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature

        if OPENAI_AVAILABLE:
            if self.azure_endpoint and self.azure_api_key:
                # Prefer Azure if configured
                self.client = AsyncAzureOpenAI(
                    api_key=self.azure_api_key,
                    api_version=self.azure_api_version,
                    azure_endpoint=self.azure_endpoint,
                    azure_deployment=self.azure_deployment
                )
            elif self.api_key:
                # Fallback to standard OpenAI
                self.client = AsyncOpenAI(api_key=self.api_key)
            else:
                self.client = None
        else:
            self.client = None

    def is_available(self) -> bool:
        """Check if OpenAI integration is available."""
        return OPENAI_AVAILABLE and self.api_key is not None

    async def generate_issue_insight(self, issue: Issue) -> Optional[AIInsight]:
        """Generate AI insight for a single issue.

        Args:
            issue: Issue to analyze

        Returns:
            AIInsight or None if generation fails
        """
        if not self.is_available():
            return self._generate_fallback_insight(issue)

        prompt = self._build_issue_prompt(issue)

        try:
            # Use deployment name for Azure, model name for standard OpenAI
            model_param = self.azure_deployment if (self.azure_endpoint and self.azure_api_key) else self.model
            
            response = await self.client.chat.completions.create(
                model=model_param,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                response_format={"type": "json_object"},
            )
            
            # Track token usage
            tracker = GlobalTokenTracker.get_tracker()
            if tracker and hasattr(response, 'usage') and response.usage:
                tracker.add_usage(
                    response.usage.prompt_tokens,
                    response.usage.completion_tokens
                )

            content = response.choices[0].message.content
            data = json.loads(content)

            return AIInsight(
                issue_id=issue.id,
                summary=data.get("summary", ""),
                detailed_explanation=data.get("detailed_explanation", ""),
                remediation_steps=data.get("remediation_steps", []),
                code_example=data.get("code_example"),
                risk_assessment=data.get("risk_assessment", ""),
                priority_score=data.get("priority_score", 5),
                estimated_effort=data.get("estimated_effort", ""),
                references=data.get("references", []),
            )

        except Exception as e:
            print(f"Error generating AI insight: {e}")
            return self._generate_fallback_insight(issue)

    async def generate_batch_insights(
        self,
        issues: List[Issue],
        max_concurrent: int = 10,  # Increased from 5 to 10 for faster processing
    ) -> List[AIInsight]:
        """Generate insights for multiple issues concurrently.

        Args:
            issues: List of issues to analyze
            max_concurrent: Maximum concurrent API calls

        Returns:
            List of AIInsight objects
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def process_issue(issue: Issue) -> Optional[AIInsight]:
            async with semaphore:
                try:
                    # Add 60 second timeout per issue (increased from 30s)
                    return await asyncio.wait_for(
                        self.generate_issue_insight(issue),
                        timeout=60.0
                    )
                except asyncio.TimeoutError:
                    print(f"⚠️  Timeout generating insight for {issue.id}, using fallback")
                    return self._generate_fallback_insight(issue)
                except Exception as e:
                    print(f"⚠️  Error processing {issue.id}: {e}")
                    return self._generate_fallback_insight(issue)

        tasks = [process_issue(issue) for issue in issues]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        insights = []
        for result in results:
            if isinstance(result, AIInsight):
                insights.append(result)

        return insights

    async def generate_report_insights(
        self,
        scan_results: List[ScanResult],
        score: Score,
    ) -> Optional[ReportInsights]:
        """Generate executive-level insights for a full scan report.

        Args:
            scan_results: List of scan results
            score: Overall score

        Returns:
            ReportInsights or None if generation fails
        """
        if not self.is_available():
            return self._generate_fallback_report_insights(scan_results, score)

        prompt = self._build_report_prompt(scan_results, score)

        try:
            # Use deployment name for Azure, model name for standard OpenAI
            model_param = self.azure_deployment if (self.azure_endpoint and self.azure_api_key) else self.model
            
            response = await self.client.chat.completions.create(
                model=model_param,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=self.max_tokens * 2,  # More tokens for report
                temperature=self.temperature,
                response_format={"type": "json_object"},
            )

            content = response.choices[0].message.content
            data = json.loads(content)
            
            # Track token usage
            tracker = GlobalTokenTracker.get_tracker()
            if tracker and hasattr(response, 'usage') and response.usage:
                tracker.add_usage(
                    response.usage.prompt_tokens,
                    response.usage.completion_tokens
                )

            return ReportInsights(
                executive_summary=data.get("executive_summary", ""),
                key_findings=data.get("key_findings", []),
                priority_actions=data.get("priority_actions", []),
                risk_overview=data.get("risk_overview", ""),
                improvement_roadmap=data.get("improvement_roadmap", []),
            )

        except Exception as e:
            print(f"Error generating report insights: {e}")
            return self._generate_fallback_report_insights(scan_results, score)

    def _build_issue_prompt(self, issue: Issue) -> str:
        """Build prompt for single issue analysis."""
        return f"""Analyze the following security/configuration issue and provide detailed remediation guidance.

Issue Details:
- ID: {issue.id}
- Title: {issue.title}
- Severity: {issue.severity.value}
- Category: {issue.category.value}
- File: {issue.file_path or 'N/A'}
- Line: {issue.line_number or 'N/A'}
- Rule: {issue.rule_id or 'N/A'}
- Scanner: {issue.scanner}

Description:
{issue.description}

Current Remediation Suggestion:
{issue.remediation or 'None provided'}

Please provide a JSON response with the following structure:
{{
    "summary": "Brief 1-2 sentence summary of the issue and its impact",
    "detailed_explanation": "Detailed explanation of why this is a security/configuration concern",
    "remediation_steps": ["Step 1", "Step 2", "Step 3"],
    "code_example": "Example code showing the fix (if applicable, otherwise null)",
    "risk_assessment": "Description of the potential risks if not addressed",
    "priority_score": 1-10 (10 being most critical),
    "estimated_effort": "Estimated time/effort to fix (e.g., '30 minutes', '2 hours')",
    "references": ["URL1", "URL2"] (relevant documentation links)
}}"""

    def _build_report_prompt(
        self,
        scan_results: List[ScanResult],
        score: Score,
    ) -> str:
        """Build prompt for full report analysis."""
        # Summarize issues by severity and category
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        category_issues = {}

        for result in scan_results:
            for issue in result.issues:
                severity_counts[issue.severity.value] += 1
                if issue.category.value not in category_issues:
                    category_issues[issue.category.value] = []
                if len(category_issues[issue.category.value]) < 5:  # Top 5 per category
                    category_issues[issue.category.value].append({
                        "title": issue.title,
                        "severity": issue.severity.value,
                        "file": issue.file_path,
                    })

        return f"""Analyze the following production readiness assessment results and provide executive insights.

Overall Score: {score.overall_score:.1f}/100
Grade: {score.grade}
Production Ready: {'Yes' if score.is_production_ready else 'No'}
Readiness Threshold: {score.readiness_threshold}

Category Scores:
{json.dumps({k: v.to_dict() for k, v in score.category_scores.items()}, indent=2)}

Issue Severity Distribution:
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Info: {severity_counts['info']}

Top Issues by Category:
{json.dumps(category_issues, indent=2)}

Please provide a JSON response with the following structure:
{{
    "executive_summary": "2-3 paragraph executive summary of the assessment",
    "key_findings": ["Finding 1", "Finding 2", "Finding 3"],
    "priority_actions": [
        {{"action": "Action description", "priority": "high/medium/low", "effort": "Estimated effort"}}
    ],
    "risk_overview": "Overview of the current risk posture",
    "improvement_roadmap": [
        {{"phase": "Phase 1", "timeline": "1 week", "actions": ["Action 1", "Action 2"], "expected_score_improvement": 10}}
    ]
}}"""

    def _generate_fallback_insight(self, issue: Issue) -> AIInsight:
        """Generate a fallback insight when AI is not available."""
        severity_priority = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 5,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }

        severity_effort = {
            Severity.CRITICAL: "1-4 hours",
            Severity.HIGH: "1-2 hours",
            Severity.MEDIUM: "30 minutes - 1 hour",
            Severity.LOW: "15-30 minutes",
            Severity.INFO: "15 minutes",
        }

        remediation_steps = []
        if issue.remediation:
            remediation_steps = [
                step.strip()
                for step in issue.remediation.split("\n")
                if step.strip()
            ]
        else:
            remediation_steps = [
                "Review the identified issue in the specified file",
                "Understand the security/configuration implication",
                "Apply the recommended fix",
                "Test the change in a non-production environment",
                "Deploy the fix to production",
            ]

        return AIInsight(
            issue_id=issue.id,
            summary=f"{issue.severity.value.upper()} severity {issue.category.value} issue: {issue.title}",
            detailed_explanation=issue.description,
            remediation_steps=remediation_steps,
            code_example=issue.fix_suggestion,
            risk_assessment=f"This is a {issue.severity.value} severity issue that should be addressed "
                           f"{'immediately' if issue.severity in [Severity.CRITICAL, Severity.HIGH] else 'in a timely manner'}.",
            priority_score=severity_priority.get(issue.severity, 5),
            estimated_effort=severity_effort.get(issue.severity, "1 hour"),
            references=issue.references if issue.references else [],
        )

    def _generate_fallback_report_insights(
        self,
        scan_results: List[ScanResult],
        score: Score,
    ) -> ReportInsights:
        """Generate fallback report insights when AI is not available."""
        total_issues = sum(r.issue_count for r in scan_results)
        critical_issues = sum(r.critical_count for r in scan_results)
        high_issues = sum(r.high_count for r in scan_results)

        # Generate executive summary
        if score.is_production_ready:
            status = "meets the minimum requirements for production deployment"
        else:
            status = "does not meet the requirements for production deployment"

        executive_summary = f"""The production readiness assessment has completed with an overall score of {score.overall_score:.1f}/100,
receiving a grade of {score.grade}. The application {status}.

A total of {total_issues} issues were identified across the scanned components, including {critical_issues} critical
and {high_issues} high severity findings that require immediate attention.

{'The system is ready for production with minor improvements recommended.' if score.is_production_ready
else 'Significant improvements are required before the system can be considered production-ready.'}"""

        # Generate key findings
        key_findings = []
        for category, cat_score in score.category_scores.items():
            if cat_score.critical_count > 0:
                key_findings.append(
                    f"{category.title()}: {cat_score.critical_count} critical issues found"
                )
            elif cat_score.high_count > 0:
                key_findings.append(
                    f"{category.title()}: {cat_score.high_count} high severity issues found"
                )
            elif cat_score.score < 70:
                key_findings.append(
                    f"{category.title()}: Score below acceptable threshold ({cat_score.score:.1f}/100)"
                )

        if not key_findings:
            key_findings = ["No critical issues found", "System meets baseline requirements"]

        # Generate priority actions
        priority_actions = []
        for category, cat_score in sorted(
            score.category_scores.items(),
            key=lambda x: x[1].score
        ):
            if cat_score.critical_count > 0:
                priority_actions.append({
                    "action": f"Address {cat_score.critical_count} critical {category} issues immediately",
                    "priority": "high",
                    "effort": f"{cat_score.critical_count * 2} hours estimated",
                })
            elif cat_score.high_count > 0:
                priority_actions.append({
                    "action": f"Review and fix {cat_score.high_count} high severity {category} issues",
                    "priority": "medium",
                    "effort": f"{cat_score.high_count} hours estimated",
                })

        # Generate improvement roadmap
        improvement_roadmap = []
        if critical_issues > 0:
            improvement_roadmap.append({
                "phase": "Phase 1: Critical Fixes",
                "timeline": "1-2 days",
                "actions": ["Fix all critical severity issues", "Rerun security scans"],
                "expected_score_improvement": 15,
            })
        if high_issues > 0:
            improvement_roadmap.append({
                "phase": "Phase 2: High Priority Fixes",
                "timeline": "3-5 days",
                "actions": ["Address high severity issues", "Implement security best practices"],
                "expected_score_improvement": 10,
            })
        improvement_roadmap.append({
            "phase": "Phase 3: Continuous Improvement",
            "timeline": "Ongoing",
            "actions": ["Regular security scans", "Monitor for new vulnerabilities"],
            "expected_score_improvement": 5,
        })

        return ReportInsights(
            executive_summary=executive_summary,
            key_findings=key_findings,
            priority_actions=priority_actions,
            risk_overview=f"Current risk level: {'HIGH' if critical_issues > 0 else 'MEDIUM' if high_issues > 0 else 'LOW'}. "
                         f"Total blocking issues: {critical_issues + high_issues}.",
            improvement_roadmap=improvement_roadmap,
        )
