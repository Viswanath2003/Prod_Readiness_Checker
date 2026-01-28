"""Checkov Security Scanner - Infrastructure as Code security scanner."""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...core.scanner import (
    BaseScanner,
    Issue,
    IssueCategory,
    ScanResult,
    Severity,
)


class CheckovScanner(BaseScanner):
    """Checkov-based IaC security scanner.

    Checkov scans infrastructure as code for security issues:
    - Terraform
    - CloudFormation
    - Kubernetes
    - Helm
    - Dockerfile
    - ARM templates
    - Serverless
    """

    # Mapping from Checkov severity to our severity
    SEVERITY_MAP: Dict[str, Severity] = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }

    # Framework to file pattern mapping
    FRAMEWORKS: Dict[str, List[str]] = {
        "terraform": ["*.tf", "*.tf.json"],
        "cloudformation": ["*.yaml", "*.yml", "*.json", "*.template"],
        "kubernetes": ["*.yaml", "*.yml"],
        "helm": ["Chart.yaml", "values.yaml", "*.yaml", "*.yml"],
        "dockerfile": ["Dockerfile", "Dockerfile.*", "*.dockerfile"],
        "arm": ["*.json"],
        "serverless": ["serverless.yml", "serverless.yaml"],
    }

    def __init__(
        self,
        frameworks: Optional[List[str]] = None,
        skip_checks: Optional[List[str]] = None,
        include_checks: Optional[List[str]] = None,
        soft_fail: bool = True,
        external_checks_dir: Optional[str] = None,
        config_file: Optional[str] = None,
    ):
        """Initialize the Checkov scanner.

        Args:
            frameworks: List of frameworks to scan (None = all)
            skip_checks: List of check IDs to skip
            include_checks: List of check IDs to include only
            soft_fail: Don't fail on findings (for CI/CD)
            external_checks_dir: Directory with custom checks
            config_file: Path to Checkov config file
        """
        super().__init__(name="checkov", scan_type="security")
        self.frameworks = frameworks
        self.skip_checks = skip_checks or []
        self.include_checks = include_checks
        self.soft_fail = soft_fail
        self.external_checks_dir = external_checks_dir
        self.config_file = config_file

    def is_available(self) -> bool:
        """Check if Checkov is installed and available."""
        return self._check_tool_available("checkov")

    async def scan(self, target_path: str | Path) -> ScanResult:
        """Perform Checkov IaC security scan.

        Args:
            target_path: Path to scan

        Returns:
            ScanResult containing all issues found
        """
        started_at = datetime.now()
        result = self._create_result(target_path, started_at)
        target_path = Path(target_path).resolve()

        if not target_path.exists():
            return self._complete_result(
                result, started_at, success=False,
                error_message=f"Target path does not exist: {target_path}"
            )

        # Build and run command
        cmd = self._build_command(target_path)
        return_code, stdout, stderr = await self._run_command(cmd, timeout=600)

        # Checkov returns 1 if issues found, 0 if clean
        if return_code not in [0, 1]:
            return self._complete_result(
                result, started_at, success=False,
                error_message=f"Checkov failed: {stderr}"
            )

        # Parse results
        result.issues = self._parse_results(stdout)
        result.metadata = {
            "target_path": str(target_path),
            "frameworks": self.frameworks or "all",
            "skipped_checks": self.skip_checks,
        }

        return self._complete_result(result, started_at)

    def _build_command(self, target_path: Path) -> List[str]:
        """Build Checkov command with appropriate options.

        Args:
            target_path: Path to scan

        Returns:
            Command as list of strings
        """
        cmd = [
            "checkov",
            "--directory", str(target_path),
            "--output", "json",
            "--quiet",
        ]

        # Add frameworks if specified
        if self.frameworks:
            cmd.extend(["--framework", ",".join(self.frameworks)])

        # Add skip checks
        for check_id in self.skip_checks:
            cmd.extend(["--skip-check", check_id])

        # Add include checks
        if self.include_checks:
            for check_id in self.include_checks:
                cmd.extend(["--check", check_id])

        # Soft fail mode
        if self.soft_fail:
            cmd.append("--soft-fail")

        # External checks
        if self.external_checks_dir:
            cmd.extend(["--external-checks-dir", self.external_checks_dir])

        # Config file
        if self.config_file:
            cmd.extend(["--config-file", self.config_file])

        return cmd

    def _parse_results(self, output: str) -> List[Issue]:
        """Parse Checkov scan output.

        Args:
            output: JSON output from Checkov

        Returns:
            List of Issue objects
        """
        issues = []

        # Checkov may output multiple JSON objects for different checks
        # Try to parse as a list first, then as single object
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            # Try to find JSON in the output
            try:
                # Look for the start of JSON
                json_start = output.find('[')
                if json_start == -1:
                    json_start = output.find('{')
                if json_start != -1:
                    data = json.loads(output[json_start:])
                else:
                    return issues
            except json.JSONDecodeError:
                return issues

        # Handle both single result and list of results
        if isinstance(data, list):
            results_list = data
        else:
            results_list = [data]

        for result_data in results_list:
            # Extract check results
            check_type = result_data.get("check_type", "")
            passed_checks = result_data.get("results", {}).get("passed_checks", [])
            failed_checks = result_data.get("results", {}).get("failed_checks", [])
            skipped_checks = result_data.get("results", {}).get("skipped_checks", [])

            # Process failed checks (these are the issues)
            for check in failed_checks:
                issue = self._create_issue_from_check(check, check_type)
                if issue:
                    issues.append(issue)

        return issues

    def _create_issue_from_check(
        self,
        check: Dict[str, Any],
        check_type: str,
    ) -> Optional[Issue]:
        """Create an Issue from a Checkov check result.

        Args:
            check: Check data from Checkov
            check_type: Type of check (terraform, kubernetes, etc.)

        Returns:
            Issue object or None
        """
        check_id = check.get("check_id", "UNKNOWN")
        check_name = check.get("check", {}).get("name", check.get("check_name", "Unknown Check"))

        # Determine severity based on check ID prefix or guideline
        severity = self._determine_severity(check_id, check)

        # Get file information
        file_path = check.get("file_path", "")
        file_line_range = check.get("file_line_range", [])
        start_line = file_line_range[0] if file_line_range else None

        # Get resource information
        resource = check.get("resource", "")
        resource_address = check.get("resource_address", resource)

        # Build description
        description = f"Check failed: {check_name}\n"
        if resource:
            description += f"Resource: {resource_address}\n"

        guideline = check.get("guideline", check.get("check", {}).get("guideline", ""))
        if guideline:
            description += f"\nGuideline: {guideline}"

        # Get remediation
        remediation = check.get("check", {}).get("remediation", None)

        issue_id = self._generate_issue_id(check_id, file_path, resource)

        return Issue(
            id=issue_id,
            title=f"{check_id}: {check_name}",
            description=description,
            severity=severity,
            category=IssueCategory.SECURITY,
            file_path=file_path,
            line_number=start_line,
            rule_id=check_id,
            scanner=self.name,
            remediation=remediation,
            references=[guideline] if guideline and guideline.startswith("http") else [],
            auto_fixable=False,
            metadata={
                "check_type": check_type,
                "resource": resource,
                "resource_address": resource_address,
                "evaluations": check.get("evaluations"),
                "file_line_range": file_line_range,
            },
        )

    def _determine_severity(
        self,
        check_id: str,
        check: Dict[str, Any],
    ) -> Severity:
        """Determine severity for a check.

        Args:
            check_id: Check ID
            check: Check data

        Returns:
            Severity level
        """
        # Check if severity is directly provided
        if "severity" in check:
            return self.SEVERITY_MAP.get(check["severity"].upper(), Severity.MEDIUM)

        # Determine based on check ID patterns
        # CKV_AWS_*, CKV_AZURE_*, CKV_GCP_* - Cloud provider checks
        # CKV_K8S_* - Kubernetes checks
        # CKV_DOCKER_* - Docker checks

        check_id_upper = check_id.upper()

        # Critical patterns (security-sensitive)
        critical_patterns = [
            "ENCRYPTION", "PUBLIC", "EXPOSE", "SECRET", "PASSWORD",
            "CREDENTIAL", "ROOT", "ADMIN", "IAM", "PRIVILEGE",
        ]

        check_name = check.get("check", {}).get("name", check.get("check_name", "")).upper()

        for pattern in critical_patterns:
            if pattern in check_name:
                return Severity.HIGH

        # Default severity based on check type
        if "CKV_SECRET" in check_id_upper:
            return Severity.CRITICAL
        elif "CKV_AWS" in check_id_upper or "CKV_AZURE" in check_id_upper or "CKV_GCP" in check_id_upper:
            return Severity.MEDIUM
        elif "CKV_K8S" in check_id_upper:
            return Severity.MEDIUM
        elif "CKV_DOCKER" in check_id_upper:
            return Severity.MEDIUM

        return Severity.MEDIUM

    def _generate_issue_id(self, *components: str) -> str:
        """Generate a unique issue ID from components.

        Args:
            *components: Strings to hash for the ID

        Returns:
            Unique issue ID
        """
        combined = "|".join(str(c) for c in components if c)
        hash_value = hashlib.md5(combined.encode()).hexdigest()[:12]
        return f"CHECKOV-{hash_value}"
