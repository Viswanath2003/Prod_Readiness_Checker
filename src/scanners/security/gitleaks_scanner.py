"""Gitleaks Security Scanner - Secret and credential detection scanner."""

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


class GitleaksScanner(BaseScanner):
    """Gitleaks-based secret detection scanner.

    Gitleaks detects hardcoded secrets like:
    - API keys
    - Passwords
    - OAuth tokens
    - Private keys
    - AWS credentials
    - Database connection strings
    """

    # Rule ID to severity mapping
    SEVERITY_MAP: Dict[str, Severity] = {
        # AWS
        "aws-access-token": Severity.CRITICAL,
        "aws-secret-key": Severity.CRITICAL,
        "aws-mws-key": Severity.CRITICAL,
        # Generic
        "generic-api-key": Severity.HIGH,
        "private-key": Severity.CRITICAL,
        "jwt": Severity.HIGH,
        # Cloud providers
        "gcp-api-key": Severity.CRITICAL,
        "azure-storage-key": Severity.CRITICAL,
        # Databases
        "postgres-connection": Severity.HIGH,
        "mysql-connection": Severity.HIGH,
        "mongodb-connection": Severity.HIGH,
        # Communication
        "slack-token": Severity.HIGH,
        "slack-webhook": Severity.MEDIUM,
        "discord-token": Severity.HIGH,
        # Version control
        "github-token": Severity.CRITICAL,
        "gitlab-token": Severity.CRITICAL,
        "bitbucket-token": Severity.HIGH,
        # Default
        "default": Severity.HIGH,
    }

    def __init__(
        self,
        config_path: Optional[str] = None,
        baseline_path: Optional[str] = None,
        redact: bool = True,
        no_git: bool = False,
        verbose: bool = False,
    ):
        """Initialize the Gitleaks scanner.

        Args:
            config_path: Path to custom Gitleaks config
            baseline_path: Path to baseline file (ignore known secrets)
            redact: Redact secrets in output
            no_git: Scan directory without git (useful for non-git repos)
            verbose: Enable verbose output
        """
        super().__init__(name="gitleaks", scan_type="security")
        self.config_path = config_path
        self.baseline_path = baseline_path
        self.redact = redact
        self.no_git = no_git
        self.verbose = verbose

    def is_available(self) -> bool:
        """Check if Gitleaks is installed and available."""
        return self._check_tool_available("gitleaks")

    async def scan(self, target_path: str | Path) -> ScanResult:
        """Perform Gitleaks secret detection scan.

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
        return_code, stdout, stderr = await self._run_command(cmd, timeout=300)

        # Gitleaks returns 1 if leaks found, 0 if clean
        if return_code not in [0, 1]:
            return self._complete_result(
                result, started_at, success=False,
                error_message=f"Gitleaks failed: {stderr}"
            )

        # Parse results
        result.issues = self._parse_results(stdout)
        result.metadata = {
            "target_path": str(target_path),
            "secrets_found": len(result.issues),
            "redacted": self.redact,
        }

        return self._complete_result(result, started_at)

    def _build_command(self, target_path: Path) -> List[str]:
        """Build Gitleaks command with appropriate options.

        Args:
            target_path: Path to scan

        Returns:
            Command as list of strings
        """
        cmd = [
            "gitleaks",
            "detect",
            "--source", str(target_path),
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--exit-code", "1",
        ]

        # Custom config
        if self.config_path:
            cmd.extend(["--config", self.config_path])

        # Baseline (ignore known secrets)
        if self.baseline_path:
            cmd.extend(["--baseline-path", self.baseline_path])

        # Redact secrets
        if self.redact:
            cmd.append("--redact")

        # No git mode
        if self.no_git:
            cmd.append("--no-git")

        # Verbose mode
        if self.verbose:
            cmd.append("--verbose")

        return cmd

    def _parse_results(self, output: str) -> List[Issue]:
        """Parse Gitleaks scan output.

        Args:
            output: JSON output from Gitleaks

        Returns:
            List of Issue objects
        """
        issues = []

        if not output.strip():
            return issues

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            # Try to find JSON array in output
            try:
                json_start = output.find('[')
                if json_start != -1:
                    data = json.loads(output[json_start:])
                else:
                    return issues
            except json.JSONDecodeError:
                return issues

        # Gitleaks returns a list of findings
        if not isinstance(data, list):
            return issues

        for finding in data:
            issue = self._create_issue_from_finding(finding)
            if issue:
                issues.append(issue)

        return issues

    def _create_issue_from_finding(
        self,
        finding: Dict[str, Any],
    ) -> Optional[Issue]:
        """Create an Issue from a Gitleaks finding.

        Args:
            finding: Finding data from Gitleaks

        Returns:
            Issue object or None
        """
        rule_id = finding.get("RuleID", "unknown")
        description_text = finding.get("Description", "Secret detected")

        # Get file information
        file_path = finding.get("File", "")
        start_line = finding.get("StartLine")
        end_line = finding.get("EndLine")

        # Get match information
        match = finding.get("Match", "")
        secret = finding.get("Secret", "")

        # Mask the secret for display
        if self.redact or not secret:
            masked_secret = "REDACTED"
        elif len(secret) > 10:
            masked_secret = secret[:3] + "..." + secret[-3:]
        else:
            masked_secret = "***"

        # Determine severity based on rule
        severity = self._get_severity_for_rule(rule_id)

        # Build description
        description = f"{description_text}\n"
        description += f"Rule: {rule_id}\n"
        if match and not self.redact:
            description += f"Pattern matched in code\n"
        description += f"Detected secret type: {rule_id.replace('-', ' ').title()}"

        # Build title
        title = f"Exposed Secret: {rule_id.replace('-', ' ').title()}"

        # Remediation
        remediation = self._get_remediation_for_rule(rule_id)

        issue_id = self._generate_issue_id(rule_id, file_path, str(start_line))

        return Issue(
            id=issue_id,
            title=title,
            description=description,
            severity=severity,
            category=IssueCategory.SECURITY,
            file_path=file_path,
            line_number=start_line,
            rule_id=rule_id,
            scanner=self.name,
            remediation=remediation,
            references=[
                "https://github.com/gitleaks/gitleaks",
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
            ],
            auto_fixable=False,  # Secrets require manual rotation
            metadata={
                "start_line": start_line,
                "end_line": end_line,
                "commit": finding.get("Commit"),
                "author": finding.get("Author"),
                "email": finding.get("Email"),
                "date": finding.get("Date"),
                "tags": finding.get("Tags", []),
                "entropy": finding.get("Entropy"),
            },
        )

    def _get_severity_for_rule(self, rule_id: str) -> Severity:
        """Get severity level for a rule ID.

        Args:
            rule_id: Gitleaks rule ID

        Returns:
            Severity level
        """
        rule_id_lower = rule_id.lower()

        # Check exact match
        if rule_id_lower in self.SEVERITY_MAP:
            return self.SEVERITY_MAP[rule_id_lower]

        # Check partial matches
        critical_keywords = [
            "private-key", "aws", "gcp", "azure", "github", "gitlab",
            "ssh", "rsa", "encryption-key", "master-key",
        ]
        for keyword in critical_keywords:
            if keyword in rule_id_lower:
                return Severity.CRITICAL

        high_keywords = [
            "token", "api-key", "secret", "password", "credential",
            "oauth", "jwt", "bearer",
        ]
        for keyword in high_keywords:
            if keyword in rule_id_lower:
                return Severity.HIGH

        # Default severity
        return self.SEVERITY_MAP.get("default", Severity.HIGH)

    def _get_remediation_for_rule(self, rule_id: str) -> str:
        """Get remediation steps for a rule.

        Args:
            rule_id: Gitleaks rule ID

        Returns:
            Remediation text
        """
        rule_id_lower = rule_id.lower()

        base_steps = [
            "1. Remove the secret from the code immediately",
            "2. Rotate/invalidate the exposed credential",
            "3. Use environment variables or a secret manager",
            "4. Review git history for the exposure",
        ]

        specific_steps = {
            "aws": [
                "5. Deactivate the AWS access key in IAM console",
                "6. Create a new access key and update your applications",
                "7. Review CloudTrail for unauthorized access",
            ],
            "github": [
                "5. Revoke the GitHub token in Developer Settings",
                "6. Create a new token with minimal required permissions",
                "7. Review GitHub audit log for unauthorized access",
            ],
            "private-key": [
                "5. Generate a new key pair",
                "6. Update all systems using the compromised key",
                "7. Add the old key to revocation lists if applicable",
            ],
            "database": [
                "5. Change the database password immediately",
                "6. Update connection strings in all applications",
                "7. Review database logs for unauthorized access",
            ],
        }

        # Find applicable specific steps
        additional_steps = []
        for keyword, steps in specific_steps.items():
            if keyword in rule_id_lower:
                additional_steps = steps
                break

        all_steps = base_steps + additional_steps
        return "\n".join(all_steps)

    def _generate_issue_id(self, *components: str) -> str:
        """Generate a unique issue ID from components.

        Args:
            *components: Strings to hash for the ID

        Returns:
            Unique issue ID
        """
        combined = "|".join(str(c) for c in components if c)
        hash_value = hashlib.md5(combined.encode()).hexdigest()[:12]
        return f"GITLEAKS-{hash_value}"
