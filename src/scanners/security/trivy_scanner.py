"""Trivy Security Scanner - Comprehensive vulnerability and misconfiguration scanner."""

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


class TrivyScanner(BaseScanner):
    """Trivy-based security scanner for vulnerabilities and misconfigurations.

    Trivy can scan:
    - Filesystem for vulnerabilities in dependencies
    - Container images
    - IaC files (Dockerfile, Kubernetes, Terraform, etc.)
    - Secrets
    """

    # Mapping from Trivy severity to our severity
    SEVERITY_MAP: Dict[str, Severity] = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "UNKNOWN": Severity.INFO,
    }

    # Trivy misconfiguration severity mapping
    MISCONFIG_SEVERITY_MAP: Dict[str, Severity] = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }

    def __init__(
        self,
        scan_vulnerabilities: bool = True,
        scan_misconfigurations: bool = True,
        scan_secrets: bool = True,
        severity_threshold: str = "LOW",
        ignore_unfixed: bool = False,
        skip_dirs: Optional[List[str]] = None,
        config_file: Optional[str] = None,
    ):
        """Initialize the Trivy scanner.

        Args:
            scan_vulnerabilities: Scan for vulnerabilities in dependencies
            scan_misconfigurations: Scan for IaC misconfigurations
            scan_secrets: Scan for exposed secrets
            severity_threshold: Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW)
            ignore_unfixed: Ignore vulnerabilities without fixes
            skip_dirs: Directories to skip during scanning
            config_file: Path to Trivy config file
        """
        super().__init__(name="trivy", scan_type="security")
        self.scan_vulnerabilities = scan_vulnerabilities
        self.scan_misconfigurations = scan_misconfigurations
        self.scan_secrets = scan_secrets
        self.severity_threshold = severity_threshold
        self.ignore_unfixed = ignore_unfixed
        self.skip_dirs = skip_dirs or [".git", "node_modules", "vendor", ".venv"]
        self.config_file = config_file

    def is_available(self) -> bool:
        """Check if Trivy is installed and available."""
        return self._check_tool_available("trivy")

    async def scan(self, target_path: str | Path) -> ScanResult:
        """Perform comprehensive Trivy scan.

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

        all_issues: List[Issue] = []

        # Run filesystem scan for vulnerabilities
        if self.scan_vulnerabilities:
            vuln_issues = await self._scan_filesystem(target_path)
            all_issues.extend(vuln_issues)

        # Run config scan for misconfigurations
        if self.scan_misconfigurations:
            config_issues = await self._scan_config(target_path)
            all_issues.extend(config_issues)

        # Run secret scan
        if self.scan_secrets:
            secret_issues = await self._scan_secrets(target_path)
            all_issues.extend(secret_issues)

        # Deduplicate issues
        result.issues = self._deduplicate_issues(all_issues)
        result.metadata = {
            "target_path": str(target_path),
            "scan_modes": {
                "vulnerabilities": self.scan_vulnerabilities,
                "misconfigurations": self.scan_misconfigurations,
                "secrets": self.scan_secrets,
            },
            "severity_threshold": self.severity_threshold,
        }

        return self._complete_result(result, started_at)

    async def _scan_filesystem(self, target_path: Path) -> List[Issue]:
        """Scan filesystem for vulnerabilities.

        Args:
            target_path: Path to scan

        Returns:
            List of vulnerability issues
        """
        cmd = self._build_command(
            target_path,
            scanners=["vuln"],
        )

        return_code, stdout, stderr = await self._run_command(cmd)

        if return_code not in [0, 1]:  # Trivy returns 1 if vulnerabilities found
            return []

        return self._parse_vulnerability_results(stdout)

    async def _scan_config(self, target_path: Path) -> List[Issue]:
        """Scan for IaC misconfigurations.

        Args:
            target_path: Path to scan

        Returns:
            List of misconfiguration issues
        """
        cmd = self._build_command(
            target_path,
            scanners=["misconfig"],
        )

        return_code, stdout, stderr = await self._run_command(cmd)

        if return_code not in [0, 1]:
            return []

        return self._parse_misconfig_results(stdout)

    async def _scan_secrets(self, target_path: Path) -> List[Issue]:
        """Scan for exposed secrets.

        Args:
            target_path: Path to scan

        Returns:
            List of secret exposure issues
        """
        cmd = self._build_command(
            target_path,
            scanners=["secret"],
        )

        return_code, stdout, stderr = await self._run_command(cmd)

        if return_code not in [0, 1]:
            return []

        return self._parse_secret_results(stdout)

    def _build_command(
        self,
        target_path: Path,
        scanners: List[str],
    ) -> List[str]:
        """Build Trivy command with appropriate options.

        Args:
            target_path: Path to scan
            scanners: List of scanners to enable

        Returns:
            Command as list of strings
        """
        cmd = [
            "trivy",
            "filesystem",
            "--format", "json",
            "--severity", self.severity_threshold + ",HIGH,CRITICAL"
            if self.severity_threshold not in ["HIGH", "CRITICAL"]
            else self.severity_threshold + ",CRITICAL"
            if self.severity_threshold != "CRITICAL"
            else "CRITICAL",
        ]

        # Add scanners
        cmd.extend(["--scanners", ",".join(scanners)])

        # Add skip directories
        for skip_dir in self.skip_dirs:
            cmd.extend(["--skip-dirs", skip_dir])

        # Ignore unfixed vulnerabilities if requested
        if self.ignore_unfixed:
            cmd.append("--ignore-unfixed")

        # Add config file if specified
        if self.config_file:
            cmd.extend(["--config", self.config_file])

        # Add target path
        cmd.append(str(target_path))

        return cmd

    def _parse_vulnerability_results(self, output: str) -> List[Issue]:
        """Parse Trivy vulnerability scan output.

        Args:
            output: JSON output from Trivy

        Returns:
            List of Issue objects
        """
        issues = []
        data = self._parse_json_output(output)

        if not data:
            return issues

        results = data.get("Results", [])

        for result in results:
            target = result.get("Target", "")
            vulnerabilities = result.get("Vulnerabilities", [])

            for vuln in vulnerabilities:
                issue = self._create_vulnerability_issue(vuln, target)
                if issue:
                    issues.append(issue)

        return issues

    def _parse_misconfig_results(self, output: str) -> List[Issue]:
        """Parse Trivy misconfiguration scan output.

        Args:
            output: JSON output from Trivy

        Returns:
            List of Issue objects
        """
        issues = []
        data = self._parse_json_output(output)

        if not data:
            return issues

        results = data.get("Results", [])

        for result in results:
            target = result.get("Target", "")
            misconfigs = result.get("Misconfigurations", [])

            for misconfig in misconfigs:
                issue = self._create_misconfig_issue(misconfig, target)
                if issue:
                    issues.append(issue)

        return issues

    def _parse_secret_results(self, output: str) -> List[Issue]:
        """Parse Trivy secret scan output.

        Args:
            output: JSON output from Trivy

        Returns:
            List of Issue objects
        """
        issues = []
        data = self._parse_json_output(output)

        if not data:
            return issues

        results = data.get("Results", [])

        for result in results:
            target = result.get("Target", "")
            secrets = result.get("Secrets", [])

            for secret in secrets:
                issue = self._create_secret_issue(secret, target)
                if issue:
                    issues.append(issue)

        return issues

    def _create_vulnerability_issue(
        self,
        vuln: Dict[str, Any],
        target: str,
    ) -> Optional[Issue]:
        """Create an Issue from a vulnerability finding.

        Args:
            vuln: Vulnerability data from Trivy
            target: Target file/package

        Returns:
            Issue object or None
        """
        vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
        severity_str = vuln.get("Severity", "UNKNOWN")
        severity = self.SEVERITY_MAP.get(severity_str, Severity.INFO)

        pkg_name = vuln.get("PkgName", "unknown")
        installed_version = vuln.get("InstalledVersion", "")
        fixed_version = vuln.get("FixedVersion", "")

        title = f"{vuln_id}: {vuln.get('Title', 'Vulnerability in ' + pkg_name)}"

        description = vuln.get("Description", "No description available")
        if len(description) > 500:
            description = description[:500] + "..."

        remediation = None
        if fixed_version:
            remediation = f"Update {pkg_name} from {installed_version} to {fixed_version}"

        references = vuln.get("References", [])[:5]  # Limit references

        issue_id = self._generate_issue_id(vuln_id, target, pkg_name)

        return Issue(
            id=issue_id,
            title=title,
            description=description,
            severity=severity,
            category=IssueCategory.SECURITY,
            file_path=target,
            rule_id=vuln_id,
            scanner=self.name,
            remediation=remediation,
            references=references,
            auto_fixable=bool(fixed_version),
            fix_suggestion=remediation,
            metadata={
                "package_name": pkg_name,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                "data_source": vuln.get("DataSource", {}),
            },
        )

    def _create_misconfig_issue(
        self,
        misconfig: Dict[str, Any],
        target: str,
    ) -> Optional[Issue]:
        """Create an Issue from a misconfiguration finding.

        Args:
            misconfig: Misconfiguration data from Trivy
            target: Target file

        Returns:
            Issue object or None
        """
        misconfig_id = misconfig.get("ID", "UNKNOWN")
        severity_str = misconfig.get("Severity", "MEDIUM")
        severity = self.MISCONFIG_SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        title = misconfig.get("Title", "Configuration Issue")
        description = misconfig.get("Description", misconfig.get("Message", ""))

        remediation = misconfig.get("Resolution", None)
        references = misconfig.get("References", [])[:5]

        # Get line numbers if available
        cause_metadata = misconfig.get("CauseMetadata", {})
        start_line = cause_metadata.get("StartLine")
        end_line = cause_metadata.get("EndLine")

        issue_id = self._generate_issue_id(misconfig_id, target, str(start_line))

        return Issue(
            id=issue_id,
            title=f"{misconfig_id}: {title}",
            description=description,
            severity=severity,
            category=IssueCategory.SECURITY,
            file_path=target,
            line_number=start_line,
            rule_id=misconfig_id,
            scanner=self.name,
            remediation=remediation,
            references=references,
            auto_fixable=False,  # Misconfigs usually need manual review
            metadata={
                "avd_id": misconfig.get("AVDID"),
                "type": misconfig.get("Type"),
                "start_line": start_line,
                "end_line": end_line,
                "code": cause_metadata.get("Code"),
            },
        )

    def _create_secret_issue(
        self,
        secret: Dict[str, Any],
        target: str,
    ) -> Optional[Issue]:
        """Create an Issue from a secret finding.

        Args:
            secret: Secret data from Trivy
            target: Target file

        Returns:
            Issue object or None
        """
        rule_id = secret.get("RuleID", "SECRET")
        category = secret.get("Category", "Secret")
        title = secret.get("Title", f"Exposed {category}")
        severity = Severity.CRITICAL  # Secrets are always critical

        start_line = secret.get("StartLine")
        end_line = secret.get("EndLine")
        match = secret.get("Match", "")

        # Mask the actual secret value
        if len(match) > 10:
            masked_match = match[:5] + "..." + match[-5:]
        else:
            masked_match = "***"

        description = f"Potential secret or credential exposed: {category}. " \
                      f"Found pattern matching: {masked_match}"

        issue_id = self._generate_issue_id(rule_id, target, str(start_line))

        return Issue(
            id=issue_id,
            title=title,
            description=description,
            severity=severity,
            category=IssueCategory.SECURITY,
            file_path=target,
            line_number=start_line,
            rule_id=rule_id,
            scanner=self.name,
            remediation="Remove the secret from the code and rotate the credential. "
                       "Use environment variables or a secret management solution.",
            auto_fixable=False,  # Secrets need manual handling
            metadata={
                "category": category,
                "start_line": start_line,
                "end_line": end_line,
            },
        )

    def _generate_issue_id(self, *components: str) -> str:
        """Generate a unique issue ID from components.

        Args:
            *components: Strings to hash for the ID

        Returns:
            Unique issue ID
        """
        combined = "|".join(str(c) for c in components if c)
        hash_value = hashlib.md5(combined.encode()).hexdigest()[:12]
        return f"TRIVY-{hash_value}"

    def _deduplicate_issues(self, issues: List[Issue]) -> List[Issue]:
        """Remove duplicate issues based on ID.

        Args:
            issues: List of issues

        Returns:
            Deduplicated list
        """
        seen_ids = set()
        unique_issues = []

        for issue in issues:
            if issue.id not in seen_ids:
                seen_ids.add(issue.id)
                unique_issues.append(issue)

        return unique_issues
