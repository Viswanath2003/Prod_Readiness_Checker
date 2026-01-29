"""Built-in Secret Scanner - Detects hardcoded secrets without external dependencies."""

import re
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ...core.scanner import (
    BaseScanner,
    Issue,
    IssueCategory,
    ScanResult,
    Severity,
)


class BuiltinSecretScanner(BaseScanner):
    """Built-in secret scanner that detects hardcoded secrets without external tools.

    This scanner uses regex patterns to detect:
    - Hardcoded passwords in config files
    - API keys and tokens
    - Database connection strings
    - Private keys
    - AWS/GCP/Azure credentials
    """

    # Common secret patterns with their severity
    SECRET_PATTERNS: List[Tuple[str, str, Severity, str]] = [
        # Passwords in various formats (YAML, config files, code)
        (r'password\s*[=:]\s*["\']?([^"\'\s\n]{4,})["\']?', 'hardcoded-password', Severity.CRITICAL, 'Hardcoded password detected'),
        (r'passwd\s*[=:]\s*["\']?([^"\'\s\n]{4,})["\']?', 'hardcoded-password', Severity.CRITICAL, 'Hardcoded password detected'),
        (r'pwd\s*[=:]\s*["\']?([^"\'\s\n]{4,})["\']?', 'hardcoded-password', Severity.HIGH, 'Possible hardcoded password'),
        (r'secret\s*[=:]\s*["\']?([^"\'\s\n]{4,})["\']?', 'hardcoded-secret', Severity.CRITICAL, 'Hardcoded secret detected'),

        # Kubernetes Secret plaintext values (should be base64, but often hardcoded as plaintext)
        (r'^\s*password\s*:\s*([a-zA-Z0-9_\-!@#$%^&*]{4,})$', 'k8s-secret-password', Severity.CRITICAL, 'Kubernetes Secret with plaintext password'),
        (r'^\s*apikey\s*:\s*([a-zA-Z0-9_\-]{8,})$', 'k8s-secret-apikey', Severity.CRITICAL, 'Kubernetes Secret with plaintext API key'),
        (r'^\s*api[_-]?key\s*:\s*([a-zA-Z0-9_\-]{8,})$', 'k8s-secret-apikey', Severity.CRITICAL, 'Kubernetes Secret with plaintext API key'),
        (r'^\s*secret[_-]?key\s*:\s*([a-zA-Z0-9_\-]{8,})$', 'k8s-secret-key', Severity.CRITICAL, 'Kubernetes Secret with plaintext secret key'),
        (r'^\s*token\s*:\s*([a-zA-Z0-9_\-]{8,})$', 'k8s-secret-token', Severity.HIGH, 'Kubernetes Secret with plaintext token'),
        (r'^\s*credentials?\s*:\s*([a-zA-Z0-9_\-]{8,})$', 'k8s-secret-credentials', Severity.HIGH, 'Kubernetes Secret with plaintext credentials'),

        # API Keys and Tokens
        (r'api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{8,})["\']?', 'api-key', Severity.CRITICAL, 'API key detected'),
        (r'apikey\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{8,})["\']?', 'api-key', Severity.CRITICAL, 'API key detected'),
        (r'token\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', 'auth-token', Severity.HIGH, 'Authentication token detected'),
        (r'auth[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', 'auth-token', Severity.CRITICAL, 'Auth token detected'),
        (r'access[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', 'access-token', Severity.CRITICAL, 'Access token detected'),
        (r'bearer\s+([a-zA-Z0-9_\-\.]{20,})', 'bearer-token', Severity.CRITICAL, 'Bearer token detected'),

        # AWS Credentials
        (r'AKIA[0-9A-Z]{16}', 'aws-access-key', Severity.CRITICAL, 'AWS Access Key ID detected'),
        (r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', 'aws-secret-key', Severity.CRITICAL, 'AWS Secret Access Key detected'),
        (r'aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?(AKIA[0-9A-Z]{16})["\']?', 'aws-access-key', Severity.CRITICAL, 'AWS Access Key ID detected'),

        # Database Connection Strings
        (r'(mysql|postgresql|postgres|mongodb|redis)://[^"\'\s]+:[^@"\'\s]+@', 'database-url', Severity.CRITICAL, 'Database connection string with credentials'),
        (r'jdbc:[a-z]+://[^"\'\s]+:[^@"\'\s]+@', 'jdbc-url', Severity.CRITICAL, 'JDBC connection string with credentials'),

        # Private Keys
        (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'private-key', Severity.CRITICAL, 'Private key detected'),
        (r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----', 'ec-private-key', Severity.CRITICAL, 'EC Private key detected'),
        (r'-----BEGIN\s+PGP\s+PRIVATE\s+KEY-----', 'pgp-private-key', Severity.CRITICAL, 'PGP Private key detected'),

        # GitHub/GitLab Tokens
        (r'ghp_[a-zA-Z0-9]{36}', 'github-pat', Severity.CRITICAL, 'GitHub Personal Access Token detected'),
        (r'gho_[a-zA-Z0-9]{36}', 'github-oauth', Severity.CRITICAL, 'GitHub OAuth Token detected'),
        (r'ghu_[a-zA-Z0-9]{36}', 'github-user-token', Severity.CRITICAL, 'GitHub User Token detected'),
        (r'ghs_[a-zA-Z0-9]{36}', 'github-server-token', Severity.CRITICAL, 'GitHub Server Token detected'),
        (r'glpat-[a-zA-Z0-9\-]{20,}', 'gitlab-pat', Severity.CRITICAL, 'GitLab Personal Access Token detected'),

        # Slack Tokens
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', 'slack-token', Severity.CRITICAL, 'Slack Token detected'),

        # JWT Tokens
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', 'jwt-token', Severity.HIGH, 'JWT Token detected'),

        # Generic secrets in YAML/JSON
        (r'["\']?credentials["\']?\s*:\s*["\']([^"\'\n]{4,})["\']', 'credentials', Severity.HIGH, 'Credentials field detected'),
        (r'["\']?secret[_-]?key["\']?\s*:\s*["\']([^"\'\n]{4,})["\']', 'secret-key', Severity.CRITICAL, 'Secret key detected'),

        # Encryption keys
        (r'encryption[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', 'encryption-key', Severity.CRITICAL, 'Encryption key detected'),
        (r'aes[_-]?key\s*[=:]\s*["\']?([a-fA-F0-9]{32,})["\']?', 'aes-key', Severity.CRITICAL, 'AES key detected'),
    ]

    # Files to scan - config files only, NOT business logic
    SCANNABLE_EXTENSIONS = {
        '.yaml', '.yml', '.json', '.xml', '.properties', '.conf', '.config',
        '.env', '.ini', '.toml', '.tf', '.tfvars',
    }

    # Files that commonly contain secrets
    HIGH_PRIORITY_FILES = {
        'secrets.yaml', 'secrets.yml', 'secret.yaml', 'secret.yml',
        'credentials.yaml', 'credentials.yml', 'credentials.json',
        '.env', '.env.local', '.env.production', '.env.development',
        'config.yaml', 'config.yml', 'application.yml', 'application.yaml',
        'settings.yaml', 'settings.yml', 'settings.json',
        'docker-compose.yml', 'docker-compose.yaml',
        'values.yaml', 'values.yml',  # Helm values
    }

    # Known safe values to ignore (common placeholders/examples)
    SAFE_VALUES = {
        'password', 'changeme', 'changeit', 'secret', 'mysecret',
        'example', 'your-password', 'your-secret', 'xxx', 'yyy',
        'placeholder', 'replace-me', 'todo', 'fixme', '***',
        '${password}', '${secret}', '$(password)', '$(secret)',
        '<password>', '<secret>', 'env:', 'vault:',
    }

    def __init__(
        self,
        include_low_confidence: bool = False,
        scan_all_files: bool = False,
        custom_patterns: Optional[List[Tuple[str, str, Severity, str]]] = None,
    ):
        """Initialize the built-in secret scanner.

        Args:
            include_low_confidence: Include low-confidence matches
            scan_all_files: Scan all files, not just known types
            custom_patterns: Additional regex patterns to check
        """
        super().__init__(name="builtin-secret-scanner", scan_type="security")
        self.include_low_confidence = include_low_confidence
        self.scan_all_files = scan_all_files
        self.patterns = list(self.SECRET_PATTERNS)
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def is_available(self) -> bool:
        """Always available since it's built-in."""
        return True

    async def scan(self, target_path: str | Path) -> ScanResult:
        """Scan for hardcoded secrets.

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

        # Walk through files
        if target_path.is_file():
            issues = self._scan_file(target_path)
            all_issues.extend(issues)
        else:
            for file_path in self._walk_files(target_path):
                issues = self._scan_file(file_path)
                all_issues.extend(issues)

        result.issues = all_issues
        result.metadata = {
            "files_scanned": len(all_issues),
            "patterns_used": len(self.patterns),
        }

        return self._complete_result(result, started_at)

    # Directories to always exclude from scanning (synchronized with cli/main.py)
    EXCLUDED_DIRS = {
        '.git', 'node_modules', 'venv', '.venv', 'env', '.env',
        '__pycache__', '.pytest_cache', '.mypy_cache', '.tox',
        'dist', 'build', '.eggs', 'vendor', 'third_party',
        'htmlcov', '.hypothesis', '.nox', '.coverage',
        'prc_reports',  # PRC output directory - never scan our own reports
        'site-packages',  # Third-party packages - never scan installed libraries
        'lib',  # Common lib directory in virtual envs (lib/pythonX.X/)
    }

    def _walk_files(self, root_path: Path):
        """Walk through files to scan.

        Args:
            root_path: Root directory

        Yields:
            File paths to scan
        """

        for item in root_path.rglob('*'):
            if item.is_file():
                # Skip excluded directories
                if any(excluded in item.parts for excluded in self.EXCLUDED_DIRS):
                    continue

                # Only scan HIGH_PRIORITY_FILES by default (secrets.yaml, .env, etc.)
                # This prevents false positives from general config files
                if self.scan_all_files:
                    yield item
                elif item.name.lower() in self.HIGH_PRIORITY_FILES:
                    yield item
                # Skip SCANNABLE_EXTENSIONS - too aggressive, causes false positives

    def _scan_file(self, file_path: Path) -> List[Issue]:
        """Scan a single file for secrets.

        Args:
            file_path: Path to file

        Returns:
            List of issues found
        """
        issues = []

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return issues

        # Check each line
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            # Skip comments (basic heuristic)
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('--'):
                continue

            # Check each pattern
            for pattern, rule_id, severity, description in self.patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    # Extract the matched secret value
                    if match.groups():
                        secret_value = match.group(1)
                    else:
                        secret_value = match.group(0)

                    # Skip safe/placeholder values
                    if self._is_safe_value(secret_value):
                        continue

                    # Skip very short values (likely false positives)
                    if len(secret_value) < 4:
                        continue

                    issue = self._create_secret_issue(
                        file_path=str(file_path),
                        line_number=line_num,
                        rule_id=rule_id,
                        severity=severity,
                        description=description,
                        secret_value=secret_value,
                        line_content=line,
                    )
                    issues.append(issue)

        return issues

    def _is_safe_value(self, value: str) -> bool:
        """Check if a value is a known safe/placeholder value.

        Args:
            value: Value to check

        Returns:
            True if safe/placeholder
        """
        value_lower = value.lower().strip()

        # Check against known safe values
        if value_lower in self.SAFE_VALUES:
            return True

        # Check for common placeholder patterns
        placeholder_patterns = [
            r'^\$\{.*\}$',  # ${VAR}
            r'^\$\(.*\)$',  # $(VAR)
            r'^<.*>$',      # <placeholder>
            r'^\{\{.*\}\}$',  # {{template}}
            r'^env\.',      # env.VAR
            r'^vault:',     # vault:path
            r'^\*+$',       # ***
            r'^x+$',        # xxx
        ]

        for pattern in placeholder_patterns:
            if re.match(pattern, value_lower):
                return True

        # Check for environment variable references (not hardcoded secrets)
        env_var_patterns = [
            r'os\.getenv\s*\(',      # Python os.getenv()
            r'os\.environ\s*\[',     # Python os.environ[]
            r'getenv\s*\(',          # C/generic getenv()
            r'process\.env\.',       # Node.js process.env.
            r'system\.getenv\s*\(',  # Java System.getenv()
            r'env\s*\[',             # Ruby/generic ENV[]
            r'env:',                 # YAML env reference
            r'configparser',         # Python configparser
            r'config\s*\.\s*get',    # Config getter pattern
        ]

        for pattern in env_var_patterns:
            if re.search(pattern, value_lower):
                return True

        return False

    def _create_secret_issue(
        self,
        file_path: str,
        line_number: int,
        rule_id: str,
        severity: Severity,
        description: str,
        secret_value: str,
        line_content: str,
    ) -> Issue:
        """Create an issue for a detected secret.

        Args:
            file_path: Path to the file
            line_number: Line number
            rule_id: Rule identifier
            severity: Severity level
            description: Description of the issue
            secret_value: The detected secret (will be masked)
            line_content: Full line content

        Returns:
            Issue object
        """
        # Mask the secret for display
        if len(secret_value) > 6:
            masked = secret_value[:3] + '*' * (len(secret_value) - 6) + secret_value[-3:]
        else:
            masked = '*' * len(secret_value)

        issue_id = self._generate_issue_id(rule_id, file_path, str(line_number))

        return Issue(
            id=issue_id,
            title=f"Hardcoded Secret: {description}",
            description=f"A potential hardcoded secret was detected.\n\n"
                       f"File: {file_path}\n"
                       f"Line: {line_number}\n"
                       f"Type: {rule_id}\n"
                       f"Value (masked): {masked}\n\n"
                       f"Hardcoded secrets in source code are a security risk. "
                       f"If this code is committed to version control, the secret "
                       f"may be exposed to unauthorized parties.",
            severity=severity,
            category=IssueCategory.SECURITY,
            file_path=file_path,
            line_number=line_number,
            rule_id=f"SECRET-{rule_id.upper()}",
            scanner=self.name,
            remediation=self._get_remediation(rule_id),
            references=[
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
            auto_fixable=False,
            metadata={
                "secret_type": rule_id,
                "masked_value": masked,
            },
        )

    def _get_remediation(self, rule_id: str) -> str:
        """Get remediation advice for a secret type.

        Args:
            rule_id: Rule identifier

        Returns:
            Remediation text
        """
        common_steps = """
1. IMMEDIATELY rotate/invalidate the exposed secret
2. Remove the hardcoded secret from the source code
3. Use environment variables or a secret management solution:
   - Environment variables for local development
   - Kubernetes Secrets for K8s deployments
   - HashiCorp Vault for production
   - Cloud provider secret managers (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)
4. Add the file to .gitignore if it contains secrets
5. Review git history and remove secrets using git-filter-repo if needed
"""

        specific_advice = {
            'aws-access-key': "\n6. Deactivate the AWS access key in IAM console immediately\n7. Review CloudTrail for unauthorized access",
            'aws-secret-key': "\n6. Rotate the AWS credentials immediately\n7. Review CloudTrail for unauthorized access",
            'github-pat': "\n6. Revoke the token in GitHub Settings > Developer Settings\n7. Create a new token with minimal required permissions",
            'private-key': "\n6. Generate a new key pair\n7. Update all systems using the compromised key\n8. Add the old key to revocation lists",
            'database-url': "\n6. Change the database password immediately\n7. Review database logs for unauthorized access",
        }

        advice = common_steps
        if rule_id in specific_advice:
            advice += specific_advice[rule_id]

        return advice

    def _generate_issue_id(self, *components: str) -> str:
        """Generate a unique issue ID.

        Args:
            *components: Strings to hash

        Returns:
            Unique issue ID
        """
        combined = "|".join(str(c) for c in components if c)
        hash_value = hashlib.md5(combined.encode()).hexdigest()[:12]
        return f"SECRET-{hash_value}"
