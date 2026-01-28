"""Config Fixer - Automated fixes for general configuration issues."""

import re
from pathlib import Path
from typing import List, Optional

from .base_fixer import BaseFixer, Fix
from ..core.scanner import Issue


class ConfigFixer(BaseFixer):
    """Fixer for general configuration security issues."""

    @property
    def name(self) -> str:
        return "config"

    @property
    def supported_rules(self) -> List[str]:
        return [
            "GENERIC_SECRET_*",
            "SECRET_*",
            "ENV_*",
            "CONFIG_*",
        ]

    def generate_fix(self, issue: Issue) -> Optional[Fix]:
        """Generate a fix for configuration issues.

        Args:
            issue: Issue to fix

        Returns:
            Fix object or None
        """
        if not issue.file_path:
            return None

        # Most config issues (like exposed secrets) require manual intervention
        # We provide guidance rather than automated fixes

        if "secret" in issue.rule_id.lower() or "SECRET" in str(issue.title).upper():
            return self._fix_secret_exposure(issue)

        if "env" in issue.rule_id.lower():
            return self._fix_env_file(issue)

        return None

    def _fix_secret_exposure(self, issue: Issue) -> Fix:
        """Generate guidance for fixing exposed secrets."""
        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Remove exposed secret and use secure secret management",
            original_content="",
            fixed_content="",
            line_start=issue.line_number,
            confidence=0.0,  # Cannot auto-fix secrets
            requires_review=True,
            review_notes="""Steps to fix this secret exposure:
1. IMMEDIATELY rotate/invalidate the exposed secret
2. Remove the secret from the source code
3. Add the file to .gitignore if it should not be committed
4. Use one of these secure alternatives:
   - Environment variables (for local development)
   - Kubernetes Secrets (for K8s deployments)
   - HashiCorp Vault or AWS Secrets Manager (for production)
   - GitHub Actions secrets (for CI/CD)
5. Update any systems using the old secret value
6. Review git history and consider using git-filter-repo to remove the secret from history
7. Add pre-commit hooks to prevent future secret commits (e.g., gitleaks)""",
        )

    def _fix_env_file(self, issue: Issue) -> Fix:
        """Generate guidance for fixing .env file issues."""
        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Secure environment configuration file",
            original_content="",
            fixed_content="",
            confidence=0.0,
            requires_review=True,
            review_notes="""Steps to secure your .env file:
1. Ensure .env is listed in .gitignore
2. Create a .env.example file with placeholder values for documentation
3. Never commit actual secrets to version control
4. Use different .env files for different environments
5. Consider using a secrets manager for production environments
6. Restrict file permissions (chmod 600 .env)""",
        )
