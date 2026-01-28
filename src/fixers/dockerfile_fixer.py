"""Dockerfile Fixer - Automated fixes for Dockerfile security issues."""

import re
from pathlib import Path
from typing import List, Optional

from .base_fixer import BaseFixer, Fix
from ..core.scanner import Issue


class DockerfileFixer(BaseFixer):
    """Fixer for common Dockerfile security issues."""

    # Mapping of rule patterns to fix functions
    FIX_HANDLERS = {
        "DS001": "_fix_root_user",
        "DS002": "_fix_root_user",
        "DS003": "_fix_sudo_usage",
        "DS004": "_fix_apt_get_upgrade",
        "DS005": "_fix_add_instead_of_copy",
        "DS006": "_fix_apt_get_clean",
        "DS007": "_fix_pip_trusted_host",
        "DS008": "_fix_curl_no_verify",
        "DS009": "_fix_wget_no_check",
        "DS010": "_fix_apk_no_cache",
        "DS011": "_fix_yum_clean",
        "DS012": "_fix_healthcheck",
        "DS013": "_fix_copy_chown",
        "DS014": "_fix_pip_no_cache",
        "DS015": "_fix_apt_get_no_install_recommends",
        # Trivy/Checkov rules
        "CKV_DOCKER_1": "_fix_root_user",
        "CKV_DOCKER_2": "_fix_healthcheck",
        "CKV_DOCKER_3": "_fix_add_instead_of_copy",
        "CKV_DOCKER_7": "_fix_latest_tag",
        "CKV_DOCKER_8": "_fix_root_user",
        "AVD-DS-0001": "_fix_root_user",
        "AVD-DS-0002": "_fix_root_user",
    }

    @property
    def name(self) -> str:
        return "dockerfile"

    @property
    def supported_rules(self) -> List[str]:
        return list(self.FIX_HANDLERS.keys()) + ["DS*", "CKV_DOCKER_*", "AVD-DS-*"]

    def generate_fix(self, issue: Issue) -> Optional[Fix]:
        """Generate a fix for Dockerfile issues.

        Args:
            issue: Issue to fix

        Returns:
            Fix object or None
        """
        if not issue.file_path:
            return None

        content = self._read_file_content(issue.file_path)
        if not content:
            return None

        # Find the appropriate fix handler
        handler_name = None
        if issue.rule_id in self.FIX_HANDLERS:
            handler_name = self.FIX_HANDLERS[issue.rule_id]
        else:
            # Try pattern matching
            for pattern, handler in self.FIX_HANDLERS.items():
                if pattern.endswith("*") and issue.rule_id.startswith(pattern[:-1]):
                    handler_name = handler
                    break

        if not handler_name:
            return None

        handler = getattr(self, handler_name, None)
        if not handler:
            return None

        return handler(issue, content)

    def _fix_root_user(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add USER instruction to not run as root."""
        # Check if USER instruction already exists
        if re.search(r"^\s*USER\s+(?!root)", content, re.MULTILINE):
            return None

        # Find the last CMD or ENTRYPOINT instruction
        lines = content.splitlines()
        insert_index = len(lines)

        for i, line in enumerate(lines):
            if re.match(r"^\s*(CMD|ENTRYPOINT)", line, re.IGNORECASE):
                insert_index = i
                break

        # Build the fix
        original = "\n".join(lines[max(0, insert_index - 1):insert_index + 1])

        # Add USER instruction with a non-root user
        user_instruction = "# Run as non-root user for security\nUSER 1001"
        fixed_lines = lines.copy()
        fixed_lines.insert(insert_index, user_instruction)
        fixed_lines.insert(insert_index, "")

        fixed = "\n".join(fixed_lines[max(0, insert_index - 1):insert_index + 4])

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add non-root USER instruction for security",
            original_content=original,
            fixed_content=fixed,
            line_start=insert_index,
            confidence=0.85,
            requires_review=True,
            review_notes="Verify that the application can run as non-root user (UID 1001). "
                        "You may need to adjust file permissions or use a named user.",
        )

    def _fix_healthcheck(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add HEALTHCHECK instruction."""
        if "HEALTHCHECK" in content:
            return None

        # Find appropriate location (before CMD/ENTRYPOINT)
        lines = content.splitlines()
        insert_index = len(lines)

        for i, line in enumerate(lines):
            if re.match(r"^\s*(CMD|ENTRYPOINT)", line, re.IGNORECASE):
                insert_index = i
                break

        original = "\n".join(lines[max(0, insert_index - 1):insert_index + 1])

        # Add generic healthcheck
        healthcheck = """# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8080/health || exit 1"""

        fixed_lines = lines.copy()
        fixed_lines.insert(insert_index, healthcheck)
        fixed_lines.insert(insert_index, "")

        fixed = "\n".join(fixed_lines[max(0, insert_index - 1):insert_index + 5])

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add HEALTHCHECK instruction for container health monitoring",
            original_content=original,
            fixed_content=fixed,
            line_start=insert_index,
            confidence=0.7,
            requires_review=True,
            review_notes="Update the health check URL and port to match your application's health endpoint.",
        )

    def _fix_add_instead_of_copy(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Replace ADD with COPY when not extracting archives."""
        line_num = issue.line_number
        if not line_num:
            return None

        lines = content.splitlines()
        if line_num > len(lines):
            return None

        line = lines[line_num - 1]

        # Only fix if ADD is not for URL or archive extraction
        if not re.match(r"^\s*ADD\s+", line, re.IGNORECASE):
            return None

        # Check if it's extracting an archive or fetching URL
        if re.search(r"(https?://|\.tar|\.gz|\.bz2|\.xz)", line, re.IGNORECASE):
            return None

        # Replace ADD with COPY
        fixed_line = re.sub(r"^\s*ADD\s+", "COPY ", line, flags=re.IGNORECASE)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Replace ADD with COPY (ADD is only needed for URL fetching or archive extraction)",
            original_content=line,
            fixed_content=fixed_line,
            line_start=line_num,
            confidence=0.95,
        )

    def _fix_apt_get_clean(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add apt-get clean and rm -rf /var/lib/apt/lists/*"""
        # Find apt-get install commands without cleanup
        pattern = r"(RUN\s+apt-get\s+(?:update\s+&&\s+)?apt-get\s+install[^\n]+)(?!\s*&&\s*(?:apt-get\s+clean|rm\s+-rf))"

        match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
        if not match:
            return None

        original = match.group(0)
        cleaned = original.rstrip() + " \\\n    && apt-get clean \\\n    && rm -rf /var/lib/apt/lists/*"

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add apt-get clean to reduce image size and remove package cache",
            original_content=original,
            fixed_content=cleaned,
            confidence=0.9,
        )

    def _fix_latest_tag(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Replace :latest tag with specific version."""
        # Find FROM instructions with :latest or no tag
        pattern = r"(FROM\s+)([a-zA-Z0-9._/-]+)(:latest)?\s*(\n|$)"

        def replace_tag(match):
            prefix = match.group(1)
            image = match.group(2)
            ending = match.group(4)

            # Suggest a version placeholder
            return f"{prefix}{image}:VERSION_TO_SPECIFY{ending}"

        if not re.search(pattern, content):
            return None

        # Find first match
        match = re.search(pattern, content)
        original = match.group(0).rstrip()
        fixed = re.sub(pattern, replace_tag, original + "\n").rstrip()

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Specify explicit version tag instead of :latest for reproducible builds",
            original_content=original,
            fixed_content=fixed,
            confidence=0.7,
            requires_review=True,
            review_notes="Replace VERSION_TO_SPECIFY with the actual version you want to use. "
                        "Check Docker Hub for available tags.",
        )

    def _fix_sudo_usage(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Remove sudo from RUN commands (not needed in Docker)."""
        pattern = r"(RUN\s+)sudo\s+"

        if not re.search(pattern, content):
            return None

        original_match = re.search(pattern + r"[^\n]+", content)
        if not original_match:
            return None

        original = original_match.group(0)
        fixed = re.sub(r"sudo\s+", "", original)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Remove sudo (not needed in Docker containers, commands run as root by default)",
            original_content=original,
            fixed_content=fixed,
            confidence=0.95,
        )

    def _fix_apt_get_upgrade(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Remove apt-get upgrade/dist-upgrade (use specific packages instead)."""
        pattern = r"(&&\s*)?apt-get\s+(upgrade|dist-upgrade)(\s*&&)?"

        if not re.search(pattern, content, re.IGNORECASE):
            return None

        # Find the full RUN line
        run_match = re.search(r"RUN[^\n]*(" + pattern + r")[^\n]*", content, re.IGNORECASE)
        if not run_match:
            return None

        original = run_match.group(0)
        fixed = re.sub(pattern, "", original, flags=re.IGNORECASE)
        # Clean up any double && or leading &&
        fixed = re.sub(r"&&\s*&&", "&&", fixed)
        fixed = re.sub(r"RUN\s*&&", "RUN ", fixed)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Remove apt-get upgrade (pins should be used for specific package versions)",
            original_content=original,
            fixed_content=fixed,
            confidence=0.8,
            requires_review=True,
            review_notes="Consider pinning specific package versions instead of upgrading all packages.",
        )

    def _fix_pip_trusted_host(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Remove --trusted-host from pip commands."""
        pattern = r"--trusted-host\s+[^\s]+"

        if not re.search(pattern, content):
            return None

        run_match = re.search(r"RUN[^\n]*(" + pattern + r")[^\n]*", content)
        if not run_match:
            return None

        original = run_match.group(0)
        fixed = re.sub(pattern, "", original)
        fixed = re.sub(r"\s+", " ", fixed)  # Clean up extra spaces

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Remove --trusted-host flag (allows MITM attacks)",
            original_content=original,
            fixed_content=fixed,
            confidence=0.95,
        )

    def _fix_curl_no_verify(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Remove -k/--insecure from curl commands."""
        pattern = r"curl[^\n]*(\s+-k|\s+--insecure)"

        if not re.search(pattern, content):
            return None

        run_match = re.search(r"RUN[^\n]*" + pattern + r"[^\n]*", content)
        if not run_match:
            return None

        original = run_match.group(0)
        fixed = re.sub(r"\s+(-k|--insecure)", "", original)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Remove --insecure flag from curl (disables SSL verification)",
            original_content=original,
            fixed_content=fixed,
            confidence=0.95,
        )

    def _fix_wget_no_check(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Remove --no-check-certificate from wget commands."""
        pattern = r"wget[^\n]*(--no-check-certificate)"

        if not re.search(pattern, content):
            return None

        run_match = re.search(r"RUN[^\n]*" + pattern + r"[^\n]*", content)
        if not run_match:
            return None

        original = run_match.group(0)
        fixed = re.sub(r"\s*--no-check-certificate", "", original)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Remove --no-check-certificate from wget (disables SSL verification)",
            original_content=original,
            fixed_content=fixed,
            confidence=0.95,
        )

    def _fix_apk_no_cache(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add --no-cache to apk add commands."""
        pattern = r"(apk\s+add)(?!\s+--no-cache)"

        if not re.search(pattern, content):
            return None

        run_match = re.search(r"RUN[^\n]*(" + pattern + r")[^\n]*", content)
        if not run_match:
            return None

        original = run_match.group(0)
        fixed = re.sub(pattern, r"\1 --no-cache", original)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add --no-cache to apk add to reduce image size",
            original_content=original,
            fixed_content=fixed,
            confidence=0.95,
        )

    def _fix_yum_clean(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add yum clean all after yum install."""
        pattern = r"(yum\s+install[^\n]+)(?!\s*&&\s*yum\s+clean)"

        if not re.search(pattern, content):
            return None

        run_match = re.search(r"RUN[^\n]*(" + pattern + r")", content)
        if not run_match:
            return None

        original = run_match.group(0)
        fixed = original.rstrip() + " && yum clean all"

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add 'yum clean all' to remove package cache and reduce image size",
            original_content=original,
            fixed_content=fixed,
            confidence=0.9,
        )

    def _fix_copy_chown(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add --chown to COPY instruction."""
        line_num = issue.line_number
        if not line_num:
            return None

        lines = content.splitlines()
        if line_num > len(lines):
            return None

        line = lines[line_num - 1]

        if not re.match(r"^\s*COPY\s+(?!--chown)", line, re.IGNORECASE):
            return None

        # Add --chown with placeholder
        fixed_line = re.sub(
            r"^(\s*COPY)\s+",
            r"\1 --chown=USER:GROUP ",
            line,
            flags=re.IGNORECASE
        )

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add --chown to COPY to set proper file ownership",
            original_content=line,
            fixed_content=fixed_line,
            line_start=line_num,
            confidence=0.7,
            requires_review=True,
            review_notes="Replace USER:GROUP with the actual user and group (e.g., 1001:1001 or appuser:appgroup)",
        )

    def _fix_pip_no_cache(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add --no-cache-dir to pip install."""
        pattern = r"(pip3?\s+install)(?!\s+--no-cache-dir)"

        if not re.search(pattern, content):
            return None

        run_match = re.search(r"RUN[^\n]*(" + pattern + r")[^\n]*", content)
        if not run_match:
            return None

        original = run_match.group(0)
        fixed = re.sub(pattern, r"\1 --no-cache-dir", original)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add --no-cache-dir to pip install to reduce image size",
            original_content=original,
            fixed_content=fixed,
            confidence=0.95,
        )

    def _fix_apt_get_no_install_recommends(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add --no-install-recommends to apt-get install."""
        pattern = r"(apt-get\s+install)(?!\s+--no-install-recommends)"

        if not re.search(pattern, content):
            return None

        run_match = re.search(r"RUN[^\n]*(" + pattern + r")[^\n]*", content)
        if not run_match:
            return None

        original = run_match.group(0)
        fixed = re.sub(pattern, r"\1 --no-install-recommends", original)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add --no-install-recommends to apt-get install to reduce image size",
            original_content=original,
            fixed_content=fixed,
            confidence=0.9,
        )
