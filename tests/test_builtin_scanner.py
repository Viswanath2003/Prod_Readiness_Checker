"""Tests for the built-in secret scanner."""

import asyncio
import pytest
import tempfile
from pathlib import Path

from src.scanners.security.builtin_secret_scanner import BuiltinSecretScanner
from src.core.scanner import Severity


class TestBuiltinSecretScanner:
    """Tests for BuiltinSecretScanner class."""

    def test_scanner_is_available(self):
        """Test that built-in scanner is always available."""
        scanner = BuiltinSecretScanner()
        assert scanner.is_available() == True

    def test_detect_hardcoded_password(self):
        """Test detection of hardcoded passwords."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "config.yaml"
            test_file.write_text("""
database:
  host: localhost
  password: admin123
  username: admin
""")

            scanner = BuiltinSecretScanner()
            result = asyncio.run(scanner.scan(tmpdir))

            assert result.success == True
            assert result.issue_count >= 1

            # Check that password was detected
            password_issues = [i for i in result.issues if 'password' in i.rule_id.lower()]
            assert len(password_issues) >= 1

    def test_detect_api_key(self):
        """Test detection of API keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "settings.json"
            test_file.write_text("""
{
  "api_key": "sk-1234567890abcdef1234567890abcdef",
  "endpoint": "https://api.example.com"
}
""")

            scanner = BuiltinSecretScanner()
            result = asyncio.run(scanner.scan(tmpdir))

            assert result.success == True
            assert result.issue_count >= 1

    def test_detect_aws_credentials(self):
        """Test detection of AWS credentials."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "aws.env"
            test_file.write_text("""
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
""")

            scanner = BuiltinSecretScanner()
            result = asyncio.run(scanner.scan(tmpdir))

            assert result.success == True
            # AWS keys should be detected
            aws_issues = [i for i in result.issues if 'aws' in i.rule_id.lower()]
            assert len(aws_issues) >= 1

    def test_detect_jwt_token(self):
        """Test detection of JWT tokens."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "auth.config"
            test_file.write_text("""
auth_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
""")

            scanner = BuiltinSecretScanner()
            result = asyncio.run(scanner.scan(tmpdir))

            assert result.success == True
            jwt_issues = [i for i in result.issues if 'jwt' in i.rule_id.lower()]
            assert len(jwt_issues) >= 1

    def test_detect_database_connection_string(self):
        """Test detection of database connection strings with credentials."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "database.config"
            test_file.write_text("""
connection_string: postgresql://admin:secretpassword@localhost:5432/mydb
""")

            scanner = BuiltinSecretScanner()
            result = asyncio.run(scanner.scan(tmpdir))

            assert result.success == True
            db_issues = [i for i in result.issues if 'database' in i.rule_id.lower()]
            assert len(db_issues) >= 1

    def test_ignore_placeholder_values(self):
        """Test that placeholder values are ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "config.yaml"
            test_file.write_text("""
database:
  password: ${DATABASE_PASSWORD}
  api_key: <your-api-key-here>
  secret: changeme
""")

            scanner = BuiltinSecretScanner()
            result = asyncio.run(scanner.scan(tmpdir))

            # Placeholders should be ignored
            assert result.issue_count == 0

    def test_ignore_comments(self):
        """Test that comments are ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "config.yaml"
            test_file.write_text("""
# password: admin123
# api_key: sk-1234567890abcdef
database:
  host: localhost
""")

            scanner = BuiltinSecretScanner()
            result = asyncio.run(scanner.scan(tmpdir))

            # Comments should be ignored
            assert result.issue_count == 0

    def test_severity_levels(self):
        """Test that different secret types have appropriate severity."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "secrets.yaml"
            test_file.write_text("""
aws_access_key_id: AKIAIOSFODNN7EXAMPLE
password: simplepassword123
""")

            scanner = BuiltinSecretScanner()
            result = asyncio.run(scanner.scan(tmpdir))

            # AWS keys should be CRITICAL
            aws_issues = [i for i in result.issues if 'aws' in i.rule_id.lower()]
            if aws_issues:
                assert aws_issues[0].severity == Severity.CRITICAL

    def test_scan_multiple_files(self):
        """Test scanning multiple files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple files with secrets
            (Path(tmpdir) / "config1.yaml").write_text("password: secret1")
            (Path(tmpdir) / "config2.yaml").write_text("api_key: sk-abcdef1234567890abcdef")

            scanner = BuiltinSecretScanner()
            result = asyncio.run(scanner.scan(tmpdir))

            assert result.success == True
            assert result.issue_count >= 2

    def test_masked_secret_in_description(self):
        """Test that secrets are masked in issue descriptions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "config.yaml"
            test_file.write_text("password: verylongsecretpassword123")

            scanner = BuiltinSecretScanner()
            result = asyncio.run(scanner.scan(tmpdir))

            if result.issues:
                issue = result.issues[0]
                # The full secret should not appear in the description
                assert "verylongsecretpassword123" not in issue.description

    def test_remediation_provided(self):
        """Test that remediation advice is provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "config.yaml"
            test_file.write_text("password: secretvalue123")

            scanner = BuiltinSecretScanner()
            result = asyncio.run(scanner.scan(tmpdir))

            if result.issues:
                issue = result.issues[0]
                assert issue.remediation is not None
                assert len(issue.remediation) > 0


class TestBuiltinSecretScannerWithRealFile:
    """Tests using the actual test data file."""

    def test_scan_secrets_yaml(self):
        """Test scanning the test secrets.yml file."""
        test_file = Path(__file__).parent / "test_data" / "secrets.yml"

        if not test_file.exists():
            pytest.skip("Test data file not found")

        scanner = BuiltinSecretScanner()
        result = asyncio.run(scanner.scan(str(test_file.parent)))

        assert result.success == True
        # Should detect multiple secrets
        assert result.issue_count >= 3

        # Print issues for debugging
        print(f"\nDetected {result.issue_count} issues:")
        for issue in result.issues:
            print(f"  - [{issue.severity.value}] {issue.title} ({issue.file_path}:{issue.line_number})")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
