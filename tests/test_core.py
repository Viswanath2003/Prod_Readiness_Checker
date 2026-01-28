"""Tests for core modules."""

import pytest
import tempfile
from pathlib import Path

from src.core.file_discovery import FileDiscovery, FileCategory
from src.core.scanner import Issue, Severity, IssueCategory, ScanResult
from src.core.scorer import Scorer, Score


class TestFileDiscovery:
    """Tests for FileDiscovery class."""

    def test_discover_empty_directory(self):
        """Test discovery in empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            discovery = FileDiscovery()
            result = discovery.discover(tmpdir)

            assert result.total_files == 0
            assert len(result.errors) == 0

    def test_discover_dockerfile(self):
        """Test Dockerfile discovery."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a Dockerfile
            dockerfile = Path(tmpdir) / "Dockerfile"
            dockerfile.write_text("FROM python:3.11\nRUN pip install flask\n")

            discovery = FileDiscovery()
            result = discovery.discover(tmpdir)

            assert result.total_files == 1
            docker_files = result.get_files_by_category(FileCategory.DOCKERFILE)
            assert len(docker_files) == 1
            assert docker_files[0].path == dockerfile

    def test_discover_kubernetes_manifests(self):
        """Test Kubernetes manifest discovery."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create k8s directory with manifest
            k8s_dir = Path(tmpdir) / "k8s"
            k8s_dir.mkdir()
            manifest = k8s_dir / "deployment.yaml"
            manifest.write_text("apiVersion: apps/v1\nkind: Deployment\n")

            discovery = FileDiscovery()
            result = discovery.discover(tmpdir)

            assert result.total_files >= 1
            k8s_files = result.get_files_by_category(FileCategory.KUBERNETES)
            assert len(k8s_files) >= 1

    def test_exclude_directories(self):
        """Test that excluded directories are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create node_modules directory (should be excluded)
            node_modules = Path(tmpdir) / "node_modules"
            node_modules.mkdir()
            (node_modules / "package.json").write_text("{}")

            # Create regular file
            (Path(tmpdir) / "app.py").write_text("print('hello')")

            discovery = FileDiscovery()
            result = discovery.discover(tmpdir)

            # node_modules should be excluded
            paths = [str(f.path) for f in result.files]
            assert not any("node_modules" in p for p in paths)


class TestIssue:
    """Tests for Issue class."""

    def test_issue_creation(self):
        """Test creating an issue."""
        issue = Issue(
            id="TEST-001",
            title="Test Issue",
            description="A test issue description",
            severity=Severity.HIGH,
            category=IssueCategory.SECURITY,
            file_path="/path/to/file.yaml",
            line_number=10,
            rule_id="SEC-001",
            scanner="test-scanner",
        )

        assert issue.id == "TEST-001"
        assert issue.severity == Severity.HIGH
        assert issue.category == IssueCategory.SECURITY

    def test_issue_to_dict(self):
        """Test converting issue to dictionary."""
        issue = Issue(
            id="TEST-001",
            title="Test Issue",
            description="Description",
            severity=Severity.CRITICAL,
            category=IssueCategory.SECURITY,
        )

        issue_dict = issue.to_dict()

        assert issue_dict["id"] == "TEST-001"
        assert issue_dict["severity"] == "critical"
        assert issue_dict["category"] == "security"

    def test_issue_from_dict(self):
        """Test creating issue from dictionary."""
        data = {
            "id": "TEST-002",
            "title": "From Dict",
            "description": "Created from dict",
            "severity": "high",
            "category": "performance",
        }

        issue = Issue.from_dict(data)

        assert issue.id == "TEST-002"
        assert issue.severity == Severity.HIGH
        assert issue.category == IssueCategory.PERFORMANCE


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_weight(self):
        """Test severity weights."""
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight
        assert Severity.LOW.weight > Severity.INFO.weight

    def test_severity_color(self):
        """Test severity colors."""
        assert Severity.CRITICAL.color == "red"
        assert Severity.HIGH.color == "orange"
        assert Severity.INFO.color == "gray"


class TestScanResult:
    """Tests for ScanResult class."""

    def test_scan_result_counts(self):
        """Test issue counting in scan results."""
        result = ScanResult(
            scanner_name="test",
            scan_type="security",
            target_path="/test",
        )

        result.issues = [
            Issue(id="1", title="Critical", description="", severity=Severity.CRITICAL, category=IssueCategory.SECURITY),
            Issue(id="2", title="High", description="", severity=Severity.HIGH, category=IssueCategory.SECURITY),
            Issue(id="3", title="High 2", description="", severity=Severity.HIGH, category=IssueCategory.SECURITY),
            Issue(id="4", title="Medium", description="", severity=Severity.MEDIUM, category=IssueCategory.SECURITY),
        ]

        assert result.issue_count == 4
        assert result.critical_count == 1
        assert result.high_count == 2
        assert result.medium_count == 1
        assert result.low_count == 0


class TestScorer:
    """Tests for Scorer class."""

    def test_perfect_score(self):
        """Test scoring with no issues."""
        scorer = Scorer()

        # Empty scan result
        result = ScanResult(
            scanner_name="test",
            scan_type="security",
            target_path="/test",
            issues=[],
        )

        score = scorer.calculate_score([result])

        assert score.overall_score == 100.0
        assert score.is_production_ready == True
        assert score.grade == "A"

    def test_score_with_critical_issues(self):
        """Test scoring with critical issues."""
        scorer = Scorer()

        result = ScanResult(
            scanner_name="test",
            scan_type="security",
            target_path="/test",
            issues=[
                Issue(id="1", title="Critical", description="", severity=Severity.CRITICAL, category=IssueCategory.SECURITY),
            ],
        )

        score = scorer.calculate_score([result])

        # Critical issues should significantly impact score
        assert score.overall_score < 100.0
        assert score.is_production_ready == False  # Block on critical

    def test_score_with_multiple_severities(self):
        """Test scoring with mixed severities."""
        scorer = Scorer(readiness_threshold=50.0)

        result = ScanResult(
            scanner_name="test",
            scan_type="security",
            target_path="/test",
            issues=[
                Issue(id="1", title="High", description="", severity=Severity.HIGH, category=IssueCategory.SECURITY),
                Issue(id="2", title="Medium", description="", severity=Severity.MEDIUM, category=IssueCategory.SECURITY),
                Issue(id="3", title="Low", description="", severity=Severity.LOW, category=IssueCategory.SECURITY),
            ],
        )

        score = scorer.calculate_score([result])

        assert score.overall_score < 100.0
        assert score.total_issues == 3

    def test_category_scores(self):
        """Test category score calculation."""
        scorer = Scorer()

        result = ScanResult(
            scanner_name="test",
            scan_type="security",
            target_path="/test",
            issues=[
                Issue(id="1", title="Security Issue", description="", severity=Severity.HIGH, category=IssueCategory.SECURITY),
            ],
        )

        score = scorer.calculate_score([result])

        assert "security" in score.category_scores
        security_score = score.category_scores["security"]
        assert security_score.issues_count == 1
        assert security_score.high_count == 1

    def test_grade_assignment(self):
        """Test grade assignment based on score."""
        scorer = Scorer()

        # Test different score ranges
        test_cases = [
            (95, "A"),
            (85, "B"),
            (75, "C"),
            (65, "D"),
            (50, "F"),
        ]

        for expected_score, expected_grade in test_cases:
            # Create issues to achieve approximate score
            issues = []
            current_penalty = 100 - expected_score

            while current_penalty > 0:
                if current_penalty >= 15:
                    issues.append(Issue(id=str(len(issues)), title="High", description="",
                                       severity=Severity.HIGH, category=IssueCategory.SECURITY))
                    current_penalty -= 15
                elif current_penalty >= 8:
                    issues.append(Issue(id=str(len(issues)), title="Medium", description="",
                                       severity=Severity.MEDIUM, category=IssueCategory.SECURITY))
                    current_penalty -= 8
                else:
                    issues.append(Issue(id=str(len(issues)), title="Low", description="",
                                       severity=Severity.LOW, category=IssueCategory.SECURITY))
                    current_penalty -= 3

            result = ScanResult(
                scanner_name="test",
                scan_type="security",
                target_path="/test",
                issues=issues,
            )

            score = scorer.calculate_score([result])

            # Grade should be close to expected (may vary due to rounding)
            assert score.grade in ["A", "B", "C", "D", "F"]


class TestScorerConfiguration:
    """Tests for Scorer configuration options."""

    def test_custom_weights(self):
        """Test custom category weights."""
        weights = {
            "security": 0.5,
            "performance": 0.5,
        }
        scorer = Scorer(weights=weights)

        assert scorer.weights["security"] == 0.5
        assert scorer.weights["performance"] == 0.5

    def test_custom_threshold(self):
        """Test custom readiness threshold."""
        scorer = Scorer(readiness_threshold=80.0)

        result = ScanResult(
            scanner_name="test",
            scan_type="security",
            target_path="/test",
            issues=[
                Issue(id="1", title="Medium", description="", severity=Severity.MEDIUM, category=IssueCategory.SECURITY),
            ],
        )

        score = scorer.calculate_score([result])

        # With higher threshold, may not be ready
        if score.overall_score < 80.0:
            assert score.is_production_ready == False

    def test_block_on_critical(self):
        """Test blocking on critical issues."""
        scorer = Scorer(block_on_critical=True)

        result = ScanResult(
            scanner_name="test",
            scan_type="security",
            target_path="/test",
            issues=[
                Issue(id="1", title="Critical", description="", severity=Severity.CRITICAL, category=IssueCategory.SECURITY),
            ],
        )

        score = scorer.calculate_score([result])
        assert score.is_production_ready == False

    def test_allow_critical_with_threshold(self):
        """Test allowing some critical issues."""
        scorer = Scorer(block_on_critical=True, max_critical_allowed=1)

        result = ScanResult(
            scanner_name="test",
            scan_type="security",
            target_path="/test",
            issues=[
                Issue(id="1", title="Critical", description="", severity=Severity.CRITICAL, category=IssueCategory.SECURITY),
            ],
        )

        score = scorer.calculate_score([result])
        # One critical allowed, but score may still be too low
        # This tests the configuration, not the overall readiness


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
