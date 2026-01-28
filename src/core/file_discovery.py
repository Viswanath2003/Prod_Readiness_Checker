"""File Discovery Module - Discovers and categorizes files for scanning."""

import os
import fnmatch
from pathlib import Path
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
from enum import Enum


class FileCategory(Enum):
    """Categories of files that can be discovered."""
    DOCKERFILE = "dockerfile"
    DOCKER_COMPOSE = "docker_compose"
    KUBERNETES = "kubernetes"
    HELM = "helm"
    TERRAFORM = "terraform"
    ANSIBLE = "ansible"
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    APPLICATION_CONFIG = "application_config"
    SECRETS = "secrets"
    PROMETHEUS = "prometheus"
    GRAFANA = "grafana"
    NGINX = "nginx"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    GO = "go"
    JAVA = "java"
    UNKNOWN = "unknown"


@dataclass
class DiscoveredFile:
    """Represents a discovered file with its metadata."""
    path: Path
    category: FileCategory
    size: int
    extension: str
    relative_path: str


@dataclass
class DiscoveryResult:
    """Result of file discovery operation."""
    root_path: Path
    files: List[DiscoveredFile] = field(default_factory=list)
    categories: Dict[FileCategory, List[DiscoveredFile]] = field(default_factory=dict)
    total_files: int = 0
    errors: List[str] = field(default_factory=list)

    def get_files_by_category(self, category: FileCategory) -> List[DiscoveredFile]:
        """Get all files of a specific category."""
        return self.categories.get(category, [])

    def get_all_paths(self) -> List[str]:
        """Get all file paths as strings."""
        return [str(f.path) for f in self.files]


class FileDiscovery:
    """Discovers and categorizes files in a repository for scanning."""

    # File patterns for each category
    PATTERNS: Dict[FileCategory, List[str]] = {
        FileCategory.DOCKERFILE: [
            "Dockerfile",
            "Dockerfile.*",
            "*.dockerfile",
            "dockerfile",
            "Containerfile",
        ],
        FileCategory.DOCKER_COMPOSE: [
            "docker-compose.yml",
            "docker-compose.yaml",
            "docker-compose.*.yml",
            "docker-compose.*.yaml",
            "compose.yml",
            "compose.yaml",
        ],
        FileCategory.KUBERNETES: [
            "**/k8s/**/*.yaml",
            "**/k8s/**/*.yml",
            "**/kubernetes/**/*.yaml",
            "**/kubernetes/**/*.yml",
            "**/manifests/**/*.yaml",
            "**/manifests/**/*.yml",
            "*-deployment.yaml",
            "*-deployment.yml",
            "*-service.yaml",
            "*-service.yml",
            "*-configmap.yaml",
            "*-configmap.yml",
            "*-secret.yaml",
            "*-secret.yml",
            "*-ingress.yaml",
            "*-ingress.yml",
        ],
        FileCategory.HELM: [
            "**/charts/**/*.yaml",
            "**/charts/**/*.yml",
            "Chart.yaml",
            "Chart.yml",
            "values.yaml",
            "values.yml",
            "values.*.yaml",
            "values.*.yml",
        ],
        FileCategory.TERRAFORM: [
            "*.tf",
            "*.tfvars",
            "*.tf.json",
        ],
        FileCategory.ANSIBLE: [
            "**/ansible/**/*.yaml",
            "**/ansible/**/*.yml",
            "**/playbooks/**/*.yaml",
            "**/playbooks/**/*.yml",
            "ansible.cfg",
        ],
        FileCategory.GITHUB_ACTIONS: [
            ".github/workflows/*.yml",
            ".github/workflows/*.yaml",
        ],
        FileCategory.GITLAB_CI: [
            ".gitlab-ci.yml",
            ".gitlab-ci.yaml",
            "**/.gitlab-ci.yml",
        ],
        FileCategory.JENKINS: [
            "Jenkinsfile",
            "Jenkinsfile.*",
            "jenkins/*.groovy",
        ],
        FileCategory.APPLICATION_CONFIG: [
            "config.yaml",
            "config.yml",
            "config.json",
            "config.toml",
            "application.yml",
            "application.yaml",
            "application.properties",
            "settings.yaml",
            "settings.yml",
            "settings.json",
            "appsettings.json",
            ".env.example",
            ".env.sample",
        ],
        FileCategory.SECRETS: [
            ".env",
            ".env.*",
            "*.pem",
            "*.key",
            "secrets.yaml",
            "secrets.yml",
            "**/secrets/**/*",
        ],
        FileCategory.PROMETHEUS: [
            "prometheus.yml",
            "prometheus.yaml",
            "**/prometheus/**/*.yml",
            "**/prometheus/**/*.yaml",
            "alerting_rules.yml",
            "recording_rules.yml",
        ],
        FileCategory.GRAFANA: [
            "**/grafana/**/*.json",
            "**/dashboards/**/*.json",
            "grafana.ini",
        ],
        FileCategory.NGINX: [
            "nginx.conf",
            "**/nginx/**/*.conf",
            "*.nginx",
        ],
        FileCategory.PYTHON: [
            "*.py",
            "requirements.txt",
            "requirements*.txt",
            "setup.py",
            "pyproject.toml",
            "Pipfile",
            "poetry.lock",
        ],
        FileCategory.JAVASCRIPT: [
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "*.js",
            "*.ts",
            "*.jsx",
            "*.tsx",
        ],
        FileCategory.GO: [
            "go.mod",
            "go.sum",
            "*.go",
        ],
        FileCategory.JAVA: [
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "*.java",
        ],
    }

    # Directories to exclude from scanning
    EXCLUDE_DIRS: Set[str] = {
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        "vendor",
        "venv",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        "dist",
        "build",
        ".eggs",
        "*.egg-info",
        ".terraform",
        ".idea",
        ".vscode",
        "coverage",
        ".nyc_output",
    }

    # File extensions to exclude
    EXCLUDE_EXTENSIONS: Set[str] = {
        ".pyc",
        ".pyo",
        ".class",
        ".o",
        ".so",
        ".dylib",
        ".exe",
        ".dll",
        ".bin",
        ".zip",
        ".tar",
        ".gz",
        ".rar",
        ".7z",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
    }

    def __init__(
        self,
        exclude_dirs: Optional[Set[str]] = None,
        exclude_extensions: Optional[Set[str]] = None,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB default
    ):
        """Initialize the file discovery.

        Args:
            exclude_dirs: Additional directories to exclude
            exclude_extensions: Additional file extensions to exclude
            max_file_size: Maximum file size to process in bytes
        """
        self.exclude_dirs = self.EXCLUDE_DIRS.copy()
        if exclude_dirs:
            self.exclude_dirs.update(exclude_dirs)

        self.exclude_extensions = self.EXCLUDE_EXTENSIONS.copy()
        if exclude_extensions:
            self.exclude_extensions.update(exclude_extensions)

        self.max_file_size = max_file_size

    def discover(self, root_path: str | Path) -> DiscoveryResult:
        """Discover all relevant files in the given path.

        Args:
            root_path: Root directory to scan

        Returns:
            DiscoveryResult containing all discovered files
        """
        root_path = Path(root_path).resolve()
        result = DiscoveryResult(root_path=root_path)

        if not root_path.exists():
            result.errors.append(f"Path does not exist: {root_path}")
            return result

        if not root_path.is_dir():
            result.errors.append(f"Path is not a directory: {root_path}")
            return result

        # Walk through the directory tree
        for current_path in self._walk_directory(root_path):
            try:
                # Get file info
                stat_info = current_path.stat()
                file_size = stat_info.st_size

                # Skip files that are too large
                if file_size > self.max_file_size:
                    continue

                # Determine file category
                category = self._categorize_file(current_path, root_path)

                # Create discovered file entry
                discovered_file = DiscoveredFile(
                    path=current_path,
                    category=category,
                    size=file_size,
                    extension=current_path.suffix.lower(),
                    relative_path=str(current_path.relative_to(root_path)),
                )

                result.files.append(discovered_file)

                # Add to category mapping
                if category not in result.categories:
                    result.categories[category] = []
                result.categories[category].append(discovered_file)

            except (OSError, PermissionError) as e:
                result.errors.append(f"Error processing {current_path}: {e}")

        result.total_files = len(result.files)
        return result

    def _walk_directory(self, root_path: Path):
        """Walk through directory tree, yielding file paths.

        Args:
            root_path: Root directory to walk

        Yields:
            Path objects for each file found
        """
        for dirpath, dirnames, filenames in os.walk(root_path):
            # Filter out excluded directories
            dirnames[:] = [
                d for d in dirnames
                if d not in self.exclude_dirs and not any(
                    fnmatch.fnmatch(d, pattern) for pattern in self.exclude_dirs
                )
            ]

            for filename in filenames:
                file_path = Path(dirpath) / filename

                # Skip excluded extensions
                if file_path.suffix.lower() in self.exclude_extensions:
                    continue

                yield file_path

    def _categorize_file(self, file_path: Path, root_path: Path) -> FileCategory:
        """Categorize a file based on its name and location.

        Args:
            file_path: Path to the file
            root_path: Root directory for relative path calculation

        Returns:
            FileCategory for the file
        """
        relative_path = str(file_path.relative_to(root_path))
        filename = file_path.name

        # Check each category's patterns
        for category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                # Check if pattern matches filename or relative path
                if fnmatch.fnmatch(filename, pattern):
                    return category
                if fnmatch.fnmatch(relative_path, pattern):
                    return category
                # Handle glob patterns with **
                if "**" in pattern:
                    # Convert glob pattern to fnmatch pattern
                    fnmatch_pattern = pattern.replace("**/", "*")
                    if fnmatch.fnmatch(relative_path, fnmatch_pattern):
                        return category

        return FileCategory.UNKNOWN

    def discover_by_category(
        self,
        root_path: str | Path,
        categories: List[FileCategory],
    ) -> DiscoveryResult:
        """Discover files filtered by specific categories.

        Args:
            root_path: Root directory to scan
            categories: List of categories to include

        Returns:
            DiscoveryResult containing only files of specified categories
        """
        full_result = self.discover(root_path)

        # Filter to only requested categories
        filtered_files = [
            f for f in full_result.files if f.category in categories
        ]

        filtered_categories = {
            cat: files for cat, files in full_result.categories.items()
            if cat in categories
        }

        return DiscoveryResult(
            root_path=full_result.root_path,
            files=filtered_files,
            categories=filtered_categories,
            total_files=len(filtered_files),
            errors=full_result.errors,
        )

    def get_security_relevant_files(self, root_path: str | Path) -> DiscoveryResult:
        """Get files relevant for security scanning.

        Args:
            root_path: Root directory to scan

        Returns:
            DiscoveryResult with security-relevant files
        """
        security_categories = [
            FileCategory.DOCKERFILE,
            FileCategory.DOCKER_COMPOSE,
            FileCategory.KUBERNETES,
            FileCategory.HELM,
            FileCategory.TERRAFORM,
            FileCategory.SECRETS,
            FileCategory.APPLICATION_CONFIG,
            FileCategory.GITHUB_ACTIONS,
            FileCategory.GITLAB_CI,
        ]
        return self.discover_by_category(root_path, security_categories)

    def get_infrastructure_files(self, root_path: str | Path) -> DiscoveryResult:
        """Get infrastructure configuration files.

        Args:
            root_path: Root directory to scan

        Returns:
            DiscoveryResult with infrastructure files
        """
        infra_categories = [
            FileCategory.DOCKERFILE,
            FileCategory.DOCKER_COMPOSE,
            FileCategory.KUBERNETES,
            FileCategory.HELM,
            FileCategory.TERRAFORM,
            FileCategory.ANSIBLE,
            FileCategory.NGINX,
        ]
        return self.discover_by_category(root_path, infra_categories)

    def get_monitoring_files(self, root_path: str | Path) -> DiscoveryResult:
        """Get monitoring and observability configuration files.

        Args:
            root_path: Root directory to scan

        Returns:
            DiscoveryResult with monitoring files
        """
        monitoring_categories = [
            FileCategory.PROMETHEUS,
            FileCategory.GRAFANA,
        ]
        return self.discover_by_category(root_path, monitoring_categories)
