"""Config Performance Scanner - Static analysis of performance configurations."""

import hashlib
import re
import yaml
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from ...core.scanner import (
    BaseScanner,
    Issue,
    IssueCategory,
    ScanResult,
    Severity,
)
from ...core.file_discovery import FileDiscovery, FileCategory


@dataclass
class PerformanceMetrics:
    """Extracted performance metrics from config files."""
    # Resource limits
    cpu_limit_set: bool = False
    cpu_request_set: bool = False
    memory_limit_set: bool = False
    memory_request_set: bool = False

    # Scaling
    replica_count: Optional[int] = None
    hpa_present: bool = False
    hpa_min_replicas: Optional[int] = None
    hpa_max_replicas: Optional[int] = None

    # Timeouts
    http_timeout_seconds: Optional[int] = None
    db_timeout_seconds: Optional[int] = None
    gateway_timeout_seconds: Optional[int] = None

    # Concurrency
    worker_count: Optional[int] = None
    thread_pool_size: Optional[int] = None

    # Connections
    db_pool_size: Optional[int] = None
    max_connections: Optional[int] = None

    # Caching
    cache_present: bool = False
    cache_type: Optional[str] = None
    cache_ttl_seconds: Optional[int] = None

    # Queueing
    queue_present: bool = False
    worker_concurrency: Optional[int] = None

    # Ingress/Edge
    rate_limit_present: bool = False
    keepalive_timeout_seconds: Optional[int] = None

    # Source file
    source_file: str = ""


class ConfigPerformanceScanner(BaseScanner):
    """Static scanner for performance configurations in infrastructure files.

    Scans Kubernetes manifests, Docker configs, Helm charts, and application
    configs to extract and validate performance-related settings.
    """

    # File categories to scan
    SCAN_CATEGORIES = [
        FileCategory.KUBERNETES,
        FileCategory.HELM,
        FileCategory.DOCKER_COMPOSE,
        FileCategory.DOCKERFILE,
        FileCategory.TERRAFORM,
        FileCategory.APPLICATION_CONFIG,
        FileCategory.NGINX,
    ]

    def __init__(self):
        """Initialize the performance scanner."""
        super().__init__(name="performance-scanner", scan_type="performance")
        self.file_discovery = FileDiscovery()

    def is_available(self) -> bool:
        """Always available - no external tools required."""
        return True

    async def scan(self, target_path: str | Path) -> ScanResult:
        """Scan for performance configuration issues.

        Args:
            target_path: Path to scan

        Returns:
            ScanResult with performance issues
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
        all_metrics: List[PerformanceMetrics] = []

        # Discover relevant files
        discovery_result = self.file_discovery.discover_by_category(
            target_path, self.SCAN_CATEGORIES
        )

        # Scan each file
        for discovered_file in discovery_result.files:
            try:
                metrics, issues = self._scan_file(discovered_file.path, discovered_file.category)
                if metrics:
                    metrics.source_file = str(discovered_file.relative_path)
                    all_metrics.append(metrics)
                all_issues.extend(issues)
            except Exception as e:
                # Log error but continue scanning
                pass

        # Generate aggregate issues if no files found
        if not all_metrics:
            all_issues.append(self._create_issue(
                rule_id="PERF-NO-CONFIG",
                title="No Performance Configuration Found",
                description="No Kubernetes, Docker, or infrastructure configuration files found. "
                           "Performance cannot be validated without deployment configurations.",
                severity=Severity.MEDIUM,
                file_path=str(target_path),
                remediation="Add Kubernetes manifests, docker-compose.yml, or other deployment "
                           "configurations to define resource limits and scaling parameters."
            ))

        result.issues = all_issues
        result.metadata = {
            "files_scanned": len(discovery_result.files),
            "metrics_extracted": len(all_metrics),
            "categories_scanned": [c.value for c in self.SCAN_CATEGORIES],
        }

        return self._complete_result(result, started_at)

    def _scan_file(
        self,
        file_path: Path,
        category: FileCategory
    ) -> Tuple[Optional[PerformanceMetrics], List[Issue]]:
        """Scan a single file for performance metrics.

        Args:
            file_path: Path to the file
            category: Category of the file

        Returns:
            Tuple of (metrics, issues)
        """
        metrics = PerformanceMetrics()
        issues: List[Issue] = []

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return None, []

        # Parse based on file type
        if category == FileCategory.KUBERNETES:
            metrics, issues = self._scan_kubernetes(content, file_path)
        elif category == FileCategory.HELM:
            metrics, issues = self._scan_helm(content, file_path)
        elif category == FileCategory.DOCKER_COMPOSE:
            metrics, issues = self._scan_docker_compose(content, file_path)
        elif category == FileCategory.DOCKERFILE:
            metrics, issues = self._scan_dockerfile(content, file_path)
        elif category == FileCategory.APPLICATION_CONFIG:
            metrics, issues = self._scan_app_config(content, file_path)
        elif category == FileCategory.NGINX:
            metrics, issues = self._scan_nginx(content, file_path)
        elif category == FileCategory.TERRAFORM:
            metrics, issues = self._scan_terraform(content, file_path)

        return metrics, issues

    def _scan_kubernetes(
        self, content: str, file_path: Path
    ) -> Tuple[PerformanceMetrics, List[Issue]]:
        """Scan Kubernetes manifest for performance settings."""
        metrics = PerformanceMetrics()
        issues: List[Issue] = []

        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return metrics, issues

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            kind = doc.get('kind', '')
            metadata = doc.get('metadata', {})
            name = metadata.get('name', 'unknown')
            spec = doc.get('spec', {})

            if kind == 'Deployment':
                issues.extend(self._check_deployment(doc, file_path, name))
                metrics = self._extract_deployment_metrics(doc, metrics)

            elif kind == 'HorizontalPodAutoscaler':
                metrics.hpa_present = True
                hpa_spec = spec
                metrics.hpa_min_replicas = hpa_spec.get('minReplicas')
                metrics.hpa_max_replicas = hpa_spec.get('maxReplicas')

            elif kind == 'Service':
                # Check for load balancer type
                svc_type = spec.get('type', 'ClusterIP')
                if svc_type == 'LoadBalancer':
                    # Check for session affinity
                    if not spec.get('sessionAffinity'):
                        issues.append(self._create_issue(
                            rule_id="PERF-NO-SESSION-AFFINITY",
                            title="LoadBalancer without session affinity",
                            description=f"Service '{name}' is a LoadBalancer without session affinity configured.",
                            severity=Severity.LOW,
                            file_path=str(file_path),
                            remediation="Consider setting sessionAffinity if your application requires sticky sessions."
                        ))

            elif kind == 'Ingress':
                issues.extend(self._check_ingress(doc, file_path, name))
                metrics = self._extract_ingress_metrics(doc, metrics)

        return metrics, issues

    def _check_deployment(
        self, doc: Dict, file_path: Path, name: str
    ) -> List[Issue]:
        """Check Deployment for performance issues."""
        issues: List[Issue] = []
        spec = doc.get('spec', {})
        template_spec = spec.get('template', {}).get('spec', {})
        containers = template_spec.get('containers', [])

        replicas = spec.get('replicas', 1)

        # Check replica count
        if replicas == 1:
            issues.append(self._create_issue(
                rule_id="PERF-SINGLE-REPLICA",
                title="Single replica deployment",
                description=f"Deployment '{name}' has only 1 replica, which limits horizontal scaling.",
                severity=Severity.HIGH,
                file_path=str(file_path),
                remediation="Increase replicas to at least 2 for high availability and better load distribution.",
                metadata={"replica_count": replicas}
            ))

        for container in containers:
            container_name = container.get('name', 'unknown')
            resources = container.get('resources', {})
            limits = resources.get('limits', {})
            requests = resources.get('requests', {})

            # Check CPU limits
            if not limits.get('cpu'):
                issues.append(self._create_issue(
                    rule_id="PERF-NO-CPU-LIMIT",
                    title="Missing CPU limit",
                    description=f"Container '{container_name}' in Deployment '{name}' has no CPU limit set.",
                    severity=Severity.HIGH,
                    file_path=str(file_path),
                    remediation="Set resources.limits.cpu to prevent unbounded CPU usage.",
                    metadata={"container": container_name, "deployment": name}
                ))

            # Check CPU requests
            if not requests.get('cpu'):
                issues.append(self._create_issue(
                    rule_id="PERF-NO-CPU-REQUEST",
                    title="Missing CPU request",
                    description=f"Container '{container_name}' in Deployment '{name}' has no CPU request set.",
                    severity=Severity.HIGH,
                    file_path=str(file_path),
                    remediation="Set resources.requests.cpu for proper scheduler resource allocation.",
                    metadata={"container": container_name, "deployment": name}
                ))

            # Check memory limits
            if not limits.get('memory'):
                issues.append(self._create_issue(
                    rule_id="PERF-NO-MEMORY-LIMIT",
                    title="Missing memory limit",
                    description=f"Container '{container_name}' in Deployment '{name}' has no memory limit set.",
                    severity=Severity.HIGH,
                    file_path=str(file_path),
                    remediation="Set resources.limits.memory to prevent OOM issues affecting other pods.",
                    metadata={"container": container_name, "deployment": name}
                ))

            # Check memory requests
            if not requests.get('memory'):
                issues.append(self._create_issue(
                    rule_id="PERF-NO-MEMORY-REQUEST",
                    title="Missing memory request",
                    description=f"Container '{container_name}' in Deployment '{name}' has no memory request set.",
                    severity=Severity.HIGH,
                    file_path=str(file_path),
                    remediation="Set resources.requests.memory for proper scheduler resource allocation.",
                    metadata={"container": container_name, "deployment": name}
                ))

        return issues

    def _check_ingress(
        self, doc: Dict, file_path: Path, name: str
    ) -> List[Issue]:
        """Check Ingress for performance issues."""
        issues: List[Issue] = []
        metadata = doc.get('metadata', {})
        annotations = metadata.get('annotations', {})

        # Check for rate limiting
        rate_limit_keys = [
            'nginx.ingress.kubernetes.io/limit-rps',
            'nginx.ingress.kubernetes.io/limit-connections',
            'nginx.ingress.kubernetes.io/limit-rpm',
        ]

        has_rate_limit = any(key in annotations for key in rate_limit_keys)
        if not has_rate_limit:
            issues.append(self._create_issue(
                rule_id="PERF-NO-RATE-LIMIT",
                title="Ingress without rate limiting",
                description=f"Ingress '{name}' has no rate limiting configured.",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                remediation="Add rate limiting annotations to protect backend services from overload."
            ))

        # Check for connection limits
        if 'nginx.ingress.kubernetes.io/proxy-connect-timeout' not in annotations:
            issues.append(self._create_issue(
                rule_id="PERF-NO-TIMEOUT-CONFIG",
                title="Ingress without timeout configuration",
                description=f"Ingress '{name}' has no proxy timeout configured.",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                remediation="Configure proxy-connect-timeout, proxy-read-timeout, and proxy-send-timeout."
            ))

        return issues

    def _extract_deployment_metrics(
        self, doc: Dict, metrics: PerformanceMetrics
    ) -> PerformanceMetrics:
        """Extract performance metrics from Deployment."""
        spec = doc.get('spec', {})
        template_spec = spec.get('template', {}).get('spec', {})
        containers = template_spec.get('containers', [])

        metrics.replica_count = spec.get('replicas', 1)

        for container in containers:
            resources = container.get('resources', {})
            limits = resources.get('limits', {})
            requests = resources.get('requests', {})

            if limits.get('cpu'):
                metrics.cpu_limit_set = True
            if requests.get('cpu'):
                metrics.cpu_request_set = True
            if limits.get('memory'):
                metrics.memory_limit_set = True
            if requests.get('memory'):
                metrics.memory_request_set = True

        return metrics

    def _extract_ingress_metrics(
        self, doc: Dict, metrics: PerformanceMetrics
    ) -> PerformanceMetrics:
        """Extract performance metrics from Ingress."""
        annotations = doc.get('metadata', {}).get('annotations', {})

        rate_limit_keys = [
            'nginx.ingress.kubernetes.io/limit-rps',
            'nginx.ingress.kubernetes.io/limit-connections',
        ]
        metrics.rate_limit_present = any(key in annotations for key in rate_limit_keys)

        keepalive = annotations.get('nginx.ingress.kubernetes.io/upstream-keepalive-timeout')
        if keepalive:
            try:
                metrics.keepalive_timeout_seconds = int(keepalive)
            except ValueError:
                pass

        return metrics

    def _scan_helm(
        self, content: str, file_path: Path
    ) -> Tuple[PerformanceMetrics, List[Issue]]:
        """Scan Helm values.yaml for performance settings."""
        metrics = PerformanceMetrics()
        issues: List[Issue] = []

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError:
            return metrics, issues

        if not isinstance(data, dict):
            return metrics, issues

        # Check for replica settings
        replicas = data.get('replicaCount', data.get('replicas'))
        if replicas is not None:
            metrics.replica_count = replicas
            if replicas == 1:
                issues.append(self._create_issue(
                    rule_id="PERF-HELM-SINGLE-REPLICA",
                    title="Helm chart with single replica default",
                    description="Helm values specify only 1 replica.",
                    severity=Severity.HIGH,
                    file_path=str(file_path),
                    remediation="Set replicaCount to at least 2 for production deployments."
                ))

        # Check resources section
        resources = data.get('resources', {})
        limits = resources.get('limits', {})
        requests = resources.get('requests', {})

        if not limits:
            issues.append(self._create_issue(
                rule_id="PERF-HELM-NO-LIMITS",
                title="Helm chart without resource limits",
                description="No resource limits defined in Helm values.",
                severity=Severity.HIGH,
                file_path=str(file_path),
                remediation="Define resources.limits.cpu and resources.limits.memory in values.yaml."
            ))
        else:
            metrics.cpu_limit_set = 'cpu' in limits
            metrics.memory_limit_set = 'memory' in limits

        if requests:
            metrics.cpu_request_set = 'cpu' in requests
            metrics.memory_request_set = 'memory' in requests

        # Check for autoscaling
        autoscaling = data.get('autoscaling', {})
        if autoscaling.get('enabled'):
            metrics.hpa_present = True
            metrics.hpa_min_replicas = autoscaling.get('minReplicas')
            metrics.hpa_max_replicas = autoscaling.get('maxReplicas')
        elif not autoscaling:
            issues.append(self._create_issue(
                rule_id="PERF-HELM-NO-HPA",
                title="Helm chart without autoscaling configuration",
                description="No autoscaling (HPA) configuration found in Helm values.",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                remediation="Add autoscaling configuration with minReplicas and maxReplicas."
            ))

        return metrics, issues

    def _scan_docker_compose(
        self, content: str, file_path: Path
    ) -> Tuple[PerformanceMetrics, List[Issue]]:
        """Scan docker-compose.yml for performance settings."""
        metrics = PerformanceMetrics()
        issues: List[Issue] = []

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError:
            return metrics, issues

        if not isinstance(data, dict):
            return metrics, issues

        services = data.get('services', {})

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            # Check deploy section
            deploy = service_config.get('deploy', {})
            resources = deploy.get('resources', {})
            limits = resources.get('limits', {})
            reservations = resources.get('reservations', {})

            # Check replicas
            replicas = deploy.get('replicas', 1)
            if replicas == 1:
                issues.append(self._create_issue(
                    rule_id="PERF-COMPOSE-SINGLE-REPLICA",
                    title="Docker Compose service with single replica",
                    description=f"Service '{service_name}' has only 1 replica.",
                    severity=Severity.MEDIUM,
                    file_path=str(file_path),
                    remediation=f"Set deploy.replicas > 1 for service '{service_name}'."
                ))

            # Check resource limits
            if not limits:
                issues.append(self._create_issue(
                    rule_id="PERF-COMPOSE-NO-LIMITS",
                    title="Docker Compose service without resource limits",
                    description=f"Service '{service_name}' has no resource limits defined.",
                    severity=Severity.HIGH,
                    file_path=str(file_path),
                    remediation=f"Add deploy.resources.limits for service '{service_name}'."
                ))
            else:
                if limits.get('cpus'):
                    metrics.cpu_limit_set = True
                if limits.get('memory'):
                    metrics.memory_limit_set = True

            if reservations:
                if reservations.get('cpus'):
                    metrics.cpu_request_set = True
                if reservations.get('memory'):
                    metrics.memory_request_set = True

        return metrics, issues

    def _scan_dockerfile(
        self, content: str, file_path: Path
    ) -> Tuple[PerformanceMetrics, List[Issue]]:
        """Scan Dockerfile for performance settings."""
        metrics = PerformanceMetrics()
        issues: List[Issue] = []

        lines = content.split('\n')

        # Check for HEALTHCHECK
        has_healthcheck = any(
            line.strip().upper().startswith('HEALTHCHECK')
            for line in lines
        )

        if not has_healthcheck:
            issues.append(self._create_issue(
                rule_id="PERF-DOCKERFILE-NO-HEALTHCHECK",
                title="Dockerfile without HEALTHCHECK",
                description="Dockerfile does not define a HEALTHCHECK instruction.",
                severity=Severity.LOW,
                file_path=str(file_path),
                remediation="Add HEALTHCHECK instruction for container health monitoring."
            ))

        return metrics, issues

    def _scan_app_config(
        self, content: str, file_path: Path
    ) -> Tuple[PerformanceMetrics, List[Issue]]:
        """Scan application config for performance settings."""
        metrics = PerformanceMetrics()
        issues: List[Issue] = []

        # Try to parse as YAML or JSON
        data = None
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError:
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                pass

        if not isinstance(data, dict):
            return metrics, issues

        # Flatten nested dict for easier searching
        flat_config = self._flatten_dict(data)

        # Check for timeout configurations
        timeout_keys = ['timeout', 'connection_timeout', 'read_timeout', 'write_timeout']
        for key, value in flat_config.items():
            key_lower = key.lower()

            # Check timeouts
            if any(tk in key_lower for tk in timeout_keys):
                if isinstance(value, (int, float)):
                    if 'http' in key_lower or 'request' in key_lower:
                        metrics.http_timeout_seconds = int(value)
                    elif 'db' in key_lower or 'database' in key_lower:
                        metrics.db_timeout_seconds = int(value)

            # Check pool sizes
            if 'pool' in key_lower and 'size' in key_lower:
                if isinstance(value, int):
                    metrics.db_pool_size = value

            # Check max connections
            if 'max' in key_lower and 'connection' in key_lower:
                if isinstance(value, int):
                    metrics.max_connections = value

            # Check worker count
            if 'worker' in key_lower and ('count' in key_lower or 'num' in key_lower):
                if isinstance(value, int):
                    metrics.worker_count = value

            # Check thread pool
            if 'thread' in key_lower and 'pool' in key_lower:
                if isinstance(value, int):
                    metrics.thread_pool_size = value

            # Check for cache
            if 'cache' in key_lower:
                if 'redis' in str(value).lower():
                    metrics.cache_present = True
                    metrics.cache_type = 'redis'
                elif 'memcached' in str(value).lower():
                    metrics.cache_present = True
                    metrics.cache_type = 'memcached'
                elif isinstance(value, dict):
                    metrics.cache_present = True
                    metrics.cache_type = 'unknown'
                    if 'ttl' in str(value).lower():
                        ttl = value.get('ttl', value.get('TTL'))
                        if isinstance(ttl, int):
                            metrics.cache_ttl_seconds = ttl

            # Check for queue
            if 'queue' in key_lower or 'celery' in key_lower or 'rabbitmq' in key_lower:
                metrics.queue_present = True

        # Generate issues for missing configs
        if metrics.http_timeout_seconds is None:
            issues.append(self._create_issue(
                rule_id="PERF-NO-HTTP-TIMEOUT",
                title="No HTTP timeout configured",
                description="No HTTP timeout found in application configuration.",
                severity=Severity.CRITICAL,
                file_path=str(file_path),
                remediation="Configure HTTP request timeouts to prevent hanging connections."
            ))

        if metrics.db_pool_size is None and 'database' in content.lower():
            issues.append(self._create_issue(
                rule_id="PERF-NO-DB-POOL",
                title="No database connection pool configured",
                description="Database configuration found but no connection pool size set.",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                remediation="Configure database connection pool size for optimal performance."
            ))

        return metrics, issues

    def _scan_nginx(
        self, content: str, file_path: Path
    ) -> Tuple[PerformanceMetrics, List[Issue]]:
        """Scan Nginx config for performance settings."""
        metrics = PerformanceMetrics()
        issues: List[Issue] = []

        # Check for worker_connections
        worker_conn_match = re.search(r'worker_connections\s+(\d+)', content)
        if worker_conn_match:
            metrics.max_connections = int(worker_conn_match.group(1))
        else:
            issues.append(self._create_issue(
                rule_id="PERF-NGINX-NO-WORKER-CONN",
                title="Nginx worker_connections not configured",
                description="worker_connections directive not found in Nginx config.",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                remediation="Set worker_connections in events block for connection capacity."
            ))

        # Check for keepalive_timeout
        keepalive_match = re.search(r'keepalive_timeout\s+(\d+)', content)
        if keepalive_match:
            metrics.keepalive_timeout_seconds = int(keepalive_match.group(1))

        # Check for rate limiting
        if 'limit_req' in content or 'limit_conn' in content:
            metrics.rate_limit_present = True
        else:
            issues.append(self._create_issue(
                rule_id="PERF-NGINX-NO-RATE-LIMIT",
                title="Nginx without rate limiting",
                description="No rate limiting (limit_req or limit_conn) configured.",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                remediation="Add limit_req or limit_conn directives to protect against abuse."
            ))

        # Check for gzip
        if 'gzip on' not in content and 'gzip_static on' not in content:
            issues.append(self._create_issue(
                rule_id="PERF-NGINX-NO-GZIP",
                title="Nginx gzip compression not enabled",
                description="Gzip compression is not enabled in Nginx config.",
                severity=Severity.LOW,
                file_path=str(file_path),
                remediation="Enable gzip compression to reduce response sizes."
            ))

        return metrics, issues

    def _scan_terraform(
        self, content: str, file_path: Path
    ) -> Tuple[PerformanceMetrics, List[Issue]]:
        """Scan Terraform files for performance settings."""
        metrics = PerformanceMetrics()
        issues: List[Issue] = []

        # Check for autoscaling resources
        if 'aws_autoscaling_group' in content or 'google_compute_autoscaler' in content:
            metrics.hpa_present = True

        # Check for instance/container sizing
        if 'instance_type' in content or 'machine_type' in content:
            # Instance type is specified - good practice
            pass

        # Check for CDN
        if 'aws_cloudfront' in content or 'google_compute_global_address' in content:
            metrics.cache_present = True
            metrics.cache_type = 'cdn'

        # Check for Redis/ElastiCache
        if 'aws_elasticache' in content or 'google_redis_instance' in content:
            metrics.cache_present = True
            metrics.cache_type = 'redis'

        return metrics, issues

    def _flatten_dict(
        self, d: Dict, parent_key: str = '', sep: str = '.'
    ) -> Dict[str, Any]:
        """Flatten a nested dictionary."""
        items: List[Tuple[str, Any]] = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def _create_issue(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        file_path: str,
        remediation: str = "",
        line_number: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Issue:
        """Create a performance issue."""
        issue_id = self._generate_issue_id(rule_id, file_path, str(line_number or ""))

        return Issue(
            id=issue_id,
            title=title,
            description=description,
            severity=severity,
            category=IssueCategory.PERFORMANCE,
            file_path=file_path,
            line_number=line_number,
            rule_id=rule_id,
            scanner=self.name,
            remediation=remediation,
            references=[
                "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
                "https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/",
            ],
            auto_fixable=False,
            metadata=metadata or {},
        )

    def _generate_issue_id(self, *components: str) -> str:
        """Generate a unique issue ID."""
        combined = "|".join(str(c) for c in components if c)
        hash_value = hashlib.md5(combined.encode()).hexdigest()[:12]
        return f"PERF-{hash_value}"
