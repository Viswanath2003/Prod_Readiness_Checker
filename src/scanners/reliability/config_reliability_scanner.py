"""Config Reliability Scanner - Static analysis of reliability configurations."""

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
class ReliabilityMetrics:
    """Extracted reliability metrics from config files."""
    # Health probes
    liveness_probe_present: bool = False
    readiness_probe_present: bool = False
    startup_probe_present: bool = False

    # Recovery
    restart_policy: Optional[str] = None
    termination_grace_period_seconds: Optional[int] = None

    # Availability
    replicas: Optional[int] = None
    pod_disruption_budget_present: bool = False
    rolling_update_strategy_present: bool = False
    max_surge: Optional[str] = None
    max_unavailable: Optional[str] = None

    # Resilience
    retry_policy_present: bool = False
    backoff_policy_present: bool = False
    circuit_breaker_present: bool = False

    # State safety
    pvc_present: bool = False
    statefulset_used: bool = False

    # Isolation
    pod_anti_affinity_present: bool = False
    node_affinity_present: bool = False

    # Source file
    source_file: str = ""


class ConfigReliabilityScanner(BaseScanner):
    """Static scanner for reliability configurations in infrastructure files.

    Scans Kubernetes manifests, Docker configs, Helm charts, and application
    configs to extract and validate reliability-related settings.
    """

    # File categories to scan
    SCAN_CATEGORIES = [
        FileCategory.KUBERNETES,
        FileCategory.HELM,
        FileCategory.DOCKER_COMPOSE,
        FileCategory.DOCKERFILE,
        FileCategory.TERRAFORM,
        FileCategory.APPLICATION_CONFIG,
    ]

    def __init__(self):
        """Initialize the reliability scanner."""
        super().__init__(name="reliability-scanner", scan_type="reliability")
        self.file_discovery = FileDiscovery()

    def is_available(self) -> bool:
        """Always available - no external tools required."""
        return True

    async def scan(self, target_path: str | Path) -> ScanResult:
        """Scan for reliability configuration issues.

        Args:
            target_path: Path to scan

        Returns:
            ScanResult with reliability issues
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
        all_metrics: List[ReliabilityMetrics] = []
        found_pdb = False
        found_hpa = False
        deployments_found = 0

        # Discover relevant files
        discovery_result = self.file_discovery.discover_by_category(
            target_path, self.SCAN_CATEGORIES
        )

        # Scan each file
        for discovered_file in discovery_result.files:
            try:
                metrics, issues, file_info = self._scan_file(
                    discovered_file.path, discovered_file.category
                )
                if metrics:
                    metrics.source_file = str(discovered_file.relative_path)
                    all_metrics.append(metrics)
                all_issues.extend(issues)

                # Track aggregate info
                if file_info.get('has_pdb'):
                    found_pdb = True
                if file_info.get('has_hpa'):
                    found_hpa = True
                if file_info.get('deployments', 0) > 0:
                    deployments_found += file_info['deployments']

            except Exception as e:
                pass

        # Generate aggregate issues
        if deployments_found > 0 and not found_pdb:
            all_issues.append(self._create_issue(
                rule_id="REL-NO-PDB",
                title="No Pod Disruption Budget defined",
                description=f"Found {deployments_found} Deployment(s) but no PodDisruptionBudget. "
                           "This means voluntary disruptions (like node drains) could take down all pods.",
                severity=Severity.HIGH,
                file_path=str(target_path),
                remediation="Create a PodDisruptionBudget to ensure minimum availability during disruptions."
            ))

        if not all_metrics:
            all_issues.append(self._create_issue(
                rule_id="REL-NO-CONFIG",
                title="No Reliability Configuration Found",
                description="No Kubernetes, Docker, or infrastructure configuration files found. "
                           "Reliability cannot be validated without deployment configurations.",
                severity=Severity.MEDIUM,
                file_path=str(target_path),
                remediation="Add Kubernetes manifests or other deployment configurations "
                           "with health checks and restart policies."
            ))

        result.issues = all_issues
        result.metadata = {
            "files_scanned": len(discovery_result.files),
            "metrics_extracted": len(all_metrics),
            "categories_scanned": [c.value for c in self.SCAN_CATEGORIES],
            "deployments_found": deployments_found,
            "pdb_found": found_pdb,
        }

        return self._complete_result(result, started_at)

    def _scan_file(
        self,
        file_path: Path,
        category: FileCategory
    ) -> Tuple[Optional[ReliabilityMetrics], List[Issue], Dict[str, Any]]:
        """Scan a single file for reliability metrics.

        Args:
            file_path: Path to the file
            category: Category of the file

        Returns:
            Tuple of (metrics, issues, file_info)
        """
        metrics = ReliabilityMetrics()
        issues: List[Issue] = []
        file_info: Dict[str, Any] = {}

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return None, [], {}

        # Parse based on file type
        if category == FileCategory.KUBERNETES:
            metrics, issues, file_info = self._scan_kubernetes(content, file_path)
        elif category == FileCategory.HELM:
            metrics, issues, file_info = self._scan_helm(content, file_path)
        elif category == FileCategory.DOCKER_COMPOSE:
            metrics, issues, file_info = self._scan_docker_compose(content, file_path)
        elif category == FileCategory.DOCKERFILE:
            metrics, issues, file_info = self._scan_dockerfile(content, file_path)
        elif category == FileCategory.APPLICATION_CONFIG:
            metrics, issues, file_info = self._scan_app_config(content, file_path)
        elif category == FileCategory.TERRAFORM:
            metrics, issues, file_info = self._scan_terraform(content, file_path)

        return metrics, issues, file_info

    def _scan_kubernetes(
        self, content: str, file_path: Path
    ) -> Tuple[ReliabilityMetrics, List[Issue], Dict[str, Any]]:
        """Scan Kubernetes manifest for reliability settings."""
        metrics = ReliabilityMetrics()
        issues: List[Issue] = []
        file_info: Dict[str, Any] = {'deployments': 0, 'has_pdb': False, 'has_hpa': False}

        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return metrics, issues, file_info

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            kind = doc.get('kind', '')
            metadata = doc.get('metadata', {})
            name = metadata.get('name', 'unknown')
            spec = doc.get('spec', {})

            if kind == 'Deployment':
                file_info['deployments'] += 1
                issues.extend(self._check_deployment_reliability(doc, file_path, name))
                metrics = self._extract_deployment_metrics(doc, metrics)

            elif kind == 'StatefulSet':
                metrics.statefulset_used = True
                issues.extend(self._check_statefulset_reliability(doc, file_path, name))
                metrics = self._extract_deployment_metrics(doc, metrics)

            elif kind == 'PodDisruptionBudget':
                file_info['has_pdb'] = True
                metrics.pod_disruption_budget_present = True

            elif kind == 'HorizontalPodAutoscaler':
                file_info['has_hpa'] = True

            elif kind == 'PersistentVolumeClaim':
                metrics.pvc_present = True

        return metrics, issues, file_info

    def _check_deployment_reliability(
        self, doc: Dict, file_path: Path, name: str
    ) -> List[Issue]:
        """Check Deployment for reliability issues."""
        issues: List[Issue] = []
        spec = doc.get('spec', {})
        template_spec = spec.get('template', {}).get('spec', {})
        containers = template_spec.get('containers', [])
        strategy = spec.get('strategy', {})

        replicas = spec.get('replicas', 1)

        # Check replica count
        if replicas < 2:
            issues.append(self._create_issue(
                rule_id="REL-LOW-REPLICAS",
                title="Deployment with less than 2 replicas",
                description=f"Deployment '{name}' has {replicas} replica(s). "
                           "Single replica deployments have no redundancy.",
                severity=Severity.HIGH,
                file_path=str(file_path),
                remediation="Set replicas to at least 2 for high availability.",
                metadata={"replica_count": replicas, "deployment": name}
            ))

        # Check for rolling update strategy
        strategy_type = strategy.get('type', 'RollingUpdate')
        if strategy_type != 'RollingUpdate':
            issues.append(self._create_issue(
                rule_id="REL-NO-ROLLING-UPDATE",
                title="Deployment without rolling update strategy",
                description=f"Deployment '{name}' uses '{strategy_type}' strategy instead of RollingUpdate.",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                remediation="Use RollingUpdate strategy to minimize downtime during deployments."
            ))

        # Check restart policy
        restart_policy = template_spec.get('restartPolicy', 'Always')
        if restart_policy != 'Always':
            issues.append(self._create_issue(
                rule_id="REL-RESTART-POLICY",
                title="Non-standard restart policy",
                description=f"Deployment '{name}' has restartPolicy '{restart_policy}' instead of 'Always'.",
                severity=Severity.CRITICAL,
                file_path=str(file_path),
                remediation="Set restartPolicy to 'Always' for automatic crash recovery."
            ))

        # Check termination grace period
        termination_grace = template_spec.get('terminationGracePeriodSeconds')
        if termination_grace is None:
            issues.append(self._create_issue(
                rule_id="REL-NO-GRACE-PERIOD",
                title="No termination grace period specified",
                description=f"Deployment '{name}' uses default termination grace period (30s). "
                           "This may not be enough for graceful shutdown.",
                severity=Severity.LOW,
                file_path=str(file_path),
                remediation="Set terminationGracePeriodSeconds based on your application's shutdown time."
            ))

        # Check containers for probes
        for container in containers:
            container_name = container.get('name', 'unknown')

            # Check liveness probe
            if not container.get('livenessProbe'):
                issues.append(self._create_issue(
                    rule_id="REL-NO-LIVENESS",
                    title="Missing liveness probe",
                    description=f"Container '{container_name}' in Deployment '{name}' has no liveness probe.",
                    severity=Severity.CRITICAL,
                    file_path=str(file_path),
                    remediation="Add a livenessProbe to detect and restart unhealthy containers.",
                    metadata={"container": container_name, "deployment": name}
                ))

            # Check readiness probe
            if not container.get('readinessProbe'):
                issues.append(self._create_issue(
                    rule_id="REL-NO-READINESS",
                    title="Missing readiness probe",
                    description=f"Container '{container_name}' in Deployment '{name}' has no readiness probe.",
                    severity=Severity.CRITICAL,
                    file_path=str(file_path),
                    remediation="Add a readinessProbe to prevent traffic to unready pods.",
                    metadata={"container": container_name, "deployment": name}
                ))

            # Check startup probe (for slow-starting containers)
            if not container.get('startupProbe'):
                issues.append(self._create_issue(
                    rule_id="REL-NO-STARTUP",
                    title="Missing startup probe",
                    description=f"Container '{container_name}' in Deployment '{name}' has no startup probe.",
                    severity=Severity.LOW,
                    file_path=str(file_path),
                    remediation="Consider adding a startupProbe for containers with slow startup.",
                    metadata={"container": container_name, "deployment": name}
                ))

        # Check for pod anti-affinity
        affinity = template_spec.get('affinity', {})
        pod_anti_affinity = affinity.get('podAntiAffinity')
        if not pod_anti_affinity and replicas >= 2:
            issues.append(self._create_issue(
                rule_id="REL-NO-ANTI-AFFINITY",
                title="No pod anti-affinity configured",
                description=f"Deployment '{name}' has multiple replicas but no pod anti-affinity. "
                           "Pods may be scheduled on the same node.",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                remediation="Add podAntiAffinity to spread pods across nodes for better fault tolerance."
            ))

        return issues

    def _check_statefulset_reliability(
        self, doc: Dict, file_path: Path, name: str
    ) -> List[Issue]:
        """Check StatefulSet for reliability issues."""
        issues: List[Issue] = []
        spec = doc.get('spec', {})
        template_spec = spec.get('template', {}).get('spec', {})
        containers = template_spec.get('containers', [])

        replicas = spec.get('replicas', 1)

        # Check volume claim templates
        volume_claim_templates = spec.get('volumeClaimTemplates', [])
        if not volume_claim_templates:
            issues.append(self._create_issue(
                rule_id="REL-STATEFULSET-NO-PVC",
                title="StatefulSet without volume claim templates",
                description=f"StatefulSet '{name}' has no volumeClaimTemplates. "
                           "Stateful data may not be persisted.",
                severity=Severity.HIGH,
                file_path=str(file_path),
                remediation="Add volumeClaimTemplates for persistent storage."
            ))

        # Check containers for probes (similar to Deployment)
        for container in containers:
            container_name = container.get('name', 'unknown')

            if not container.get('livenessProbe'):
                issues.append(self._create_issue(
                    rule_id="REL-NO-LIVENESS",
                    title="Missing liveness probe",
                    description=f"Container '{container_name}' in StatefulSet '{name}' has no liveness probe.",
                    severity=Severity.CRITICAL,
                    file_path=str(file_path),
                    remediation="Add a livenessProbe to detect and restart unhealthy containers."
                ))

            if not container.get('readinessProbe'):
                issues.append(self._create_issue(
                    rule_id="REL-NO-READINESS",
                    title="Missing readiness probe",
                    description=f"Container '{container_name}' in StatefulSet '{name}' has no readiness probe.",
                    severity=Severity.CRITICAL,
                    file_path=str(file_path),
                    remediation="Add a readinessProbe to prevent traffic to unready pods."
                ))

        return issues

    def _extract_deployment_metrics(
        self, doc: Dict, metrics: ReliabilityMetrics
    ) -> ReliabilityMetrics:
        """Extract reliability metrics from Deployment/StatefulSet."""
        spec = doc.get('spec', {})
        template_spec = spec.get('template', {}).get('spec', {})
        containers = template_spec.get('containers', [])
        strategy = spec.get('strategy', {})

        metrics.replicas = spec.get('replicas', 1)
        metrics.restart_policy = template_spec.get('restartPolicy', 'Always')
        metrics.termination_grace_period_seconds = template_spec.get('terminationGracePeriodSeconds')

        # Check strategy
        if strategy.get('type') == 'RollingUpdate':
            metrics.rolling_update_strategy_present = True
            rolling_update = strategy.get('rollingUpdate', {})
            metrics.max_surge = str(rolling_update.get('maxSurge', ''))
            metrics.max_unavailable = str(rolling_update.get('maxUnavailable', ''))

        # Check probes
        for container in containers:
            if container.get('livenessProbe'):
                metrics.liveness_probe_present = True
            if container.get('readinessProbe'):
                metrics.readiness_probe_present = True
            if container.get('startupProbe'):
                metrics.startup_probe_present = True

        # Check affinity
        affinity = template_spec.get('affinity', {})
        if affinity.get('podAntiAffinity'):
            metrics.pod_anti_affinity_present = True
        if affinity.get('nodeAffinity'):
            metrics.node_affinity_present = True

        return metrics

    def _scan_helm(
        self, content: str, file_path: Path
    ) -> Tuple[ReliabilityMetrics, List[Issue], Dict[str, Any]]:
        """Scan Helm values.yaml for reliability settings."""
        metrics = ReliabilityMetrics()
        issues: List[Issue] = []
        file_info: Dict[str, Any] = {}

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError:
            return metrics, issues, file_info

        if not isinstance(data, dict):
            return metrics, issues, file_info

        # Check for replica settings
        replicas = data.get('replicaCount', data.get('replicas', 1))
        metrics.replicas = replicas
        if replicas < 2:
            issues.append(self._create_issue(
                rule_id="REL-HELM-LOW-REPLICAS",
                title="Helm chart with less than 2 replicas",
                description="Helm values specify less than 2 replicas.",
                severity=Severity.HIGH,
                file_path=str(file_path),
                remediation="Set replicaCount to at least 2 for production deployments."
            ))

        # Check for probes
        probes = data.get('probes', data.get('livenessProbe', {}))
        liveness = data.get('livenessProbe', probes.get('liveness', {}))
        readiness = data.get('readinessProbe', probes.get('readiness', {}))

        if liveness:
            metrics.liveness_probe_present = True
        else:
            issues.append(self._create_issue(
                rule_id="REL-HELM-NO-LIVENESS",
                title="Helm chart without liveness probe configuration",
                description="No liveness probe configuration in Helm values.",
                severity=Severity.CRITICAL,
                file_path=str(file_path),
                remediation="Add livenessProbe configuration in values.yaml."
            ))

        if readiness:
            metrics.readiness_probe_present = True
        else:
            issues.append(self._create_issue(
                rule_id="REL-HELM-NO-READINESS",
                title="Helm chart without readiness probe configuration",
                description="No readiness probe configuration in Helm values.",
                severity=Severity.CRITICAL,
                file_path=str(file_path),
                remediation="Add readinessProbe configuration in values.yaml."
            ))

        # Check for PDB
        pdb = data.get('podDisruptionBudget', data.get('pdb', {}))
        if pdb and pdb.get('enabled', True) is not False:
            metrics.pod_disruption_budget_present = True
            file_info['has_pdb'] = True
        else:
            issues.append(self._create_issue(
                rule_id="REL-HELM-NO-PDB",
                title="Helm chart without PodDisruptionBudget",
                description="No PodDisruptionBudget configuration in Helm values.",
                severity=Severity.HIGH,
                file_path=str(file_path),
                remediation="Add podDisruptionBudget configuration for controlled disruptions."
            ))

        # Check for affinity
        affinity = data.get('affinity', {})
        if affinity.get('podAntiAffinity'):
            metrics.pod_anti_affinity_present = True

        return metrics, issues, file_info

    def _scan_docker_compose(
        self, content: str, file_path: Path
    ) -> Tuple[ReliabilityMetrics, List[Issue], Dict[str, Any]]:
        """Scan docker-compose.yml for reliability settings."""
        metrics = ReliabilityMetrics()
        issues: List[Issue] = []
        file_info: Dict[str, Any] = {}

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError:
            return metrics, issues, file_info

        if not isinstance(data, dict):
            return metrics, issues, file_info

        services = data.get('services', {})

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            # Check restart policy
            restart = service_config.get('restart', 'no')
            if restart not in ['always', 'unless-stopped', 'on-failure']:
                issues.append(self._create_issue(
                    rule_id="REL-COMPOSE-NO-RESTART",
                    title="Docker Compose service without restart policy",
                    description=f"Service '{service_name}' has restart policy '{restart}'. "
                               "Container will not restart on failure.",
                    severity=Severity.CRITICAL,
                    file_path=str(file_path),
                    remediation=f"Set restart: always or restart: unless-stopped for '{service_name}'."
                ))
            else:
                metrics.restart_policy = restart

            # Check healthcheck
            healthcheck = service_config.get('healthcheck')
            if not healthcheck:
                issues.append(self._create_issue(
                    rule_id="REL-COMPOSE-NO-HEALTHCHECK",
                    title="Docker Compose service without healthcheck",
                    description=f"Service '{service_name}' has no healthcheck defined.",
                    severity=Severity.HIGH,
                    file_path=str(file_path),
                    remediation=f"Add healthcheck configuration for '{service_name}'."
                ))
            else:
                metrics.liveness_probe_present = True
                metrics.readiness_probe_present = True

            # Check deploy replicas
            deploy = service_config.get('deploy', {})
            replicas = deploy.get('replicas', 1)
            if replicas < 2:
                issues.append(self._create_issue(
                    rule_id="REL-COMPOSE-LOW-REPLICAS",
                    title="Docker Compose service with low replica count",
                    description=f"Service '{service_name}' has {replicas} replica(s).",
                    severity=Severity.MEDIUM,
                    file_path=str(file_path),
                    remediation=f"Set deploy.replicas >= 2 for '{service_name}'."
                ))

            # Check for volumes (state persistence)
            volumes = service_config.get('volumes', [])
            if volumes:
                metrics.pvc_present = True

        return metrics, issues, file_info

    def _scan_dockerfile(
        self, content: str, file_path: Path
    ) -> Tuple[ReliabilityMetrics, List[Issue], Dict[str, Any]]:
        """Scan Dockerfile for reliability settings."""
        metrics = ReliabilityMetrics()
        issues: List[Issue] = []
        file_info: Dict[str, Any] = {}

        lines = content.split('\n')

        # Check for HEALTHCHECK
        has_healthcheck = any(
            line.strip().upper().startswith('HEALTHCHECK')
            for line in lines
        )

        if has_healthcheck:
            metrics.liveness_probe_present = True
        else:
            issues.append(self._create_issue(
                rule_id="REL-DOCKERFILE-NO-HEALTHCHECK",
                title="Dockerfile without HEALTHCHECK",
                description="Dockerfile does not define a HEALTHCHECK instruction.",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                remediation="Add HEALTHCHECK instruction for container health monitoring."
            ))

        # Check for signal handling (STOPSIGNAL)
        has_stopsignal = any(
            line.strip().upper().startswith('STOPSIGNAL')
            for line in lines
        )

        if not has_stopsignal:
            issues.append(self._create_issue(
                rule_id="REL-DOCKERFILE-NO-STOPSIGNAL",
                title="Dockerfile without STOPSIGNAL",
                description="Dockerfile does not define STOPSIGNAL for graceful shutdown.",
                severity=Severity.LOW,
                file_path=str(file_path),
                remediation="Add STOPSIGNAL instruction if your app needs specific signal handling."
            ))

        return metrics, issues, file_info

    def _scan_app_config(
        self, content: str, file_path: Path
    ) -> Tuple[ReliabilityMetrics, List[Issue], Dict[str, Any]]:
        """Scan application config for reliability settings."""
        metrics = ReliabilityMetrics()
        issues: List[Issue] = []
        file_info: Dict[str, Any] = {}

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
            return metrics, issues, file_info

        # Flatten nested dict for easier searching
        flat_config = self._flatten_dict(data)

        # Check for retry configurations
        for key, value in flat_config.items():
            key_lower = key.lower()

            # Check for retry policy
            if 'retry' in key_lower:
                metrics.retry_policy_present = True
                if 'max' in key_lower or 'count' in key_lower:
                    if isinstance(value, int) and value < 2:
                        issues.append(self._create_issue(
                            rule_id="REL-LOW-RETRY-COUNT",
                            title="Low retry count configured",
                            description=f"Retry count '{key}' is set to {value}.",
                            severity=Severity.MEDIUM,
                            file_path=str(file_path),
                            remediation="Consider setting retry count to at least 3."
                        ))

            # Check for backoff policy
            if 'backoff' in key_lower or 'exponential' in key_lower:
                metrics.backoff_policy_present = True

            # Check for circuit breaker
            if 'circuit' in key_lower or 'breaker' in key_lower:
                metrics.circuit_breaker_present = True

        # Generate issues for missing resilience patterns
        if not metrics.retry_policy_present and 'http' in content.lower():
            issues.append(self._create_issue(
                rule_id="REL-NO-RETRY",
                title="No retry policy configured",
                description="Application config mentions HTTP but no retry policy found.",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                remediation="Configure retry policies for external service calls."
            ))

        if not metrics.circuit_breaker_present and 'http' in content.lower():
            issues.append(self._create_issue(
                rule_id="REL-NO-CIRCUIT-BREAKER",
                title="No circuit breaker configured",
                description="Application config mentions HTTP but no circuit breaker found.",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                remediation="Configure circuit breaker to prevent cascade failures."
            ))

        return metrics, issues, file_info

    def _scan_terraform(
        self, content: str, file_path: Path
    ) -> Tuple[ReliabilityMetrics, List[Issue], Dict[str, Any]]:
        """Scan Terraform files for reliability settings."""
        metrics = ReliabilityMetrics()
        issues: List[Issue] = []
        file_info: Dict[str, Any] = {}

        # Check for health checks in cloud resources
        if 'health_check' in content:
            metrics.liveness_probe_present = True

        # Check for autoscaling (implies multiple instances)
        if 'aws_autoscaling_group' in content or 'google_compute_autoscaler' in content:
            metrics.replicas = 2  # Autoscaling implies >= 2

        # Check for multi-AZ
        if 'multi_az' in content.lower() or 'availability_zone' in content:
            metrics.pod_anti_affinity_present = True  # Equivalent concept

        return metrics, issues, file_info

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
        """Create a reliability issue."""
        issue_id = self._generate_issue_id(rule_id, file_path, str(line_number or ""))

        return Issue(
            id=issue_id,
            title=title,
            description=description,
            severity=severity,
            category=IssueCategory.RELIABILITY,
            file_path=file_path,
            line_number=line_number,
            rule_id=rule_id,
            scanner=self.name,
            remediation=remediation,
            references=[
                "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/",
                "https://kubernetes.io/docs/concepts/workloads/pods/disruptions/",
            ],
            auto_fixable=False,
            metadata=metadata or {},
        )

    def _generate_issue_id(self, *components: str) -> str:
        """Generate a unique issue ID."""
        combined = "|".join(str(c) for c in components if c)
        hash_value = hashlib.md5(combined.encode()).hexdigest()[:12]
        return f"REL-{hash_value}"
