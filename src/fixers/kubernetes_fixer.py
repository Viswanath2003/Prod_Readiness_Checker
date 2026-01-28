"""Kubernetes Fixer - Automated fixes for Kubernetes manifest security issues."""

import re
from pathlib import Path
from typing import List, Optional

import yaml

from .base_fixer import BaseFixer, Fix
from ..core.scanner import Issue


class KubernetesFixer(BaseFixer):
    """Fixer for common Kubernetes security issues."""

    # Mapping of rule patterns to fix functions
    FIX_HANDLERS = {
        # Trivy rules
        "KSV001": "_fix_privileged_container",
        "KSV003": "_fix_capabilities",
        "KSV005": "_fix_allow_privilege_escalation",
        "KSV006": "_fix_root_filesystem",
        "KSV011": "_fix_cpu_limits",
        "KSV012": "_fix_run_as_non_root",
        "KSV013": "_fix_image_tag",
        "KSV014": "_fix_memory_limits",
        "KSV015": "_fix_cpu_requests",
        "KSV016": "_fix_memory_requests",
        "KSV020": "_fix_run_as_user",
        "KSV021": "_fix_run_as_group",
        "KSV022": "_fix_read_only_root",
        "KSV023": "_fix_host_path",
        "KSV025": "_fix_seccomp_profile",
        # Checkov rules
        "CKV_K8S_1": "_fix_cpu_limits",
        "CKV_K8S_3": "_fix_memory_limits",
        "CKV_K8S_8": "_fix_liveness_probe",
        "CKV_K8S_9": "_fix_readiness_probe",
        "CKV_K8S_12": "_fix_memory_requests",
        "CKV_K8S_13": "_fix_cpu_requests",
        "CKV_K8S_20": "_fix_allow_privilege_escalation",
        "CKV_K8S_21": "_fix_image_tag",
        "CKV_K8S_22": "_fix_read_only_root",
        "CKV_K8S_23": "_fix_privileged_container",
        "CKV_K8S_25": "_fix_capabilities",
        "CKV_K8S_28": "_fix_run_as_non_root",
        "CKV_K8S_37": "_fix_run_as_user",
        "CKV_K8S_38": "_fix_service_account",
        "CKV_K8S_40": "_fix_run_as_user",
    }

    @property
    def name(self) -> str:
        return "kubernetes"

    @property
    def supported_rules(self) -> List[str]:
        return list(self.FIX_HANDLERS.keys()) + ["KSV*", "CKV_K8S_*"]

    def generate_fix(self, issue: Issue) -> Optional[Fix]:
        """Generate a fix for Kubernetes issues.

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
        handler_name = self.FIX_HANDLERS.get(issue.rule_id)

        if not handler_name:
            # Try pattern matching
            for pattern, handler in self.FIX_HANDLERS.items():
                if issue.rule_id.startswith(pattern.replace("*", "")):
                    handler_name = handler
                    break

        if not handler_name:
            return None

        handler = getattr(self, handler_name, None)
        if not handler:
            return None

        return handler(issue, content)

    def _fix_privileged_container(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Set privileged: false in securityContext."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            containers = self._get_containers(doc)
            for container in containers:
                security_context = container.setdefault("securityContext", {})
                if security_context.get("privileged", False):
                    security_context["privileged"] = False
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Set privileged: false to prevent container from running with elevated privileges",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.9,
            requires_review=True,
            review_notes="Verify that the container doesn't require privileged access to function.",
        )

    def _fix_allow_privilege_escalation(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Set allowPrivilegeEscalation: false."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            containers = self._get_containers(doc)
            for container in containers:
                security_context = container.setdefault("securityContext", {})
                if security_context.get("allowPrivilegeEscalation", True):
                    security_context["allowPrivilegeEscalation"] = False
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Set allowPrivilegeEscalation: false to prevent privilege escalation",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.95,
        )

    def _fix_run_as_non_root(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Set runAsNonRoot: true."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            # Add to pod-level securityContext
            spec = self._get_pod_spec(doc)
            if spec:
                security_context = spec.setdefault("securityContext", {})
                if not security_context.get("runAsNonRoot"):
                    security_context["runAsNonRoot"] = True
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Set runAsNonRoot: true to ensure container runs as non-root user",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.85,
            requires_review=True,
            review_notes="Verify that the container image supports running as non-root user.",
        )

    def _fix_run_as_user(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Set runAsUser to non-root (1000)."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            spec = self._get_pod_spec(doc)
            if spec:
                security_context = spec.setdefault("securityContext", {})
                if not security_context.get("runAsUser") or security_context.get("runAsUser") == 0:
                    security_context["runAsUser"] = 1000
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Set runAsUser to non-root user (1000)",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.8,
            requires_review=True,
            review_notes="Verify UID 1000 is appropriate for your container or adjust as needed.",
        )

    def _fix_run_as_group(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Set runAsGroup to non-root (1000)."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            spec = self._get_pod_spec(doc)
            if spec:
                security_context = spec.setdefault("securityContext", {})
                if not security_context.get("runAsGroup"):
                    security_context["runAsGroup"] = 1000
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Set runAsGroup to non-root group (1000)",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.8,
            requires_review=True,
            review_notes="Verify GID 1000 is appropriate for your container or adjust as needed.",
        )

    def _fix_read_only_root(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Set readOnlyRootFilesystem: true."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            containers = self._get_containers(doc)
            for container in containers:
                security_context = container.setdefault("securityContext", {})
                if not security_context.get("readOnlyRootFilesystem"):
                    security_context["readOnlyRootFilesystem"] = True
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Set readOnlyRootFilesystem: true for immutable container filesystem",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.75,
            requires_review=True,
            review_notes="Container may need emptyDir volumes for writable directories like /tmp.",
        )

    def _fix_root_filesystem(self, issue: Issue, content: str) -> Optional[Fix]:
        """Alias for read-only root filesystem fix."""
        return self._fix_read_only_root(issue, content)

    def _fix_capabilities(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Drop all capabilities."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            containers = self._get_containers(doc)
            for container in containers:
                security_context = container.setdefault("securityContext", {})
                capabilities = security_context.setdefault("capabilities", {})
                if capabilities.get("drop") != ["ALL"]:
                    capabilities["drop"] = ["ALL"]
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Drop all Linux capabilities for minimal privilege",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.85,
            requires_review=True,
            review_notes="If specific capabilities are needed, add them to the 'add' list.",
        )

    def _fix_cpu_limits(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add CPU limits."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            containers = self._get_containers(doc)
            for container in containers:
                resources = container.setdefault("resources", {})
                limits = resources.setdefault("limits", {})
                if not limits.get("cpu"):
                    limits["cpu"] = "500m"
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add CPU limits to prevent resource exhaustion",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.8,
            requires_review=True,
            review_notes="Adjust CPU limit (500m = 0.5 cores) based on your application's needs.",
        )

    def _fix_memory_limits(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add memory limits."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            containers = self._get_containers(doc)
            for container in containers:
                resources = container.setdefault("resources", {})
                limits = resources.setdefault("limits", {})
                if not limits.get("memory"):
                    limits["memory"] = "512Mi"
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add memory limits to prevent OOM issues",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.8,
            requires_review=True,
            review_notes="Adjust memory limit (512Mi) based on your application's memory usage.",
        )

    def _fix_cpu_requests(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add CPU requests."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            containers = self._get_containers(doc)
            for container in containers:
                resources = container.setdefault("resources", {})
                requests = resources.setdefault("requests", {})
                if not requests.get("cpu"):
                    requests["cpu"] = "100m"
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add CPU requests for proper scheduling",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.85,
        )

    def _fix_memory_requests(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add memory requests."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            containers = self._get_containers(doc)
            for container in containers:
                resources = container.setdefault("resources", {})
                requests = resources.setdefault("requests", {})
                if not requests.get("memory"):
                    requests["memory"] = "128Mi"
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add memory requests for proper scheduling",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.85,
        )

    def _fix_image_tag(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Replace :latest with specific version."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            containers = self._get_containers(doc)
            for container in containers:
                image = container.get("image", "")
                if ":latest" in image or ":" not in image:
                    # Add placeholder version
                    if ":" in image:
                        container["image"] = image.replace(":latest", ":VERSION")
                    else:
                        container["image"] = f"{image}:VERSION"
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Use specific image tag instead of :latest",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.7,
            requires_review=True,
            review_notes="Replace VERSION with actual semantic version tag for reproducible deployments.",
        )

    def _fix_liveness_probe(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add liveness probe."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            containers = self._get_containers(doc)
            for container in containers:
                if not container.get("livenessProbe"):
                    container["livenessProbe"] = {
                        "httpGet": {
                            "path": "/health",
                            "port": 8080,
                        },
                        "initialDelaySeconds": 15,
                        "periodSeconds": 10,
                    }
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add liveness probe for container health monitoring",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.6,
            requires_review=True,
            review_notes="Update the health check path and port to match your application.",
        )

    def _fix_readiness_probe(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add readiness probe."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            containers = self._get_containers(doc)
            for container in containers:
                if not container.get("readinessProbe"):
                    container["readinessProbe"] = {
                        "httpGet": {
                            "path": "/ready",
                            "port": 8080,
                        },
                        "initialDelaySeconds": 5,
                        "periodSeconds": 5,
                    }
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add readiness probe for proper service routing",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.6,
            requires_review=True,
            review_notes="Update the ready check path and port to match your application.",
        )

    def _fix_service_account(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Set automountServiceAccountToken: false."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            spec = self._get_pod_spec(doc)
            if spec and spec.get("automountServiceAccountToken", True):
                spec["automountServiceAccountToken"] = False
                modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Disable automatic service account token mounting",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.85,
            requires_review=True,
            review_notes="Enable if the pod needs to access the Kubernetes API.",
        )

    def _fix_seccomp_profile(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Add seccomp profile."""
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return None

        modified = False
        for doc in docs:
            if not doc:
                continue

            spec = self._get_pod_spec(doc)
            if spec:
                security_context = spec.setdefault("securityContext", {})
                if not security_context.get("seccompProfile"):
                    security_context["seccompProfile"] = {
                        "type": "RuntimeDefault"
                    }
                    modified = True

        if not modified:
            return None

        fixed_content = yaml.dump_all(docs, default_flow_style=False)

        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Add seccomp profile for syscall filtering",
            original_content=content,
            fixed_content=fixed_content,
            confidence=0.85,
        )

    def _fix_host_path(self, issue: Issue, content: str) -> Optional[Fix]:
        """Fix: Remove or replace hostPath volumes (complex - requires review)."""
        # This is a complex fix that requires significant changes
        return Fix(
            issue_id=issue.id,
            file_path=issue.file_path,
            description="Replace hostPath volume with more secure volume type",
            original_content="",
            fixed_content="",
            confidence=0.3,
            requires_review=True,
            review_notes="hostPath volumes should be replaced with PersistentVolumeClaims, "
                        "ConfigMaps, Secrets, or emptyDir as appropriate for your use case.",
        )

    def _get_containers(self, doc: dict) -> List[dict]:
        """Get all containers from a Kubernetes document."""
        containers = []

        spec = self._get_pod_spec(doc)
        if spec:
            containers.extend(spec.get("containers", []))
            containers.extend(spec.get("initContainers", []))

        return containers

    def _get_pod_spec(self, doc: dict) -> Optional[dict]:
        """Get the pod spec from a Kubernetes document."""
        if not doc:
            return None

        kind = doc.get("kind", "")

        if kind == "Pod":
            return doc.get("spec")
        elif kind in ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"]:
            return doc.get("spec", {}).get("template", {}).get("spec")
        elif kind == "CronJob":
            return doc.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec")

        return None
