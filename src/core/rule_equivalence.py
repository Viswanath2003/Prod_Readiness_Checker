"""Rule Equivalence Module - Maps equivalent rules across different scanners."""

from typing import Dict, Optional

# Mapping of scanner-specific rule IDs to canonical rule IDs
# This allows deduplication of findings from different scanners that detect the same issue
RULE_EQUIVALENCE_MAP: Dict[str, str] = {
    # Trivy to Checkov equivalences (Dockerfile)
    "DS001": "CKV_DOCKER_2",  # HEALTHCHECK missing
    "DS002": "CKV_DOCKER_3",  # ADD instruction used
    "DS003": "CKV_DOCKER_7",  # Using latest tag
    "DS004": "CKV_DOCKER_8",  # Duplicate RUN
    "DS005": "CKV_DOCKER_1",  # Root user
    "DS006": "CKV_DOCKER_4",  # COPY with --chown
    "DS007": "CKV_DOCKER_6",  # COPY with more than two args
    "DS009": "CKV_DOCKER_5",  # ADD with remote URL
    "DS012": "CKV_DOCKER_9",  # Maintainer deprecated
    "DS013": "CKV_DOCKER_10",  # WORKDIR absolute path
    "DS014": "CKV_DOCKER_11",  # WORKDIR relative path
    "DS015": "CKV_DOCKER_8",  # Multiple entrypoints
    "DS016": "CKV_DOCKER_12",  # Multiple CMD
    "DS017": "CKV_DOCKER_7",  # Unspecified image tag
    "DS021": "CKV_DOCKER_1",  # User root
    "DS022": "CKV_DOCKER_15",  # Insecure APT repository
    "DS023": "CKV_DOCKER_16",  # APT no recommends
    "DS024": "CKV_DOCKER_17",  # APT cache not cleared
    "DS025": "CKV_DOCKER_18",  # YUM cache not cleared
    "DS026": "CKV_DOCKER_19",  # APT clean missing

    # Trivy to Checkov equivalences (Kubernetes)
    "KSV001": "CKV_K8S_1",  # Privileged container
    "KSV002": "CKV_K8S_17",  # SYS_ADMIN capability
    "KSV003": "CKV_K8S_10",  # CPU limit not set
    "KSV005": "CKV_K8S_29",  # Security context missing
    "KSV006": "CKV_K8S_23",  # Host PID
    "KSV007": "CKV_K8S_24",  # Host IPC
    "KSV008": "CKV_K8S_31",  # Host network
    "KSV009": "CKV_K8S_27",  # Host path volume
    "KSV010": "CKV_K8S_6",  # Root file system not read-only
    "KSV011": "CKV_K8S_12",  # Memory limits not set
    "KSV012": "CKV_K8S_20",  # Running as root
    "KSV013": "CKV_K8S_14",  # Image tag latest
    "KSV014": "CKV_K8S_8",  # Liveness probe not set
    "KSV015": "CKV_K8S_9",  # Readiness probe not set
    "KSV016": "CKV_K8S_11",  # CPU requests not set
    "KSV017": "CKV_K8S_13",  # Memory requests not set
    "KSV018": "CKV_K8S_22",  # Read-only filesystem
    "KSV020": "CKV_K8S_25",  # Privilege escalation
    "KSV021": "CKV_K8S_21",  # Default namespace
    "KSV022": "CKV_K8S_28",  # Capabilities not dropped
    "KSV023": "CKV_K8S_37",  # Dangerous capabilities
    "KSV024": "CKV_K8S_38",  # Service account token
    "KSV025": "CKV_K8S_35",  # Secrets in env vars
    "KSV027": "CKV_K8S_40",  # Service account
    "KSV028": "CKV_K8S_43",  # Image pull policy
    "KSV029": "CKV_K8S_30",  # Seccomp profile
    "KSV030": "CKV_K8S_32",  # SELinux options
    "KSV033": "CKV_K8S_39",  # App armor
    "KSV034": "CKV_K8S_41",  # Proc mount
    "KSV036": "CKV_K8S_33",  # Privileged ports
    "KSV037": "CKV_K8S_34",  # User ID < 10000
    "KSV038": "CKV_K8S_42",  # Group ID
}

# Reverse mapping (Checkov to Trivy)
REVERSE_RULE_MAP: Dict[str, str] = {v: k for k, v in RULE_EQUIVALENCE_MAP.items()}


def get_canonical_rule_id(rule_id: str) -> str:
    """Get the canonical rule ID for cross-scanner deduplication.

    Prefers Checkov rule IDs as canonical since they have more coverage.

    Args:
        rule_id: Original rule ID from any scanner

    Returns:
        Canonical rule ID (Checkov format when mapping exists, original otherwise)
    """
    if not rule_id:
        return ""

    # If it's a Trivy rule and has a Checkov equivalent, use that
    if rule_id in RULE_EQUIVALENCE_MAP:
        return RULE_EQUIVALENCE_MAP[rule_id]

    # Already canonical or no mapping exists
    return rule_id


def normalize_file_path(file_path: str) -> str:
    """Normalize file path for consistent comparison.

    Different scanners may report paths differently:
    - With or without leading slash
    - With or without ./ prefix
    - Absolute vs relative

    Args:
        file_path: Original file path

    Returns:
        Normalized path for comparison
    """
    if not file_path:
        return ""

    # Remove common prefixes
    path = file_path
    if path.startswith("./"):
        path = path[2:]
    if path.startswith("/"):
        path = path[1:]

    # Normalize separators (in case of Windows paths)
    path = path.replace("\\", "/")

    # Remove duplicate slashes
    while "//" in path:
        path = path.replace("//", "/")

    return path.lower()


def are_rules_equivalent(rule_id_1: str, rule_id_2: str) -> bool:
    """Check if two rule IDs represent the same issue.

    Args:
        rule_id_1: First rule ID
        rule_id_2: Second rule ID

    Returns:
        True if rules are equivalent
    """
    canonical_1 = get_canonical_rule_id(rule_id_1)
    canonical_2 = get_canonical_rule_id(rule_id_2)
    return canonical_1 == canonical_2
