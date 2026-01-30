"""Cross-scanner rule equivalence mapping for deduplication.

This module provides mappings between equivalent rules from different scanners
(e.g., Trivy and Checkov) to enable proper deduplication of issues that are
semantically the same but reported by multiple tools.
"""

from typing import Dict, Optional, Set, Tuple

# Sets of equivalent rules - each tuple contains rule IDs that represent
# the same security check across different scanners
EQUIVALENT_RULE_SETS: Set[Tuple[str, ...]] = {
    # Docker: Running as root user (no USER statement)
    # Trivy DS002 == Checkov CKV_DOCKER_3
    ("DS002", "CKV_DOCKER_3"),
    
    # Docker: No HEALTHCHECK instruction
    # Trivy DS026 == Checkov CKV_DOCKER_2
    ("DS026", "CKV_DOCKER_2"),
    
    # Docker: Using APT without best practices
    # Trivy DS029 == Checkov CKV_DOCKER_9
    ("DS029", "CKV_DOCKER_9"),
    
    # Docker: Using ADD instead of COPY
    # Trivy DS005 == Checkov CKV_DOCKER_4
    ("DS005", "CKV_DOCKER_4"),
    
    # Docker: Using latest tag
    # Trivy DS001 == Checkov CKV_DOCKER_7
    ("DS001", "CKV_DOCKER_7"),
    
    # Docker: COPY with more than 2 arguments not using wildcard
    # Trivy DS006 == Checkov CKV_DOCKER_10
    ("DS006", "CKV_DOCKER_10"),
    
    # Docker: Using MAINTAINER (deprecated)
    # Trivy DS021 == Checkov CKV_DOCKER_6
    ("DS021", "CKV_DOCKER_6"),
}

# Build lookup dictionary for O(1) access
_RULE_TO_CANONICAL: Dict[str, str] = {}

def _build_lookup() -> None:
    """Build the rule-to-canonical lookup dictionary."""
    global _RULE_TO_CANONICAL
    if _RULE_TO_CANONICAL:
        return
    
    for rule_set in EQUIVALENT_RULE_SETS:
        # Use the first rule in each set as the canonical version
        canonical = rule_set[0]
        for rule_id in rule_set:
            _RULE_TO_CANONICAL[rule_id] = canonical

# Initialize on module load
_build_lookup()


def get_canonical_rule_id(rule_id: str) -> str:
    """Get the canonical rule ID for cross-scanner deduplication.
    
    Args:
        rule_id: The rule ID from any scanner
        
    Returns:
        The canonical rule ID if an equivalent exists, otherwise the original rule_id
    """
    return _RULE_TO_CANONICAL.get(rule_id, rule_id)


def are_rules_equivalent(rule_id_1: str, rule_id_2: str) -> bool:
    """Check if two rule IDs represent the same underlying check.
    
    Args:
        rule_id_1: First rule ID
        rule_id_2: Second rule ID
        
    Returns:
        True if the rules are semantically equivalent
    """
    return get_canonical_rule_id(rule_id_1) == get_canonical_rule_id(rule_id_2)


def normalize_file_path(file_path: str) -> str:
    """Normalize file path for consistent fingerprinting.
    
    Removes leading slashes and normalizes path separators to handle
    differences in how scanners report file paths.
    
    Args:
        file_path: The file path to normalize
        
    Returns:
        Normalized file path
    """
    if not file_path:
        return ""
    
    # Remove leading slashes for consistency
    # Trivy might report "Dockerfile" while Checkov reports "/Dockerfile"
    normalized = file_path.lstrip("/")
    
    # Normalize path separators
    normalized = normalized.replace("\\", "/")
    
    return normalized
