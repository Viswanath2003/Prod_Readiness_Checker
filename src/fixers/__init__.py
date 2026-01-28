"""Automated fix generation module for common production readiness issues."""

from .base_fixer import BaseFixer, Fix, FixResult
from .dockerfile_fixer import DockerfileFixer
from .kubernetes_fixer import KubernetesFixer
from .config_fixer import ConfigFixer
from .fix_manager import FixManager

__all__ = [
    "BaseFixer",
    "Fix",
    "FixResult",
    "DockerfileFixer",
    "KubernetesFixer",
    "ConfigFixer",
    "FixManager",
]
