"""Parallel Executor Module - Runs multiple scanners concurrently."""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Type

from .scanner import BaseScanner, ScanResult


@dataclass
class ExecutionResult:
    """Result of parallel execution of multiple scanners."""
    scan_results: List[ScanResult] = field(default_factory=list)
    total_duration_ms: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    scanner_count: int = 0
    successful_scans: int = 0
    failed_scans: int = 0
    errors: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_results": [r.to_dict() for r in self.scan_results],
            "total_duration_ms": self.total_duration_ms,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scanner_count": self.scanner_count,
            "successful_scans": self.successful_scans,
            "failed_scans": self.failed_scans,
            "errors": self.errors,
        }


class ParallelExecutor:
    """Executes multiple scanners in parallel."""

    def __init__(
        self,
        max_concurrent: int = 4,
        timeout_per_scanner: int = 300,
    ):
        """Initialize the parallel executor.

        Args:
            max_concurrent: Maximum number of concurrent scanners
            timeout_per_scanner: Timeout in seconds for each scanner
        """
        self.max_concurrent = max_concurrent
        self.timeout_per_scanner = timeout_per_scanner
        self.scanners: List[BaseScanner] = []

    def add_scanner(self, scanner: BaseScanner) -> "ParallelExecutor":
        """Add a scanner to execute.

        Args:
            scanner: Scanner instance to add

        Returns:
            Self for chaining
        """
        self.scanners.append(scanner)
        return self

    def add_scanners(self, scanners: List[BaseScanner]) -> "ParallelExecutor":
        """Add multiple scanners to execute.

        Args:
            scanners: List of scanner instances

        Returns:
            Self for chaining
        """
        self.scanners.extend(scanners)
        return self

    async def execute(self, target_path: str, progress_callback=None) -> ExecutionResult:
        """Execute all scanners in parallel.

        Args:
            target_path: Path to scan
            progress_callback: Optional callback function called with (completed_count, total_count, scanner_name)
                              when each scanner completes

        Returns:
            ExecutionResult with all scan results
        """
        started_at = datetime.now()
        result = ExecutionResult(
            started_at=started_at,
            scanner_count=len(self.scanners),
        )

        if not self.scanners:
            result.completed_at = datetime.now()
            return result

        # Track completed scanners for progress reporting
        completed_count = 0
        total_scanners = len(self.scanners)

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def run_scanner(scanner: BaseScanner) -> Optional[ScanResult]:
            nonlocal completed_count
            """Run a single scanner with semaphore."""
            scan_result = None
            async with semaphore:
                try:
                    # Check if scanner is available
                    if not scanner.is_available():
                        result.errors[scanner.name] = "Scanner not available"
                        result.failed_scans += 1
                    else:
                        # Run with timeout
                        scan_result = await asyncio.wait_for(
                            scanner.scan(target_path),
                            timeout=self.timeout_per_scanner,
                        )

                except asyncio.TimeoutError:
                    result.errors[scanner.name] = (
                        f"Scanner timed out after {self.timeout_per_scanner}s"
                    )
                    result.failed_scans += 1

                except Exception as e:
                    result.errors[scanner.name] = str(e)
                    result.failed_scans += 1
                
                finally:
                    # Update progress after scanner completes (success or failure)
                    completed_count += 1
                    if progress_callback:
                        progress_callback(completed_count, total_scanners, scanner.name)
                
                return scan_result

        # Run all scanners concurrently
        tasks = [run_scanner(scanner) for scanner in self.scanners]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for scan_result in scan_results:
            if isinstance(scan_result, ScanResult):
                result.scan_results.append(scan_result)
                if scan_result.success:
                    result.successful_scans += 1
                else:
                    result.failed_scans += 1
            elif isinstance(scan_result, Exception):
                result.failed_scans += 1

        # Complete result
        completed_at = datetime.now()
        result.completed_at = completed_at
        result.total_duration_ms = int(
            (completed_at - started_at).total_seconds() * 1000
        )

        return result

    def clear_scanners(self) -> "ParallelExecutor":
        """Clear all registered scanners.

        Returns:
            Self for chaining
        """
        self.scanners.clear()
        return self


class ScannerRegistry:
    """Registry for managing available scanners."""

    def __init__(self):
        """Initialize the registry."""
        self._scanners: Dict[str, Type[BaseScanner]] = {}
        self._instances: Dict[str, BaseScanner] = {}

    def register(self, name: str, scanner_class: Type[BaseScanner]) -> None:
        """Register a scanner class.

        Args:
            name: Unique name for the scanner
            scanner_class: Scanner class to register
        """
        self._scanners[name] = scanner_class

    def get_scanner(self, name: str, **kwargs) -> Optional[BaseScanner]:
        """Get a scanner instance by name.

        Args:
            name: Name of the scanner
            **kwargs: Arguments to pass to scanner constructor

        Returns:
            Scanner instance or None if not found
        """
        if name not in self._scanners:
            return None

        # Create new instance
        return self._scanners[name](**kwargs)

    def get_all_available(self) -> List[str]:
        """Get names of all available scanners.

        Returns:
            List of scanner names
        """
        available = []
        for name, scanner_class in self._scanners.items():
            try:
                instance = scanner_class()
                if instance.is_available():
                    available.append(name)
            except Exception:
                pass
        return available

    def create_executor(
        self,
        scanner_names: Optional[List[str]] = None,
        **executor_kwargs,
    ) -> ParallelExecutor:
        """Create a parallel executor with specified scanners.

        Args:
            scanner_names: Names of scanners to include (all if None)
            **executor_kwargs: Arguments for ParallelExecutor

        Returns:
            Configured ParallelExecutor
        """
        executor = ParallelExecutor(**executor_kwargs)

        names = scanner_names or list(self._scanners.keys())

        for name in names:
            scanner = self.get_scanner(name)
            if scanner and scanner.is_available():
                executor.add_scanner(scanner)

        return executor


# Global registry instance
scanner_registry = ScannerRegistry()
