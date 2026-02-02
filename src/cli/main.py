"""Main CLI Module - Command-line interface for Production Readiness Checker."""

import asyncio
import os
import sys
import hashlib
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
from rich import print as rprint

from ..core.file_discovery import FileDiscovery
from ..core.scanner import ScanResult, Severity, Issue
from ..core.scorer import Scorer, Score
from ..core.parallel_executor import ParallelExecutor
from ..core.rule_equivalence import get_canonical_rule_id, normalize_file_path
from ..core.issue_processor import IssueProcessor, ProcessedResults
from ..scanners.security.trivy_scanner import TrivyScanner
from ..scanners.security.checkov_scanner import CheckovScanner
from ..scanners.security.gitleaks_scanner import GitleaksScanner
from ..scanners.security.builtin_secret_scanner import BuiltinSecretScanner
from ..scanners.performance.config_performance_scanner import ConfigPerformanceScanner
from ..scanners.reliability.config_reliability_scanner import ConfigReliabilityScanner
from ..database.storage import LocalStorage
from ..database.models import ProjectRecord, ScanRecord, IssueRecord, TrendData
from ..reporters.report_generator import ReportGenerator
from ..api.ai_insights import AIInsightsGenerator
from ..api.problem_insights import ProblemInsightsGenerator

console = Console()

# Directories to always exclude from scanning
EXCLUDED_DIRS = {
    '.git', 'node_modules', 'venv', '.venv', 'env', '.env',
    '__pycache__', '.pytest_cache', '.mypy_cache', '.tox',
    'dist', 'build', '.eggs', '*.egg-info', '.coverage',
    'htmlcov', '.hypothesis', '.nox', 'vendor', 'third_party',
    'prc_reports',  # PRC output directory - never scan our own reports
    'site-packages',  # Third-party packages - never scan installed libraries
    'lib',  # Common lib directory in virtual envs (lib/pythonX.X/)
}


def get_severity_color(severity: str) -> str:
    """Get color for severity level."""
    colors = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    return colors.get(severity.lower(), "white")


def get_score_color(score: float) -> str:
    """Get color for score value."""
    if score >= 90:
        return "green"
    elif score >= 80:
        return "green"
    elif score >= 70:
        return "yellow"
    elif score >= 60:
        return "orange1"
    else:
        return "red"


def generate_issue_fingerprint(issue: Issue) -> str:
    """Generate a unique fingerprint for deduplication.
    
    Uses canonical rule IDs and normalized paths to ensure issues from
    different scanners (e.g., Trivy and Checkov) that represent the same
    underlying problem are recognized as duplicates.

    Args:
        issue: Issue to fingerprint

    Returns:
        Unique fingerprint string
    """
    # Use canonical rule ID for cross-scanner matching
    # e.g., Trivy's DS002 and Checkov's CKV_DOCKER_3 both map to DS002
    canonical_rule = get_canonical_rule_id(issue.rule_id or "")
    
    # Normalize file path to handle differences in path reporting
    # e.g., "/Dockerfile" vs "Dockerfile"
    normalized_path = normalize_file_path(issue.file_path or "")
    
    # Create fingerprint from key fields
    components = [
        canonical_rule,
        normalized_path,
        str(issue.line_number or ""),
    ]
    combined = "|".join(components)
    return hashlib.md5(combined.encode()).hexdigest()


def deduplicate_issues(issues: List[Issue]) -> Tuple[List[Issue], int]:
    """Remove duplicate issues based on fingerprint.

    Args:
        issues: List of issues to deduplicate

    Returns:
        Tuple of (deduplicated issues, count of duplicates removed)
    """
    seen_fingerprints: Set[str] = set()
    unique_issues: List[Issue] = []
    duplicates_removed = 0

    for issue in issues:
        fingerprint = generate_issue_fingerprint(issue)
        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            unique_issues.append(issue)
        else:
            duplicates_removed += 1

    return unique_issues, duplicates_removed


def deduplicate_scan_results(scan_results: List[ScanResult]) -> List[ScanResult]:
    """Deduplicate issues across all scan results.

    Args:
        scan_results: List of scan results

    Returns:
        Scan results with deduplicated issues
    """
    # Collect all issues with their source
    all_issues: List[Tuple[Issue, str]] = []
    for result in scan_results:
        for issue in result.issues:
            all_issues.append((issue, result.scanner_name))

    # Deduplicate
    seen_fingerprints: Set[str] = set()
    unique_issues_by_scanner: Dict[str, List[Issue]] = {}

    for issue, scanner_name in all_issues:
        fingerprint = generate_issue_fingerprint(issue)
        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            if scanner_name not in unique_issues_by_scanner:
                unique_issues_by_scanner[scanner_name] = []
            unique_issues_by_scanner[scanner_name].append(issue)

    # Update scan results with deduplicated issues
    for result in scan_results:
        result.issues = unique_issues_by_scanner.get(result.scanner_name, [])

    return scan_results


@click.group()
@click.version_option(version="1.0.0", prog_name="prc")
@click.option("--data-dir", type=click.Path(), help="Data directory for storage")
@click.pass_context
def cli(ctx: click.Context, data_dir: Optional[str]):
    """Production Readiness Checker - Assess your application's production readiness."""
    ctx.ensure_object(dict)
    ctx.obj["data_dir"] = data_dir


@cli.command("scan")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--name", "-n", help="Project name (default: directory name)")
@click.option("--format", "-f", "formats", multiple=True, default=["json", "html", "pdf"],
              type=click.Choice(["json", "html", "pdf"]), help="Output formats (default: json, html, pdf)")
@click.option("--output", "-o", type=click.Path(), help="Output directory for reports")
@click.option("--ai/--no-ai", default=True, help="Enable/disable AI insights")
@click.option("--threshold", type=float, default=70.0, help="Production readiness threshold")
@click.option("--scanner", "-s", "scanners", multiple=True,
              type=click.Choice(["trivy", "checkov", "gitleaks", "builtin", "all"]),
              default=["all"], help="Scanners to use")
@click.pass_context
def scan(
    ctx: click.Context,
    path: str,
    name: Optional[str],
    formats: tuple,
    output: Optional[str],
    ai: bool,
    threshold: float,
    scanners: tuple,
):
    """Scan a project for production readiness.

    PATH is the directory to scan (default: current directory).
    """
    target_path = Path(path).resolve()
    project_name = name or target_path.name
    output_dir = output or str(target_path / "prc_reports")
    data_dir = ctx.obj.get("data_dir")

    # Check for OpenAI API key if AI is enabled
    openai_key = os.getenv("OPENAI_API_KEY")
    if ai and not openai_key:
        console.print("[yellow]Note: OPENAI_API_KEY not set. AI insights will use fallback mode.[/yellow]")
        console.print("[dim]Set it with: export OPENAI_API_KEY=your-api-key[/dim]\n")

    console.print(Panel.fit(
        f"[bold blue]Production Readiness Checker[/bold blue]\n"
        f"Scanning: [cyan]{target_path}[/cyan]",
        title="PRC Scan",
        border_style="blue"
    ))

    # Initialize storage
    storage = LocalStorage(data_dir=data_dir)

    # Create or get project
    project = ProjectRecord(
        name=project_name,
        path=str(target_path),
        description=f"Scanned on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    )
    project = storage.create_project(project)

    # Track scanner status
    scanner_status: Dict[str, str] = {}  # name -> status

    # Track timing
    scan_start_time = time.time()

    # File discovery phase
    console.print("[cyan]Phase 1/3:[/cyan] Discovering files...")
    discovery = FileDiscovery()
    discovered = discovery.discover(target_path)
    console.print(f"  Found [green]{discovered.total_files}[/green] files to analyze")

    # Run the full scan with progress
    console.print("[cyan]Phase 2/3:[/cyan] Running security scans...")

    # Store for tracking progress updates
    progress_state = {"task": None, "progress_bar": None}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        # Create task for overall scan progress
        scan_task = progress.add_task("[cyan]Scanning...", total=100)
        progress_state["task"] = scan_task
        progress_state["progress_bar"] = progress

        # Define progress update callback that updates the Rich progress bar
        def update_progress(percent, description):
            progress.update(scan_task, completed=percent, description=f"[cyan]{description}")

        # Use asyncio.run() which handles cleanup properly
        try:
            # Initial progress update
            progress.update(scan_task, completed=5, description="[cyan]Initializing scanners...")
            
            # Run the async function with progress callback
            async def run_with_progress():
                return await run_full_scan_with_callback(update_progress)
            
            # Wrapper to pass the callback
            async def run_full_scan_with_callback(progress_update_callback):
                nonlocal output_dir, scanner_status

                # Initialize scanners
                active_scanners = []
                skipped_scanners = []

                scanner_list = list(scanners)
                if "all" in scanner_list:
                    scanner_list = ["trivy", "checkov", "gitleaks", "builtin"]

                for scanner_name in scanner_list:
                    if scanner_name == "trivy":
                        scanner = TrivyScanner()
                        if scanner.is_available():
                            active_scanners.append(scanner)
                            scanner_status["Trivy"] = "active"
                        else:
                            skipped_scanners.append(("Trivy", "not installed"))
                            scanner_status["Trivy"] = "skipped (not installed)"
                    elif scanner_name == "checkov":
                        scanner = CheckovScanner()
                        if scanner.is_available():
                            active_scanners.append(scanner)
                            scanner_status["Checkov"] = "active"
                        else:
                            skipped_scanners.append(("Checkov", "not installed"))
                            scanner_status["Checkov"] = "skipped (not installed)"
                    elif scanner_name == "gitleaks":
                        scanner = GitleaksScanner()
                        if scanner.is_available():
                            active_scanners.append(scanner)
                            scanner_status["Gitleaks"] = "active"
                        else:
                            skipped_scanners.append(("Gitleaks", "not installed"))
                            scanner_status["Gitleaks"] = "skipped (not installed)"
                    elif scanner_name == "builtin":
                        # Built-in scanner with exclusions
                        scanner = BuiltinSecretScanner()
                        active_scanners.append(scanner)
                        scanner_status["Built-in Secret Scanner"] = "active"

                # Always ensure built-in scanner is included
                if not any(isinstance(s, BuiltinSecretScanner) for s in active_scanners):
                    active_scanners.append(BuiltinSecretScanner())
                    scanner_status["Built-in Secret Scanner"] = "active"

                if not active_scanners:
                    return None, None, [], skipped_scanners, None

                # Run scans with progress callback
                executor = ParallelExecutor()
                executor.add_scanners(active_scanners)
                
                # Create a callback to report progress
                def on_scanner_complete(completed, total, scanner_name):
                    # Report progress: scanners take 10-80% of progress
                    progress_percent = 10 + int((completed / total) * 70)
                    if progress_update_callback:
                        progress_update_callback(progress_percent, f"Completed {scanner_name} ({completed}/{total})")
                
                execution_result = await executor.execute(str(target_path), progress_callback=on_scanner_complete)
                scan_results = execution_result.scan_results

                # Deduplicate issues across all scanners
                if progress_update_callback:
                    progress_update_callback(80, "Deduplicating issues...")
                scan_results = deduplicate_scan_results(scan_results)

                # Process and group issues
                if progress_update_callback:
                    progress_update_callback(83, "Processing and classifying issues...")

                issue_processor = IssueProcessor(
                    api_key=os.getenv("OPENAI_API_KEY"),
                    use_ai_classification=ai,
                )
                processed_results = await issue_processor.process_scan_results(scan_results)

                # Generate AI insights for unique problems
                if progress_update_callback:
                    progress_update_callback(86, "Generating problem insights...")

                if ai:
                    problem_insights_gen = ProblemInsightsGenerator(
                        api_key=os.getenv("OPENAI_API_KEY"),
                    )
                    processed_results = await problem_insights_gen.generate_insights(processed_results)

                # Calculate score based on unique problems
                if progress_update_callback:
                    progress_update_callback(89, "Calculating score...")
                scorer = Scorer(readiness_threshold=threshold)
                score = scorer.calculate_score_from_problems(processed_results)

                # Generate reports
                if progress_update_callback:
                    progress_update_callback(92, "Generating reports...")
                generator = ReportGenerator(
                    output_dir=output_dir,
                    enable_ai_insights=ai,
                    openai_api_key=os.getenv("OPENAI_API_KEY"),
                )
                report_paths = await generator.generate_reports(
                    project_name=project_name,
                    project_path=str(target_path),
                    scan_results=scan_results,
                    score=score,
                    formats=list(formats),
                    include_ai=ai,
                    processed_results=processed_results,
                )

                return score, report_paths, scan_results, skipped_scanners, processed_results
            
            result = asyncio.run(run_with_progress())
        except Exception as e:
            console.print(f"[red]Error during scan: {e}[/red]")
            sys.exit(1)

        if result[0] is None:
            console.print("[red]Error: No scanners available.[/red]")
            sys.exit(1)

        score, report_paths, scan_results, skipped_scanners, processed_results = result
        progress.update(scan_task, completed=100, description="[green]Scan complete!")

    # Calculate elapsed time
    elapsed_time = time.time() - scan_start_time
    minutes, seconds = divmod(int(elapsed_time), 60)

    # Show active scanners
    active_names = list(set(r.scanner_name for r in scan_results)) if scan_results else []
    console.print(f"  Active scanners: [green]{', '.join(active_names) if active_names else 'None'}[/green]")

    # Show skipped scanners
    if skipped_scanners:
        skipped_info = ", ".join([f"{name} ({reason})" for name, reason in skipped_scanners])
        console.print(f"  Skipped scanners: [yellow]{skipped_info}[/yellow]")

    # Show timing
    console.print(f"  [cyan]Total scan time:[/cyan] {minutes}m {seconds}s")

    # Phase 3: Report generation
    console.print("[cyan]Phase 3/3:[/cyan] Reports generated")

    # Display results
    console.print()
    _display_scan_results(scan_results, score, report_paths, scanner_status, processed_results)

    # Save to storage
    _save_to_storage(storage, project, scan_results, score, report_paths)

    # Exit with appropriate code
    if not score.is_production_ready:
        sys.exit(1)


@cli.command("history")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--limit", "-l", type=int, default=10, help="Number of scans to show")
@click.pass_context
def history(ctx: click.Context, path: str, limit: int):
    """Show scan history for a project."""
    target_path = Path(path).resolve()
    data_dir = ctx.obj.get("data_dir")

    storage = LocalStorage(data_dir=data_dir)
    project = storage.get_project_by_path(str(target_path))

    if not project:
        console.print(f"[yellow]No scan history found for {target_path}[/yellow]")
        return

    scans = storage.get_scans_for_project(project.id, limit=limit)

    if not scans:
        console.print(f"[yellow]No scans found for {project.name}[/yellow]")
        return

    table = Table(title=f"Scan History: {project.name}")
    table.add_column("Date", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Grade", justify="center")
    table.add_column("Issues", justify="right")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("Status")

    for scan in scans:
        score_color = get_score_color(scan.overall_score)
        status = "Ready" if scan.is_production_ready else "Not Ready"
        status_style = "green" if scan.is_production_ready else "red"

        table.add_row(
            scan.started_at.strftime("%Y-%m-%d %H:%M"),
            f"[{score_color}]{scan.overall_score:.1f}[/{score_color}]",
            scan.category_scores.get("grade", "N/A") if isinstance(scan.category_scores, dict) else "N/A",
            str(scan.total_issues),
            str(scan.critical_count),
            f"[{status_style}]{status}[/{status_style}]",
        )

    console.print(table)


@cli.command("status")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.pass_context
def status(ctx: click.Context, path: str):
    """Show current status and statistics for a project."""
    target_path = Path(path).resolve()
    data_dir = ctx.obj.get("data_dir")

    storage = LocalStorage(data_dir=data_dir)
    project = storage.get_project_by_path(str(target_path))

    if not project:
        console.print(f"[yellow]No project found for {target_path}[/yellow]")
        console.print("Run 'prc scan' to analyze this project first.")
        return

    stats = storage.get_project_statistics(project.id)

    console.print(Panel.fit(
        f"[bold]{project.name}[/bold]\n"
        f"Path: {project.path}",
        title="Project Status",
        border_style="blue"
    ))

    if stats["scan_count"] == 0:
        console.print("[yellow]No scans recorded yet.[/yellow]")
        return

    score_color = get_score_color(stats["latest_score"])
    status_text = "Production Ready" if stats["is_production_ready"] else "Not Production Ready"
    status_color = "green" if stats["is_production_ready"] else "red"

    console.print(f"\n[bold]Latest Scan:[/bold]")
    console.print(f"  Score: [{score_color}]{stats['latest_score']:.1f}/100[/{score_color}]")
    console.print(f"  Status: [{status_color}]{status_text}[/{status_color}]")
    console.print(f"  Issues: {stats['latest_issues']} (Critical: {stats['latest_critical']}, High: {stats['latest_high']})")

    if stats.get("last_scan"):
        console.print(f"  Last Scan: {stats['last_scan']}")

    console.print(f"\n[bold]Statistics (30 days):[/bold]")
    console.print(f"  Total Scans: {stats['scan_count']}")
    console.print(f"  Average Score: {stats['average_score_30d']:.1f}")

    trend = stats.get("score_trend", 0)
    trend_symbol = "↑" if trend > 0 else "↓" if trend < 0 else "→"
    trend_color = "green" if trend > 0 else "red" if trend < 0 else "yellow"
    console.print(f"  Trend: [{trend_color}]{trend_symbol} {abs(trend):.1f} points[/{trend_color}]")


@cli.command("issues")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info", "all"]),
              default="all", help="Filter by severity")
@click.option("--limit", "-l", type=int, default=20, help="Number of issues to show")
@click.pass_context
def issues(ctx: click.Context, path: str, severity: str, limit: int):
    """List issues from the latest scan."""
    target_path = Path(path).resolve()
    data_dir = ctx.obj.get("data_dir")

    storage = LocalStorage(data_dir=data_dir)
    project = storage.get_project_by_path(str(target_path))

    if not project:
        console.print(f"[yellow]No project found for {target_path}[/yellow]")
        return

    latest_scan = storage.get_latest_scan(project.id)
    if not latest_scan:
        console.print(f"[yellow]No scans found for {project.name}[/yellow]")
        return

    issues_list = storage.get_issues_for_scan(latest_scan.id)

    if severity != "all":
        issues_list = [i for i in issues_list if i.severity.lower() == severity]

    if not issues_list:
        console.print(f"[green]No issues found matching criteria.[/green]")
        return

    table = Table(title=f"Issues: {project.name} (Scan: {latest_scan.started_at.strftime('%Y-%m-%d %H:%M')})")
    table.add_column("Severity", width=10)
    table.add_column("Title", width=40)
    table.add_column("File", width=30)
    table.add_column("Scanner", width=15)
    table.add_column("Fixable", width=8, justify="center")

    for issue in issues_list[:limit]:
        sev_color = get_severity_color(issue.severity)
        file_info = issue.file_path or "N/A"
        if issue.line_number:
            file_info = f"{file_info}:{issue.line_number}"
        if len(file_info) > 28:
            file_info = "..." + file_info[-25:]

        table.add_row(
            f"[{sev_color}]{issue.severity.upper()}[/{sev_color}]",
            issue.title[:38] + "..." if len(issue.title) > 38 else issue.title,
            file_info,
            issue.scanner or "N/A",
            "[green]Yes[/green]" if issue.auto_fixable else "[dim]No[/dim]",
        )

    console.print(table)

    if len(issues_list) > limit:
        console.print(f"\n[dim]Showing {limit} of {len(issues_list)} issues. Use --limit to see more.[/dim]")


@cli.command("projects")
@click.pass_context
def projects(ctx: click.Context):
    """List all tracked projects."""
    data_dir = ctx.obj.get("data_dir")
    storage = LocalStorage(data_dir=data_dir)

    projects_list = storage.list_projects()

    if not projects_list:
        console.print("[yellow]No projects found. Run 'prc scan' to analyze a project.[/yellow]")
        return

    table = Table(title="Tracked Projects")
    table.add_column("Name", style="cyan")
    table.add_column("Path")
    table.add_column("Last Updated")

    for project in projects_list:
        table.add_row(
            project.name,
            project.path,
            project.updated_at.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


@cli.command("check-tools")
def check_tools():
    """Check availability of scanning tools."""
    console.print(Panel.fit(
        "[bold]Tool Availability Check[/bold]",
        border_style="blue"
    ))

    tools = [
        ("Trivy", TrivyScanner(), "Security vulnerability scanner"),
        ("Checkov", CheckovScanner(), "IaC security scanner"),
        ("Gitleaks", GitleaksScanner(), "Git secret detection"),
        ("Built-in Secret Scanner", BuiltinSecretScanner(), "Hardcoded secret detection"),
        ("Performance Scanner", ConfigPerformanceScanner(), "Config-based performance analysis"),
        ("Reliability Scanner", ConfigReliabilityScanner(), "Config-based reliability analysis"),
    ]

    table = Table()
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Description")
    table.add_column("Installation")

    for name, scanner, description in tools:
        if scanner.is_available():
            status = "[green]✓ Available[/green]"
            if name in ["Built-in Secret Scanner", "Performance Scanner", "Reliability Scanner"]:
                install = "[dim]Built-in (no installation needed)[/dim]"
            else:
                install = "[dim]Installed[/dim]"
        else:
            status = "[red]✗ Not Found[/red]"
            if name == "Trivy":
                install = "https://trivy.dev/latest/getting-started/installation/"
            elif name == "Checkov":
                install = "pip install checkov"
            elif name == "Gitleaks":
                install = "https://github.com/gitleaks/gitleaks#installing"
            else:
                install = "See documentation"

        table.add_row(name, status, description, install)

    console.print(table)

    # Check for optional dependencies
    console.print("\n[bold]Optional Dependencies:[/bold]")

    # Check ReportLab for PDF
    try:
        import reportlab
        console.print("  PDF Generation (ReportLab): [green]✓ Available[/green]")
    except ImportError:
        console.print("  PDF Generation (ReportLab): [yellow]✗ Not installed[/yellow] - pip install reportlab")

    # Check OpenAI
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        console.print("  AI Insights (OpenAI): [green]✓ Configured[/green]")
    else:
        console.print("  AI Insights (OpenAI): [yellow]✗ Not configured[/yellow] - Set OPENAI_API_KEY environment variable")

    # Excluded directories
    console.print("\n[bold]Excluded Directories (auto-skipped):[/bold]")
    console.print(f"  {', '.join(sorted(EXCLUDED_DIRS))}")


@cli.command("config")
def config():
    """Show configuration and environment variables."""
    console.print(Panel.fit(
        "[bold]Configuration Guide[/bold]",
        border_style="blue"
    ))

    console.print("\n[bold]Environment Variables:[/bold]\n")

    env_vars = [
        ("OPENAI_API_KEY", "OpenAI API key for AI-powered insights", os.getenv("OPENAI_API_KEY")),
        ("PRC_DATA_DIR", "Data directory for local storage", os.getenv("PRC_DATA_DIR", "~/.prc")),
    ]

    table = Table()
    table.add_column("Variable", style="cyan")
    table.add_column("Description")
    table.add_column("Status")

    for var_name, description, value in env_vars:
        if value:
            if "KEY" in var_name or "SECRET" in var_name:
                status = "[green]Set[/green] (hidden)"
            else:
                status = f"[green]{value}[/green]"
        else:
            status = "[yellow]Not set[/yellow]"

        table.add_row(var_name, description, status)

    console.print(table)

    console.print("\n[bold]How to set environment variables:[/bold]\n")
    console.print("  [cyan]Linux/macOS (temporary):[/cyan]")
    console.print("    export OPENAI_API_KEY=your-api-key-here\n")
    console.print("  [cyan]Linux/macOS (permanent - add to ~/.bashrc or ~/.zshrc):[/cyan]")
    console.print("    echo 'export OPENAI_API_KEY=your-api-key-here' >> ~/.bashrc\n")
    console.print("  [cyan]Windows (Command Prompt):[/cyan]")
    console.print("    set OPENAI_API_KEY=your-api-key-here\n")
    console.print("  [cyan]Windows (PowerShell):[/cyan]")
    console.print("    $env:OPENAI_API_KEY=\"your-api-key-here\"\n")


def _display_scan_results(
    scan_results: List[ScanResult],
    score: Score,
    report_paths: dict,
    scanner_status: Dict[str, str] = None,
    processed_results: ProcessedResults = None,
):
    """Display scan results in the terminal."""
    # Score display
    score_color = get_score_color(score.overall_score)
    status_color = "green" if score.is_production_ready else "red"

    console.print(Panel.fit(
        f"[bold {score_color}]{score.overall_score:.1f}[/bold {score_color}] / 100\n"
        f"Grade: [bold]{score.grade}[/bold]",
        title="Overall Score",
        border_style=score_color,
    ))

    console.print(f"\nStatus: [{status_color}]{score.status}[/{status_color}]")

    # Severity summary
    total_issues = sum(r.issue_count for r in scan_results)
    critical = sum(r.critical_count for r in scan_results)
    high = sum(r.high_count for r in scan_results)
    medium = sum(r.medium_count for r in scan_results)
    low = sum(r.low_count for r in scan_results)

    # Display unique problems summary if available
    if processed_results:
        console.print(f"\n[bold]Issues Summary:[/bold]")
        console.print(f"  Total issue instances: {processed_results.total_issues}")
        console.print(f"  Unique problems: [cyan]{processed_results.total_unique_problems}[/cyan]")
        console.print(f"  [dim](Scoring is based on unique problems, not total instances)[/dim]")
    else:
        console.print(f"\n[bold]Issues Found:[/bold] {total_issues}")

    console.print(f"\n  [red]Critical: {critical}[/red] | [orange1]High: {high}[/orange1] | "
                  f"[yellow]Medium: {medium}[/yellow] | [blue]Low: {low}[/blue]")

    # Unique problems by dimension
    if processed_results and processed_results.problems_by_dimension:
        console.print("\n[bold]Unique Problems by Dimension:[/bold]")
        dimension_icons = {
            "security": "🔒",
            "performance": "⚡",
            "reliability": "🛡️",
            "monitoring": "📊",
        }
        for dimension in ["security", "performance", "reliability", "monitoring"]:
            problems = processed_results.problems_by_dimension.get(dimension, [])
            if problems:
                summary = processed_results.dimension_summary.get(dimension, {})
                icon = dimension_icons.get(dimension, "📋")
                console.print(f"  {icon} {dimension.title()}: {len(problems)} problems "
                             f"({summary.get('total_occurrences', 0)} occurrences)")
    # Issues by scanner (fallback display)
    elif scan_results:
        console.print("\n[bold]Issues by Scanner:[/bold]")
        for result in scan_results:
            if result.issue_count > 0:
                console.print(f"  {result.scanner_name}: {result.issue_count} issues")

    # Category scores
    if score.category_scores:
        console.print("\n[bold]Category Scores:[/bold]")
        for name, cat_score in score.category_scores.items():
            cat_color = get_score_color(cat_score.score)
            console.print(f"  {name.title()}: [{cat_color}]{cat_score.score:.1f}[/{cat_color}] "
                         f"({cat_score.issues_count} issues)")

    # Reports
    if report_paths:
        console.print("\n[bold]Reports Generated:[/bold]")
        for fmt, path in report_paths.items():
            console.print(f"  {fmt.upper()}: [cyan]{path}[/cyan]")


def _save_to_storage(
    storage: LocalStorage,
    project: ProjectRecord,
    scan_results: List[ScanResult],
    score: Score,
    report_paths: dict,
):
    """Save scan results to storage."""
    # Create scan record
    scan_record = ScanRecord(
        project_id=project.id,
        scan_type="comprehensive",
        scanner_name=",".join(r.scanner_name for r in scan_results),
        target_path=project.path,
        overall_score=score.overall_score,
        is_production_ready=score.is_production_ready,
        total_issues=score.total_issues,
        critical_count=sum(r.critical_count for r in scan_results),
        high_count=sum(r.high_count for r in scan_results),
        medium_count=sum(r.medium_count for r in scan_results),
        low_count=sum(r.low_count for r in scan_results),
        info_count=sum(r.info_count for r in scan_results),
        duration_ms=sum(r.scan_duration_ms for r in scan_results),
        started_at=datetime.now(),
        completed_at=datetime.now(),
        category_scores={k: v.to_dict() for k, v in score.category_scores.items()},
        report_path=report_paths.get("html") or report_paths.get("json"),
    )
    scan_record = storage.save_scan(scan_record)

    # Save issues
    issue_records = []
    for result in scan_results:
        for issue in result.issues:
            issue_record = IssueRecord(
                scan_id=scan_record.id,
                issue_id=issue.id,
                title=issue.title,
                description=issue.description,
                severity=issue.severity.value,
                category=issue.category.value,
                file_path=issue.file_path,
                line_number=issue.line_number,
                rule_id=issue.rule_id,
                scanner=issue.scanner,
                remediation=issue.remediation,
                auto_fixable=issue.auto_fixable,
                fix_suggestion=issue.fix_suggestion,
                metadata=issue.metadata,
            )
            issue_records.append(issue_record)

    if issue_records:
        storage.save_issues(issue_records)

    # Save trend data
    trend = TrendData(
        project_id=project.id,
        date=datetime.now(),
        overall_score=score.overall_score,
        security_score=score.category_scores.get("security", type("", (), {"score": 0})).score,
        total_issues=score.total_issues,
        critical_count=sum(r.critical_count for r in scan_results),
        high_count=sum(r.high_count for r in scan_results),
    )
    storage.save_trend(trend)


def main():
    """Entry point for the CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
