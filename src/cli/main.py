"""Main CLI Module - Command-line interface for Production Readiness Checker."""

import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.text import Text
from rich import print as rprint

from ..core.file_discovery import FileDiscovery
from ..core.scanner import ScanResult, Severity
from ..core.scorer import Scorer, Score
from ..core.parallel_executor import ParallelExecutor
from ..scanners.security.trivy_scanner import TrivyScanner
from ..scanners.security.checkov_scanner import CheckovScanner
from ..scanners.security.gitleaks_scanner import GitleaksScanner
from ..database.storage import LocalStorage
from ..database.models import ProjectRecord, ScanRecord, IssueRecord, TrendData
from ..reporters.report_generator import ReportGenerator
from ..api.ai_insights import AIInsightsGenerator

console = Console()


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
@click.option("--format", "-f", "formats", multiple=True, default=["json", "html"],
              type=click.Choice(["json", "html", "pdf"]), help="Output formats")
@click.option("--output", "-o", type=click.Path(), help="Output directory for reports")
@click.option("--ai/--no-ai", default=True, help="Enable/disable AI insights")
@click.option("--threshold", type=float, default=70.0, help="Production readiness threshold")
@click.option("--scanner", "-s", "scanners", multiple=True,
              type=click.Choice(["trivy", "checkov", "gitleaks", "all"]),
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

    # Run the scan
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
    ) as progress:
        # File discovery
        task = progress.add_task("[cyan]Discovering files...", total=None)
        discovery = FileDiscovery()
        discovered = discovery.discover(target_path)
        progress.update(task, completed=True)
        console.print(f"  Found [green]{discovered.total_files}[/green] files to analyze")

        # Initialize scanners
        task = progress.add_task("[cyan]Initializing scanners...", total=None)
        active_scanners = []

        scanner_list = list(scanners)
        if "all" in scanner_list:
            scanner_list = ["trivy", "checkov", "gitleaks"]

        for scanner_name in scanner_list:
            if scanner_name == "trivy":
                scanner = TrivyScanner()
                if scanner.is_available():
                    active_scanners.append(scanner)
                else:
                    console.print(f"  [yellow]Warning: Trivy not available[/yellow]")
            elif scanner_name == "checkov":
                scanner = CheckovScanner()
                if scanner.is_available():
                    active_scanners.append(scanner)
                else:
                    console.print(f"  [yellow]Warning: Checkov not available[/yellow]")
            elif scanner_name == "gitleaks":
                scanner = GitleaksScanner()
                if scanner.is_available():
                    active_scanners.append(scanner)
                else:
                    console.print(f"  [yellow]Warning: Gitleaks not available[/yellow]")

        progress.update(task, completed=True)

        if not active_scanners:
            console.print("[red]Error: No scanners available. Please install trivy, checkov, or gitleaks.[/red]")
            sys.exit(1)

        console.print(f"  Active scanners: [green]{', '.join(s.name for s in active_scanners)}[/green]")

        # Run scans
        task = progress.add_task("[cyan]Running security scans...", total=len(active_scanners))
        scan_results: List[ScanResult] = []

        async def run_scans():
            executor = ParallelExecutor()
            executor.add_scanners(active_scanners)
            return await executor.execute(str(target_path))

        execution_result = asyncio.run(run_scans())
        scan_results = execution_result.scan_results
        progress.update(task, advance=len(active_scanners))

        # Calculate score
        task = progress.add_task("[cyan]Calculating scores...", total=None)
        scorer = Scorer(readiness_threshold=threshold)
        score = scorer.calculate_score(scan_results)
        progress.update(task, completed=True)

        # Generate reports
        task = progress.add_task("[cyan]Generating reports...", total=None)

        async def generate_reports():
            generator = ReportGenerator(
                output_dir=output_dir,
                enable_ai_insights=ai,
                openai_api_key=os.getenv("OPENAI_API_KEY"),
            )
            return await generator.generate_reports(
                project_name=project_name,
                project_path=str(target_path),
                scan_results=scan_results,
                score=score,
                formats=list(formats),
                include_ai=ai,
            )

        report_paths = asyncio.run(generate_reports())
        progress.update(task, completed=True)

    # Display results
    console.print()
    _display_scan_results(scan_results, score, report_paths)

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
        ("Trivy", TrivyScanner()),
        ("Checkov", CheckovScanner()),
        ("Gitleaks", GitleaksScanner()),
    ]

    table = Table()
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Installation")

    for name, scanner in tools:
        if scanner.is_available():
            status = "[green]Available[/green]"
            install = "[dim]Installed[/dim]"
        else:
            status = "[red]Not Found[/red]"
            if name == "Trivy":
                install = "https://trivy.dev/latest/getting-started/installation/"
            elif name == "Checkov":
                install = "pip install checkov"
            elif name == "Gitleaks":
                install = "https://github.com/gitleaks/gitleaks#installing"
            else:
                install = "See documentation"

        table.add_row(name, status, install)

    console.print(table)


def _display_scan_results(
    scan_results: List[ScanResult],
    score: Score,
    report_paths: dict,
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

    console.print(f"\n[bold]Issues Found:[/bold] {total_issues}")
    console.print(f"  [red]Critical: {critical}[/red] | [orange1]High: {high}[/orange1] | "
                  f"[yellow]Medium: {medium}[/yellow] | [blue]Low: {low}[/blue]")

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
