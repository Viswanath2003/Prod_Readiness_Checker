"""PDF Reporter Module - Generate PDF format reports."""

from io import BytesIO
from typing import Optional, List, Tuple

from .base_reporter import BaseReporter, ReportData

# Attempt to import ReportLab
REPORTLAB_AVAILABLE = False
colors = None
letter = A4 = None
getSampleStyleSheet = ParagraphStyle = None
inch = None
SimpleDocTemplate = Paragraph = Spacer = Table = TableStyle = None
PageBreak = Image = HRFlowable = None
TA_CENTER = TA_LEFT = TA_RIGHT = None

try:
    from reportlab.lib import colors as _colors
    from reportlab.lib.pagesizes import letter as _letter, A4 as _A4
    from reportlab.lib.styles import getSampleStyleSheet as _getSampleStyleSheet, ParagraphStyle as _ParagraphStyle
    from reportlab.lib.units import inch as _inch
    from reportlab.platypus import (
        SimpleDocTemplate as _SimpleDocTemplate,
        Paragraph as _Paragraph,
        Spacer as _Spacer,
        Table as _Table,
        TableStyle as _TableStyle,
        PageBreak as _PageBreak,
        Image as _Image,
        HRFlowable as _HRFlowable
    )
    from reportlab.lib.enums import TA_CENTER as _TA_CENTER, TA_LEFT as _TA_LEFT, TA_RIGHT as _TA_RIGHT

    # Assign to module-level variables
    colors = _colors
    letter = _letter
    A4 = _A4
    getSampleStyleSheet = _getSampleStyleSheet
    ParagraphStyle = _ParagraphStyle
    inch = _inch
    SimpleDocTemplate = _SimpleDocTemplate
    Paragraph = _Paragraph
    Spacer = _Spacer
    Table = _Table
    TableStyle = _TableStyle
    PageBreak = _PageBreak
    Image = _Image
    HRFlowable = _HRFlowable
    TA_CENTER = _TA_CENTER
    TA_LEFT = _TA_LEFT
    TA_RIGHT = _TA_RIGHT

    REPORTLAB_AVAILABLE = True
except ImportError:
    pass


class PDFReporter(BaseReporter):
    """Generate reports in PDF format using ReportLab."""

    def __init__(
        self,
        output_dir: Optional[str] = None,
        page_size: str = "letter",
        include_ai_insights: bool = True,
    ):
        """Initialize the PDF reporter.

        Args:
            output_dir: Directory to save reports
            page_size: Page size ('letter' or 'a4')
            include_ai_insights: Include AI insights section
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError(
                "ReportLab is required for PDF generation. "
                "Install it with: pip install reportlab"
            )

        super().__init__(output_dir)
        self.page_size = letter if page_size.lower() == "letter" else A4
        self.include_ai_insights = include_ai_insights

        # Initialize colors after confirming ReportLab is available
        self._init_colors()

    def _init_colors(self):
        """Initialize color definitions."""
        self.COLORS = {
            "primary": colors.HexColor("#2563eb"),
            "success": colors.HexColor("#16a34a"),
            "warning": colors.HexColor("#f59e0b"),
            "danger": colors.HexColor("#dc2626"),
            "critical": colors.HexColor("#7c2d12"),
            "high": colors.HexColor("#dc2626"),
            "medium": colors.HexColor("#f59e0b"),
            "low": colors.HexColor("#2563eb"),
            "info": colors.HexColor("#6b7280"),
            "light_gray": colors.HexColor("#f1f5f9"),
            "dark_gray": colors.HexColor("#1e293b"),
        }

    @property
    def format(self) -> str:
        return "pdf"

    @property
    def extension(self) -> str:
        return "pdf"

    def generate(self, report_data: ReportData) -> bytes:
        """Generate PDF report.

        Args:
            report_data: Data to include in the report

        Returns:
            PDF content as bytes
        """
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=self.page_size,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        # Build the PDF content
        story = []
        styles = self._get_styles()

        # Title page
        story.extend(self._build_title_page(report_data, styles))

        # Executive summary
        story.extend(self._build_summary_section(report_data, styles))

        # Category scores
        story.extend(self._build_category_section(report_data, styles))

        # AI Insights (if available)
        if self.include_ai_insights and report_data.ai_insights:
            story.extend(self._build_ai_insights_section(report_data, styles))

        # Issues section
        story.extend(self._build_issues_section(report_data, styles))

        # Scan information
        story.extend(self._build_scan_info_section(report_data, styles))

        # Build PDF
        doc.build(story)

        return buffer.getvalue()

    def _get_styles(self) -> dict:
        """Get custom paragraph styles."""
        base_styles = getSampleStyleSheet()

        custom_styles = {
            "base": base_styles,
            "title": ParagraphStyle(
                "CustomTitle",
                parent=base_styles["Heading1"],
                fontSize=24,
                textColor=self.COLORS["primary"],
                spaceAfter=12,
                alignment=TA_CENTER,
            ),
            "subtitle": ParagraphStyle(
                "Subtitle",
                parent=base_styles["Normal"],
                fontSize=14,
                textColor=self.COLORS["dark_gray"],
                alignment=TA_CENTER,
                spaceAfter=6,
            ),
            "heading": ParagraphStyle(
                "CustomHeading",
                parent=base_styles["Heading2"],
                fontSize=16,
                textColor=self.COLORS["primary"],
                spaceBefore=20,
                spaceAfter=10,
            ),
            "subheading": ParagraphStyle(
                "SubHeading",
                parent=base_styles["Heading3"],
                fontSize=12,
                textColor=self.COLORS["dark_gray"],
                spaceBefore=12,
                spaceAfter=6,
            ),
            "body": ParagraphStyle(
                "CustomBody",
                parent=base_styles["Normal"],
                fontSize=10,
                textColor=self.COLORS["dark_gray"],
                spaceAfter=8,
            ),
            "small": ParagraphStyle(
                "Small",
                parent=base_styles["Normal"],
                fontSize=8,
                textColor=self.COLORS["info"],
            ),
            "score": ParagraphStyle(
                "Score",
                parent=base_styles["Normal"],
                fontSize=48,
                textColor=self.COLORS["primary"],
                alignment=TA_CENTER,
            ),
        }

        return custom_styles

    def _build_title_page(self, report_data: ReportData, styles: dict) -> List:
        """Build the title page elements."""
        elements = []

        elements.append(Spacer(1, 1 * inch))

        # Title
        elements.append(Paragraph(
            "Production Readiness Assessment Report",
            styles["title"]
        ))

        elements.append(Spacer(1, 0.25 * inch))

        # Project name
        elements.append(Paragraph(
            f"<b>{report_data.project_name}</b>",
            styles["subtitle"]
        ))

        elements.append(Spacer(1, 0.5 * inch))

        # Score display
        score_color = (
            self.COLORS["success"] if report_data.score.is_production_ready and report_data.score.overall_score >= 80
            else self.COLORS["warning"] if report_data.score.overall_score >= 60
            else self.COLORS["danger"]
        )

        score_style = ParagraphStyle(
            "ScoreValue",
            fontSize=72,
            textColor=score_color,
            alignment=TA_CENTER,
        )
        elements.append(Paragraph(f"{report_data.score.overall_score:.0f}", score_style))
        elements.append(Paragraph("Overall Score", styles["subtitle"]))

        elements.append(Spacer(1, 0.25 * inch))

        # Grade and status
        elements.append(Paragraph(
            f"Grade: <b>{report_data.score.grade}</b>",
            styles["subtitle"]
        ))

        status_text = report_data.score.status
        status_color = "green" if report_data.score.is_production_ready else "red"
        elements.append(Paragraph(
            f'<font color="{status_color}">{status_text}</font>',
            styles["subtitle"]
        ))

        elements.append(Spacer(1, 0.5 * inch))

        # Timestamp
        elements.append(Paragraph(
            f"Generated: {report_data.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            styles["small"]
        ))

        elements.append(PageBreak())

        return elements

    def _build_summary_section(self, report_data: ReportData, styles: dict) -> List:
        """Build the summary section."""
        elements = []

        elements.append(Paragraph("Executive Summary", styles["heading"]))
        elements.append(HRFlowable(
            width="100%",
            thickness=1,
            color=self.COLORS["light_gray"],
            spaceAfter=10
        ))

        # Summary table
        summary_data = [
            ["Metric", "Value"],
            ["Overall Score", f"{report_data.score.overall_score:.1f}/100"],
            ["Grade", report_data.score.grade],
            ["Production Ready", "Yes" if report_data.score.is_production_ready else "No"],
            ["Total Issues", str(report_data.total_issues)],
            ["Blocking Issues", str(report_data.score.blocking_issues)],
            ["Critical Issues", str(report_data.critical_count)],
            ["High Severity Issues", str(report_data.high_count)],
        ]

        table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.COLORS["primary"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), self.COLORS["light_gray"]),
            ("GRID", (0, 0), (-1, -1), 1, colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.COLORS["light_gray"]]),
        ]))
        elements.append(table)

        elements.append(Spacer(1, 0.5 * inch))

        # Severity distribution
        elements.append(Paragraph("Issue Severity Distribution", styles["subheading"]))

        severity_data = [
            ["Severity", "Count"],
            ["Critical", str(report_data.critical_count)],
            ["High", str(report_data.high_count)],
            ["Medium", str(sum(r.medium_count for r in report_data.scan_results))],
            ["Low", str(sum(r.low_count for r in report_data.scan_results))],
            ["Info", str(sum(r.info_count for r in report_data.scan_results))],
        ]

        severity_colors = [
            colors.white,
            self.COLORS["critical"],
            self.COLORS["high"],
            self.COLORS["medium"],
            self.COLORS["low"],
            self.COLORS["info"],
        ]

        severity_table = Table(severity_data, colWidths=[2 * inch, 1.5 * inch])
        severity_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.COLORS["primary"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 1, colors.white),
        ] + [
            ("BACKGROUND", (0, i), (0, i), severity_colors[i])
            for i in range(1, len(severity_colors))
        ] + [
            ("TEXTCOLOR", (0, i), (0, i), colors.white)
            for i in range(1, 4)  # Critical, High, Medium
        ]))
        elements.append(severity_table)

        return elements

    def _build_category_section(self, report_data: ReportData, styles: dict) -> List:
        """Build the category scores section."""
        elements = []

        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph("Category Scores", styles["heading"]))
        elements.append(HRFlowable(
            width="100%",
            thickness=1,
            color=self.COLORS["light_gray"],
            spaceAfter=10
        ))

        # Category scores table
        cat_data = [["Category", "Score", "Grade", "Issues", "Critical", "High"]]

        for name, cat_score in report_data.score.category_scores.items():
            cat_data.append([
                name.title(),
                f"{cat_score.score:.1f}",
                cat_score.grade,
                str(cat_score.issues_count),
                str(cat_score.critical_count),
                str(cat_score.high_count),
            ])

        cat_table = Table(cat_data, colWidths=[1.5 * inch, 1 * inch, 0.75 * inch, 0.75 * inch, 0.75 * inch, 0.75 * inch])
        cat_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.COLORS["primary"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("ALIGN", (0, 0), (0, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 1, self.COLORS["light_gray"]),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.COLORS["light_gray"]]),
        ]))
        elements.append(cat_table)

        return elements

    def _build_ai_insights_section(self, report_data: ReportData, styles: dict) -> List:
        """Build the AI insights section."""
        elements = []

        elements.append(PageBreak())
        elements.append(Paragraph("AI-Powered Insights", styles["heading"]))
        elements.append(HRFlowable(
            width="100%",
            thickness=1,
            color=self.COLORS["light_gray"],
            spaceAfter=10
        ))

        ai = report_data.ai_insights

        # Executive summary
        elements.append(Paragraph("Executive Summary", styles["subheading"]))
        elements.append(Paragraph(ai.executive_summary, styles["body"]))

        # Key findings
        elements.append(Paragraph("Key Findings", styles["subheading"]))
        for finding in ai.key_findings:
            elements.append(Paragraph(f"• {finding}", styles["body"]))

        # Priority actions
        elements.append(Paragraph("Priority Actions", styles["subheading"]))
        for action in ai.priority_actions:
            priority = action.get("priority", "medium").upper()
            text = action.get("action", "")
            effort = action.get("effort", "")
            elements.append(Paragraph(
                f"<b>[{priority}]</b> {text} <i>({effort})</i>",
                styles["body"]
            ))

        # Risk overview
        elements.append(Paragraph("Risk Overview", styles["subheading"]))
        elements.append(Paragraph(ai.risk_overview, styles["body"]))

        return elements

    def _build_issues_section(self, report_data: ReportData, styles: dict) -> List:
        """Build the detailed issues section."""
        elements = []

        elements.append(PageBreak())
        elements.append(Paragraph(
            f"Detailed Issues ({report_data.total_issues} total)",
            styles["heading"]
        ))
        elements.append(HRFlowable(
            width="100%",
            thickness=1,
            color=self.COLORS["light_gray"],
            spaceAfter=10
        ))

        # Sort issues by severity
        sorted_issues = sorted(
            report_data.all_issues,
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity.value, 5)
        )

        # Create issues table (paginated)
        issues_per_page = 15
        for i, issue in enumerate(sorted_issues[:50]):  # Limit to first 50 issues
            if i > 0 and i % issues_per_page == 0:
                elements.append(PageBreak())

            severity_color = {
                "critical": self.COLORS["critical"],
                "high": self.COLORS["high"],
                "medium": self.COLORS["medium"],
                "low": self.COLORS["low"],
                "info": self.COLORS["info"],
            }.get(issue.severity.value, self.COLORS["info"])

            # Issue header
            elements.append(Paragraph(
                f'<font color="#{severity_color.hexval()[2:]}">[{issue.severity.value.upper()}]</font> {issue.title[:80]}',
                styles["subheading"]
            ))

            # Issue details
            file_info = issue.file_path or "N/A"
            if issue.line_number:
                file_info += f":{issue.line_number}"

            elements.append(Paragraph(
                f"<b>File:</b> {file_info}",
                styles["small"]
            ))
            elements.append(Paragraph(
                f"<b>Category:</b> {issue.category.value} | <b>Rule:</b> {issue.rule_id or 'N/A'}",
                styles["small"]
            ))

            # Description (truncated)
            desc = issue.description[:200] + "..." if len(issue.description) > 200 else issue.description
            elements.append(Paragraph(desc, styles["body"]))

            # Remediation if available
            if issue.remediation:
                rem = issue.remediation[:150] + "..." if len(issue.remediation) > 150 else issue.remediation
                elements.append(Paragraph(
                    f"<b>Remediation:</b> {rem}",
                    styles["small"]
                ))

            elements.append(Spacer(1, 0.2 * inch))

        if len(sorted_issues) > 50:
            elements.append(Paragraph(
                f"<i>... and {len(sorted_issues) - 50} more issues. See full report for details.</i>",
                styles["small"]
            ))

        return elements

    def _build_scan_info_section(self, report_data: ReportData, styles: dict) -> List:
        """Build the scan information section."""
        elements = []

        elements.append(PageBreak())
        elements.append(Paragraph("Scan Information", styles["heading"]))
        elements.append(HRFlowable(
            width="100%",
            thickness=1,
            color=self.COLORS["light_gray"],
            spaceAfter=10
        ))

        scan_data = [["Scanner", "Type", "Duration", "Issues", "Status"]]

        for result in report_data.scan_results:
            scan_data.append([
                result.scanner_name,
                result.scan_type,
                f"{result.scan_duration_ms}ms",
                str(result.issue_count),
                "Success" if result.success else "Failed",
            ])

        scan_table = Table(scan_data, colWidths=[1.5 * inch, 1.2 * inch, 1 * inch, 0.8 * inch, 1 * inch])
        scan_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.COLORS["primary"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 1, self.COLORS["light_gray"]),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, self.COLORS["light_gray"]]),
        ]))
        elements.append(scan_table)

        # Footer
        elements.append(Spacer(1, 1 * inch))
        elements.append(HRFlowable(
            width="100%",
            thickness=1,
            color=self.COLORS["light_gray"],
            spaceBefore=20,
            spaceAfter=10
        ))
        elements.append(Paragraph(
            "Production Readiness Checker v1.0.0",
            styles["small"]
        ))
        elements.append(Paragraph(
            f"Report generated: {report_data.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            styles["small"]
        ))

        return elements
