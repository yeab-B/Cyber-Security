"""PDF Report Generator.

Generates professional security assessment PDF reports containing:
- Cover page
- Executive summary
- Risk scores and charts
- Detailed vulnerability findings
- Recommendations
- Conclusion
"""
import os
import io
import logging
from datetime import datetime
from typing import Dict, Any, List
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from app.config import settings

logger = logging.getLogger(__name__)

# Brand colors
BRAND_PRIMARY = colors.HexColor("#6366F1")  # Indigo
BRAND_DARK = colors.HexColor("#1E1B4B")
BRAND_ACCENT = colors.HexColor("#818CF8")

SEVERITY_COLORS = {
    "critical": colors.HexColor("#EF4444"),
    "high": colors.HexColor("#F97316"),
    "medium": colors.HexColor("#EAB308"),
    "low": colors.HexColor("#3B82F6"),
    "info": colors.HexColor("#6B7280"),
}


def _get_styles():
    """Create custom paragraph styles."""
    styles = getSampleStyleSheet()
    
    styles.add(ParagraphStyle(
        "CoverTitle",
        parent=styles["Title"],
        fontSize=28,
        textColor=BRAND_DARK,
        spaceAfter=12,
        alignment=1,
    ))
    styles.add(ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontSize=14,
        textColor=colors.HexColor("#4B5563"),
        alignment=1,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=BRAND_PRIMARY,
        spaceAfter=12,
        spaceBefore=20,
    ))
    styles.add(ParagraphStyle(
        "SubSection",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=BRAND_DARK,
        spaceAfter=8,
        spaceBefore=14,
    ))
    styles.add(ParagraphStyle(
        "BodyText2",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#374151"),
        spaceAfter=6,
        leading=14,
    ))
    styles.add(ParagraphStyle(
        "FindingTitle",
        parent=styles["Heading3"],
        fontSize=12,
        textColor=BRAND_DARK,
        spaceAfter=4,
        spaceBefore=10,
    ))
    
    return styles


class ReportGenerator:
    """Generates professional PDF security assessment reports."""

    def __init__(self, scan_data: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]):
        self.scan = scan_data
        self.vulnerabilities = vulnerabilities
        self.styles = _get_styles()

    def generate(self, filename: str = None) -> str:
        """Generate the PDF report and return the file path."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.pdf"

        filepath = os.path.join(settings.REPORTS_DIR, filename)
        
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=60,
            leftMargin=60,
            topMargin=60,
            bottomMargin=60,
        )

        story = []

        # Cover page
        story.extend(self._build_cover_page())
        story.append(PageBreak())

        # Executive Summary
        story.extend(self._build_executive_summary())
        story.append(PageBreak())

        # Risk Score Overview
        story.extend(self._build_risk_overview())

        # Vulnerability Summary Table
        story.extend(self._build_vulnerability_summary())
        story.append(PageBreak())

        # Detailed Findings
        story.extend(self._build_detailed_findings())

        # Recommendations
        story.extend(self._build_recommendations())
        story.append(PageBreak())

        # Conclusion
        story.extend(self._build_conclusion())

        doc.build(story)
        logger.info(f"Report generated: {filepath}")
        return filepath

    def _build_cover_page(self):
        """Build the cover page."""
        elements = []
        elements.append(Spacer(1, 2 * inch))
        elements.append(Paragraph("🛡️ Security Assessment Report", self.styles["CoverTitle"]))
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph("VulnAssess Pro — Automated Vulnerability Analysis", self.styles["CoverSubtitle"]))
        elements.append(Spacer(1, 0.5 * inch))
        elements.append(HRFlowable(width="60%", thickness=2, color=BRAND_PRIMARY, spaceAfter=20))
        elements.append(Spacer(1, 0.3 * inch))

        scan_type = self.scan.get("scan_type", "web").upper()
        target = self.scan.get("target", "Unknown")
        date = datetime.now().strftime("%B %d, %Y at %H:%M")
        
        elements.append(Paragraph(f"<b>Target:</b> {target}", self.styles["CoverSubtitle"]))
        elements.append(Paragraph(f"<b>Scan Type:</b> {scan_type} Security Assessment", self.styles["CoverSubtitle"]))
        elements.append(Paragraph(f"<b>Date:</b> {date}", self.styles["CoverSubtitle"]))
        elements.append(Paragraph(f"<b>Classification:</b> CONFIDENTIAL", self.styles["CoverSubtitle"]))
        
        elements.append(Spacer(1, 2 * inch))
        elements.append(Paragraph(
            "This document contains confidential security assessment findings. "
            "Distribution should be limited to authorized personnel only.",
            self.styles["BodyText2"]
        ))
        return elements

    def _build_executive_summary(self):
        """Build the executive summary section."""
        elements = []
        elements.append(Paragraph("1. Executive Summary", self.styles["SectionTitle"]))
        
        score = self.scan.get("security_score", 0)
        total = self.scan.get("total_vulnerabilities", len(self.vulnerabilities))
        critical = self.scan.get("critical_count", 0)
        high = self.scan.get("high_count", 0)
        
        risk_level = "Critical" if critical > 0 else ("High" if high > 0 else "Medium")
        
        summary = (
            f"A comprehensive security assessment was performed on <b>{self.scan.get('target', 'the target')}</b>. "
            f"The assessment identified <b>{total} vulnerabilities</b> with an overall security score of "
            f"<b>{score}/100</b>. The overall risk level is classified as <b>{risk_level}</b>."
        )
        elements.append(Paragraph(summary, self.styles["BodyText2"]))
        elements.append(Spacer(1, 0.2 * inch))

        if critical > 0:
            elements.append(Paragraph(
                f"⚠️ <b>{critical} critical vulnerability/vulnerabilities</b> require immediate attention.",
                self.styles["BodyText2"]
            ))
        
        return elements

    def _build_risk_overview(self):
        """Build the risk score overview with severity table."""
        elements = []
        elements.append(Paragraph("2. Risk Score Overview", self.styles["SectionTitle"]))

        score = self.scan.get("security_score", 0)
        elements.append(Paragraph(
            f"Overall Security Score: <b>{score}/100</b>",
            self.styles["SubSection"]
        ))
        elements.append(Spacer(1, 0.2 * inch))

        # Severity distribution table
        data = [
            ["Severity", "Count", "Weight"],
            ["Critical", str(self.scan.get("critical_count", 0)), "25 pts each"],
            ["High", str(self.scan.get("high_count", 0)), "15 pts each"],
            ["Medium", str(self.scan.get("medium_count", 0)), "8 pts each"],
            ["Low", str(self.scan.get("low_count", 0)), "3 pts each"],
            ["Total", str(self.scan.get("total_vulnerabilities", 0)), ""],
        ]

        table = Table(data, colWidths=[2 * inch, 1.5 * inch, 2 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 11),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#FEE2E2")),
            ("BACKGROUND", (0, 2), (0, 2), colors.HexColor("#FFEDD5")),
            ("BACKGROUND", (0, 3), (0, 3), colors.HexColor("#FEF9C3")),
            ("BACKGROUND", (0, 4), (0, 4), colors.HexColor("#DBEAFE")),
            ("BACKGROUND", (0, 5), (-1, 5), colors.HexColor("#F3F4F6")),
            ("FONTNAME", (0, 5), (-1, 5), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("ROWHEIGHT", (0, 0), (-1, -1), 28),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))
        return elements

    def _build_vulnerability_summary(self):
        """Build the vulnerability summary table."""
        elements = []
        elements.append(Paragraph("3. Vulnerability Summary", self.styles["SectionTitle"]))

        if not self.vulnerabilities:
            elements.append(Paragraph("No vulnerabilities were identified.", self.styles["BodyText2"]))
            return elements

        data = [["#", "Vulnerability", "Severity", "Category"]]
        for i, vuln in enumerate(self.vulnerabilities, 1):
            data.append([
                str(i),
                vuln.get("name", "Unknown")[:50],
                vuln.get("severity", "info").upper(),
                vuln.get("category", "General")[:20],
            ])

        table = Table(data, colWidths=[0.4 * inch, 2.8 * inch, 1.2 * inch, 1.4 * inch])
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("ROWHEIGHT", (0, 0), (-1, -1), 22),
        ]
        # Alternate row colors
        for i in range(1, len(data)):
            if i % 2 == 0:
                style_commands.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F9FAFB")))
        
        table.setStyle(TableStyle(style_commands))
        elements.append(table)
        return elements

    def _build_detailed_findings(self):
        """Build detailed findings for each vulnerability."""
        elements = []
        elements.append(Paragraph("4. Detailed Findings", self.styles["SectionTitle"]))

        for i, vuln in enumerate(self.vulnerabilities, 1):
            sev = vuln.get("severity", "info").lower()
            sev_color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
            
            elements.append(Paragraph(
                f"4.{i} {vuln.get('name', 'Unknown')}",
                self.styles["FindingTitle"]
            ))

            # Severity badge
            elements.append(Paragraph(
                f"<font color='{sev_color.hexval()}'><b>[{sev.upper()}]</b></font> — "
                f"Category: {vuln.get('category', 'General')}",
                self.styles["BodyText2"]
            ))

            if vuln.get("description"):
                elements.append(Paragraph(f"<b>Description:</b> {vuln['description']}", self.styles["BodyText2"]))
            if vuln.get("impact"):
                elements.append(Paragraph(f"<b>Impact:</b> {vuln['impact']}", self.styles["BodyText2"]))
            if vuln.get("evidence"):
                elements.append(Paragraph(f"<b>Evidence:</b> {vuln['evidence'][:200]}", self.styles["BodyText2"]))
            if vuln.get("remediation"):
                elements.append(Paragraph(f"<b>Remediation:</b> {vuln['remediation'][:300]}", self.styles["BodyText2"]))

            elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E5E7EB"), spaceAfter=6))

        return elements

    def _build_recommendations(self):
        """Build the recommendations section."""
        elements = []
        elements.append(Paragraph("5. Recommendations", self.styles["SectionTitle"]))

        priorities = {"critical": [], "high": [], "medium": [], "low": []}
        for vuln in self.vulnerabilities:
            sev = vuln.get("severity", "info").lower()
            if sev in priorities:
                priorities[sev].append(vuln)

        if priorities["critical"]:
            elements.append(Paragraph("<b>🔴 Immediate Actions Required:</b>", self.styles["SubSection"]))
            for v in priorities["critical"]:
                elements.append(Paragraph(f"• Fix: {v.get('name', '')} — {v.get('remediation', 'See details')[:150]}", self.styles["BodyText2"]))

        if priorities["high"]:
            elements.append(Paragraph("<b>🟠 High Priority:</b>", self.styles["SubSection"]))
            for v in priorities["high"]:
                elements.append(Paragraph(f"• Fix: {v.get('name', '')} — {v.get('remediation', 'See details')[:150]}", self.styles["BodyText2"]))

        if priorities["medium"]:
            elements.append(Paragraph("<b>🟡 Medium Priority:</b>", self.styles["SubSection"]))
            for v in priorities["medium"]:
                elements.append(Paragraph(f"• Fix: {v.get('name', '')} — {v.get('remediation', 'See details')[:150]}", self.styles["BodyText2"]))

        return elements

    def _build_conclusion(self):
        """Build the conclusion section."""
        elements = []
        elements.append(Paragraph("6. Conclusion", self.styles["SectionTitle"]))

        score = self.scan.get("security_score", 0)
        total = self.scan.get("total_vulnerabilities", 0)

        elements.append(Paragraph(
            f"The security assessment of <b>{self.scan.get('target', 'the target')}</b> revealed "
            f"<b>{total} vulnerability/vulnerabilities</b> with an overall security score of <b>{score}/100</b>. "
            f"It is recommended to prioritize remediation of critical and high-severity findings first, "
            f"followed by medium and low-severity issues. A follow-up assessment should be conducted "
            f"after remediation to verify the effectiveness of the applied fixes.",
            self.styles["BodyText2"]
        ))
        elements.append(Spacer(1, 0.5 * inch))
        elements.append(Paragraph(
            f"<i>Report generated by VulnAssess Pro on {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</i>",
            self.styles["BodyText2"]
        ))
        return elements
