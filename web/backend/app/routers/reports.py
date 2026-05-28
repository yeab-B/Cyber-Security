"""Report API routes for PDF/JSON/CSV generation and downloads."""
import os
import json
import csv
import io
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.models.scan import Scan
from app.models.report import Report, ReportFormat
from app.models.audit_log import AuditLog
from app.schemas.scan import VulnerabilityResponse
from app.auth.jwt_handler import get_current_user
from app.services.report_generator import ReportGenerator

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.post("/generate/{scan_id}")
async def generate_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate a PDF security report for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = [{"name": v.name, "severity": v.severity.value, "category": v.category,
              "description": v.description, "impact": v.impact, "remediation": v.remediation,
              "evidence": v.evidence, "cve_id": v.cve_id} for v in scan.vulnerabilities]

    scan_data = {"target": scan.target, "scan_type": scan.scan_type.value,
                 "security_score": scan.security_score, "critical_count": scan.critical_count,
                 "high_count": scan.high_count, "medium_count": scan.medium_count,
                 "low_count": scan.low_count, "total_vulnerabilities": scan.total_vulnerabilities}

    generator = ReportGenerator(scan_data, vulns)
    filepath = generator.generate()

    report = Report(scan_id=scan.id, user_id=current_user.id,
                    title=f"Security Report - {scan.target}", format=ReportFormat.PDF,
                    file_path=filepath, file_size=str(os.path.getsize(filepath)))
    db.add(report)

    audit = AuditLog(user_id=current_user.id, action="REPORT_GENERATED",
                     resource_type="report", resource_id=report.id)
    db.add(audit)
    db.commit()

    return {"report_id": report.id, "message": "Report generated successfully"}


@router.get("/download/{report_id}")
async def download_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download a generated PDF report."""
    report = db.query(Report).filter(Report.id == report_id, Report.user_id == current_user.id).first()
    if not report or not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(report.file_path, media_type="application/pdf",
                        filename=f"{report.title}.pdf")


@router.get("/export/{scan_id}/json")
async def export_json(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Export scan results as JSON."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    data = {"target": scan.target, "scan_type": scan.scan_type.value,
            "security_score": scan.security_score, "total_vulnerabilities": scan.total_vulnerabilities,
            "vulnerabilities": [VulnerabilityResponse.model_validate(v).model_dump() for v in scan.vulnerabilities]}

    content = json.dumps(data, indent=2, default=str)
    return StreamingResponse(io.BytesIO(content.encode()),
                             media_type="application/json",
                             headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.json"})


@router.get("/export/{scan_id}/csv")
async def export_csv(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Export scan results as CSV."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Severity", "Category", "Description", "Impact", "Remediation"])
    for v in scan.vulnerabilities:
        writer.writerow([v.name, v.severity.value, v.category, v.description, v.impact, v.remediation])

    output.seek(0)
    return StreamingResponse(io.BytesIO(output.getvalue().encode()),
                             media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"})


@router.get("/")
async def list_reports(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """List all reports for the current user."""
    reports = db.query(Report).filter(Report.user_id == current_user.id).order_by(Report.created_at.desc()).all()
    return [{"id": r.id, "title": r.title, "format": r.format.value,
             "file_size": r.file_size, "created_at": r.created_at.isoformat()} for r in reports]
