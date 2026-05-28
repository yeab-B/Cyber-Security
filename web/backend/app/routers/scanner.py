"""Scanner API routes for web and APK vulnerability scanning."""
import os
import time
import logging
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.vulnerability import Vulnerability, Severity
from app.models.audit_log import AuditLog
from app.schemas.scan import WebScanRequest, ScanResponse, ScanSummary
from app.auth.jwt_handler import get_current_user
from app.services.web_scanner import WebScanner
from app.services.apk_scanner import APKScanner
from app.services.risk_engine import RiskEngine
from app.services.recommendations import RecommendationsEngine
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["Scanning"])


@router.post("/web", response_model=ScanResponse)
async def scan_website(
    request: WebScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Perform a website vulnerability scan."""
    # Create scan record
    scan = Scan(
        user_id=current_user.id,
        scan_type=ScanType.WEB,
        target=request.url,
        status=ScanStatus.RUNNING,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        # Execute scan
        scanner = WebScanner(request.url)
        results = scanner.scan()

        if "error" in results and not results.get("vulnerabilities"):
            scan.status = ScanStatus.FAILED
            scan.error_message = results["error"]
            db.commit()
            raise HTTPException(status_code=400, detail=f"Scan failed: {results['error']}")

        # Enrich with recommendations
        vulns = RecommendationsEngine.enrich_vulnerabilities(results["vulnerabilities"])

        # Calculate risk score
        risk = RiskEngine.calculate_score(vulns)

        # Update scan record
        scan.status = ScanStatus.COMPLETED
        scan.security_score = risk["security_score"]
        scan.critical_count = risk["critical_count"]
        scan.high_count = risk["high_count"]
        scan.medium_count = risk["medium_count"]
        scan.low_count = risk["low_count"]
        scan.info_count = risk["info_count"]
        scan.total_vulnerabilities = risk["total_vulnerabilities"]
        scan.scan_duration = results.get("scan_duration", 0)
        scan.completed_at = datetime.utcnow()
        scan.raw_results = {
            "server": results.get("server"),
            "technologies": results.get("technologies", []),
            "status_code": results.get("status_code"),
        }

        # Save vulnerabilities
        for v in vulns:
            vuln = Vulnerability(
                scan_id=scan.id,
                name=v.get("name", "Unknown"),
                severity=Severity(v.get("severity", "info").lower()),
                category=v.get("category"),
                description=v.get("description"),
                impact=v.get("impact"),
                remediation=v.get("remediation"),
                evidence=v.get("evidence"),
                cve_id=v.get("cve_id"),
                risk_explanation=v.get("risk_explanation"),
                business_impact=v.get("business_impact"),
                technical_impact=v.get("technical_impact"),
                priority=v.get("priority"),
            )
            db.add(vuln)

        # Audit log
        audit = AuditLog(
            user_id=current_user.id,
            action="WEB_SCAN_COMPLETED",
            resource_type="scan",
            resource_id=scan.id,
            details={"target": request.url, "vulnerabilities": risk["total_vulnerabilities"]},
        )
        db.add(audit)
        db.commit()
        db.refresh(scan)

        return ScanResponse.model_validate(scan)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan error: {e}")
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        db.commit()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/apk", response_model=ScanResponse)
async def scan_apk(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload and analyze an Android APK file."""
    # Validate file
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are accepted")

    # Save uploaded file
    filepath = os.path.join(settings.UPLOAD_DIR, f"{current_user.id}_{file.filename}")
    with open(filepath, "wb") as f:
        content = await file.read()
        if len(content) > settings.MAX_UPLOAD_SIZE:
            raise HTTPException(status_code=400, detail="File size exceeds 100MB limit")
        f.write(content)

    # Create scan record
    scan = Scan(
        user_id=current_user.id,
        scan_type=ScanType.APK,
        target=file.filename,
        status=ScanStatus.RUNNING,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        # Execute APK scan
        scanner = APKScanner(filepath)
        results = scanner.scan()

        # Enrich with recommendations
        vulns = RecommendationsEngine.enrich_vulnerabilities(results["vulnerabilities"])

        # Calculate risk score
        risk = RiskEngine.calculate_score(vulns)

        # Update scan record
        scan.status = ScanStatus.COMPLETED
        scan.security_score = risk["security_score"]
        scan.critical_count = risk["critical_count"]
        scan.high_count = risk["high_count"]
        scan.medium_count = risk["medium_count"]
        scan.low_count = risk["low_count"]
        scan.info_count = risk["info_count"]
        scan.total_vulnerabilities = risk["total_vulnerabilities"]
        scan.scan_duration = results.get("scan_duration", 0)
        scan.completed_at = datetime.utcnow()
        scan.raw_results = {
            "permissions": results.get("permissions", []),
            "file_count": results.get("file_count", 0),
        }

        # Save vulnerabilities
        for v in vulns:
            vuln = Vulnerability(
                scan_id=scan.id,
                name=v.get("name", "Unknown"),
                severity=Severity(v.get("severity", "info").lower()),
                category=v.get("category"),
                description=v.get("description"),
                impact=v.get("impact"),
                remediation=v.get("remediation"),
                evidence=v.get("evidence"),
                cve_id=v.get("cve_id"),
                risk_explanation=v.get("risk_explanation"),
                business_impact=v.get("business_impact"),
                technical_impact=v.get("technical_impact"),
                priority=v.get("priority"),
            )
            db.add(vuln)

        # Audit log
        audit = AuditLog(
            user_id=current_user.id,
            action="APK_SCAN_COMPLETED",
            resource_type="scan",
            resource_id=scan.id,
            details={"target": file.filename, "vulnerabilities": risk["total_vulnerabilities"]},
        )
        db.add(audit)
        db.commit()
        db.refresh(scan)

        return ScanResponse.model_validate(scan)

    except Exception as e:
        logger.error(f"APK scan error: {e}")
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        db.commit()
        raise HTTPException(status_code=500, detail=f"APK scan failed: {str(e)}")
    finally:
        # Cleanup uploaded file
        try:
            os.remove(filepath)
        except Exception:
            pass


@router.get("/", response_model=List[ScanSummary])
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    scan_type: str = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List user's scan history."""
    query = db.query(Scan).filter(Scan.user_id == current_user.id)
    if scan_type:
        query = query.filter(Scan.scan_type == scan_type)
    scans = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    return [ScanSummary.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed scan results by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse.model_validate(scan)


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a scan and its results."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully"}
