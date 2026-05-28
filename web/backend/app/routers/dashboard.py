"""Dashboard API routes providing analytics and statistics."""
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models.user import User
from app.models.scan import Scan, ScanStatus
from app.schemas.scan import DashboardStats, ScanSummary
from app.auth.jwt_handler import get_current_user

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get comprehensive dashboard statistics."""
    uid = current_user.id
    completed = db.query(Scan).filter(Scan.user_id == uid, Scan.status == ScanStatus.COMPLETED)

    total_scans = completed.count()
    total_vulns = completed.with_entities(func.sum(Scan.total_vulnerabilities)).scalar() or 0
    avg_score = completed.with_entities(func.avg(Scan.security_score)).scalar() or 0
    critical = int(completed.with_entities(func.sum(Scan.critical_count)).scalar() or 0)
    high = int(completed.with_entities(func.sum(Scan.high_count)).scalar() or 0)
    medium = int(completed.with_entities(func.sum(Scan.medium_count)).scalar() or 0)
    low = int(completed.with_entities(func.sum(Scan.low_count)).scalar() or 0)

    recent = db.query(Scan).filter(Scan.user_id == uid).order_by(Scan.created_at.desc()).limit(10).all()
    recent_scans = [ScanSummary.model_validate(s) for s in recent]

    trend_scans = completed.order_by(Scan.created_at.asc()).limit(20).all()
    score_trend = [{"date": s.created_at.strftime("%Y-%m-%d"), "score": s.security_score, "target": s.target[:30]} for s in trend_scans]

    web_count = db.query(Scan).filter(Scan.user_id == uid, Scan.scan_type == "web").count()
    apk_count = db.query(Scan).filter(Scan.user_id == uid, Scan.scan_type == "apk").count()

    vuln_trends = []
    for i in range(6, -1, -1):
        day = datetime.utcnow() - timedelta(days=i)
        ds = day.replace(hour=0, minute=0, second=0, microsecond=0)
        de = day.replace(hour=23, minute=59, second=59)
        day_scans = completed.filter(Scan.created_at >= ds, Scan.created_at <= de).all()
        vuln_trends.append({
            "date": day.strftime("%b %d"),
            "critical": sum(s.critical_count for s in day_scans),
            "high": sum(s.high_count for s in day_scans),
            "medium": sum(s.medium_count for s in day_scans),
            "low": sum(s.low_count for s in day_scans),
        })

    return DashboardStats(
        total_scans=total_scans, total_vulnerabilities=int(total_vulns),
        average_score=round(float(avg_score), 1), critical_issues=critical,
        high_issues=high, medium_issues=medium, low_issues=low,
        recent_scans=recent_scans,
        severity_distribution={"critical": critical, "high": high, "medium": medium, "low": low},
        score_trend=score_trend,
        scan_type_distribution={"web": web_count, "apk": apk_count},
        vulnerability_trends=vuln_trends,
    )
