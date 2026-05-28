"""Admin API routes for system management."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models.user import User, UserRole
from app.models.scan import Scan, ScanStatus
from app.models.audit_log import AuditLog
from app.models.report import Report
from app.schemas.user import UserResponse
from app.auth.jwt_handler import get_current_admin

router = APIRouter(prefix="/api/admin", tags=["Admin"])


@router.get("/users")
async def list_users(current_user: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    """List all users (admin only)."""
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [UserResponse.model_validate(u) for u in users]


@router.put("/users/{user_id}/role")
async def update_user_role(
    user_id: str, role: str,
    current_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Update a user's role."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        user.role = UserRole(role)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid role")
    db.commit()
    return {"message": f"User role updated to {role}"}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Delete a user account."""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"message": "User deleted"}


@router.get("/stats")
async def system_stats(current_user: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    """Get system-wide statistics."""
    return {
        "total_users": db.query(User).count(),
        "total_scans": db.query(Scan).count(),
        "completed_scans": db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED).count(),
        "total_reports": db.query(Report).count(),
        "total_audit_logs": db.query(AuditLog).count(),
    }


@router.get("/audit-logs")
async def get_audit_logs(
    limit: int = 50,
    current_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Get recent audit logs."""
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return [{"id": l.id, "user_id": l.user_id, "action": l.action,
             "resource_type": l.resource_type, "created_at": l.created_at.isoformat()} for l in logs]
