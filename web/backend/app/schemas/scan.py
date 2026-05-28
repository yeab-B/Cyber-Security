"""Scan schemas for request/response validation."""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class WebScanRequest(BaseModel):
    url: str
    scan_depth: Optional[str] = "standard"  # quick, standard, deep


class APKScanRequest(BaseModel):
    filename: str


class VulnerabilityResponse(BaseModel):
    id: str
    name: str
    severity: str
    category: Optional[str] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[str] = None
    affected_component: Optional[str] = None
    risk_explanation: Optional[str] = None
    business_impact: Optional[str] = None
    technical_impact: Optional[str] = None
    priority: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    id: str
    user_id: str
    scan_type: str
    target: str
    status: str
    security_score: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    total_vulnerabilities: int
    scan_duration: Optional[float] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    vulnerabilities: Optional[List[VulnerabilityResponse]] = []

    class Config:
        from_attributes = True


class ScanSummary(BaseModel):
    id: str
    scan_type: str
    target: str
    status: str
    security_score: float
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_scans: int
    total_vulnerabilities: int
    average_score: float
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    recent_scans: List[ScanSummary]
    severity_distribution: dict
    score_trend: List[dict]
    scan_type_distribution: dict
    vulnerability_trends: List[dict]
