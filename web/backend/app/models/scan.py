"""Scan database model."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Integer, Float, Text, ForeignKey, JSON
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class ScanType(str, enum.Enum):
    WEB = "web"
    APK = "apk"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    scan_type = Column(SQLEnum(ScanType), nullable=False)
    target = Column(String, nullable=False)  # URL or APK filename
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    security_score = Column(Float, default=0.0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    scan_duration = Column(Float, nullable=True)  # seconds
    raw_results = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan {self.scan_type}:{self.target} [{self.status}]>"
