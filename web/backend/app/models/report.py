"""Report database model."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, ForeignKey
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class ReportFormat(str, enum.Enum):
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"


class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    title = Column(String, nullable=False)
    format = Column(SQLEnum(ReportFormat), default=ReportFormat.PDF)
    file_path = Column(String, nullable=True)
    file_size = Column(String, nullable=True)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="reports")
    user = relationship("User", back_populates="reports")

    def __repr__(self):
        return f"<Report {self.title} [{self.format}]>"
