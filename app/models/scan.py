from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.target import Target


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_scans_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        default="pending",
        server_default="pending",
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    target: Mapped[Target] = relationship(back_populates="scans")
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class ScheduledScan(Base):
    """Recurring scan schedule configuration."""
    __tablename__ = "scheduled_scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'paused', 'disabled')",
            name="ck_scheduled_scans_status",
        ),
        CheckConstraint(
            "cron_expression IS NOT NULL",
            name="ck_scheduled_scans_cron_required",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    cron_expression: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # e.g., "0 2 * * *" for daily at 2am
    status: Mapped[str] = mapped_column(
        String(20),
        default="active",
        server_default="active",
        nullable=False,
    )
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    target: Mapped[Target] = relationship()


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        CheckConstraint(
            "risk IN ('High', 'Medium', 'Low', 'Info')",
            name="ck_vulnerabilities_risk",
        ),
        CheckConstraint(
            "cvss_severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')",
            name="ck_vulnerabilities_cvss_severity",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    risk: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str | None] = mapped_column(String(50), nullable=True)
    description: Mapped[str | None] = mapped_column(String(4000), nullable=True)
    solution: Mapped[str | None] = mapped_column(String(4000), nullable=True)
    evidence: Mapped[str | None] = mapped_column(String(4000), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(nullable=True)
    cvss_severity: Mapped[str | None] = mapped_column(String(10), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    cvss_details: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    cwes: Mapped[str | None] = mapped_column(String(500), nullable=True)  # comma-separated
    references: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    vendor_advisories: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    exploit_available: Mapped[bool] = mapped_column(default=False, nullable=False)
    published_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_modified_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    remediation_code: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="vulnerabilities")