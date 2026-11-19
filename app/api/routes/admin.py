from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import get_current_admin
from app.db.session import get_db
from app.models.scan import Scan, ScheduledScan, Vulnerability
from app.models.target import Target
from app.models.user import User

router = APIRouter(prefix="/admin", tags=["admin"])


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: str
    role: str
    created_at: datetime
    target_count: int
    scan_count: int


class UserUpdate(BaseModel):
    role: str | None = None
    full_name: str | None = None


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    target_url: str
    target_owner_email: str
    status: str
    created_at: datetime
    completed_at: datetime | None
    vulnerability_count: int
    high_risk_count: int


class SystemStats(BaseModel):
    total_users: int
    total_targets: int
    total_scans: int
    total_scheduled_scans: int
    active_scheduled_scans: int
    scans_last_24h: int
    scans_last_7d: int
    vulnerabilities_total: int
    high_risk_vulns: int


@router.get("/stats", response_model=SystemStats)
def get_system_stats(
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> SystemStats:
    """Get system-wide statistics."""
    now = datetime.now(UTC)
    day_ago = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = day_ago - timedelta(days=7)

    total_users = db.scalar(select(func.count(User.id))) or 0
    total_targets = db.scalar(select(func.count(Target.id))) or 0
    total_scans = db.scalar(select(func.count(Scan.id))) or 0
    total_scheduled = db.scalar(select(func.count(ScheduledScan.id))) or 0
    active_scheduled = db.scalar(
        select(func.count(ScheduledScan.id)).where(ScheduledScan.status == "active")
    ) or 0

    scans_last_24h = db.scalar(
        select(func.count(Scan.id)).where(Scan.created_at >= day_ago)
    ) or 0
    scans_last_7d = db.scalar(
        select(func.count(Scan.id)).where(Scan.created_at >= week_ago)
    ) or 0

    vulns_total = db.scalar(select(func.count(Scan.id)).select_from(Scan.__table__))  # placeholder
    # Get vulnerability stats
    vulns_total = db.scalar(select(func.count(Vulnerability.id))) or 0
    high_risk_vulns = db.scalar(
        select(func.count(Vulnerability.id)).where(Vulnerability.risk == "High")
    ) or 0

    return SystemStats(
        total_users=total_users,
        total_targets=total_targets,
        total_scans=total_scans,
        total_scheduled_scans=total_scheduled,
        active_scheduled_scans=active_scheduled,
        scans_last_24h=scans_last_24h,
        scans_last_7d=scans_last_7d,
        vulnerabilities_total=vulns_total,
        high_risk_vulns=high_risk_vulns,
    )


@router.get("/users", response_model=list[UserOut])
def list_users(
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> list[UserOut]:
    """List all users with their target/scan counts."""
    users = db.scalars(
        select(User)
        .offset(skip)
        .limit(limit)
        .order_by(desc(User.created_at))
    ).all()

    result = []
    for user in users:
        target_count = db.scalar(
            select(func.count(Target.id)).where(Target.user_id == user.id)
        ) or 0
        scan_count = db.scalar(
            select(func.count(Scan.id)).join(Target).where(Target.user_id == user.id)
        ) or 0

        result.append(UserOut(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            created_at=user.created_at,
            target_count=target_count,
            scan_count=scan_count,
        ))
    return result


@router.get("/users/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> UserOut:
    """Get user details with counts."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    target_count = db.scalar(
        select(func.count(Target.id)).where(Target.user_id == user.id)
    ) or 0
    scan_count = db.scalar(
        select(func.count(Scan.id)).join(Target).where(Target.user_id == user.id)
    ) or 0

    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        created_at=user.created_at,
        target_count=target_count,
        scan_count=scan_count,
    )


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    data: UserUpdate,
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> UserOut:
    """Update user (role, name)."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if data.role is not None:
        if data.role not in {"user", "admin"}:
            raise HTTPException(status_code=400, detail="Role must be 'user' or 'admin'")
        user.role = data.role
    if data.full_name is not None:
        user.full_name = data.full_name

    db.add(user)
    db.commit()
    db.refresh(user)

    target_count = db.scalar(
        select(func.count(Target.id)).where(Target.user_id == user.id)
    ) or 0
    scan_count = db.scalar(
        select(func.count(Scan.id)).join(Target).where(Target.user_id == user.id)
    ) or 0

    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        created_at=user.created_at,
        target_count=target_count,
        scan_count=scan_count,
    )


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> None:
    """Delete a user and all their data."""
    if admin.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()


@router.get("/scans", response_model=list[ScanSummary])
def list_all_scans(
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    status: str | None = Query(None, pattern="^(pending|running|completed|failed)$"),
) -> list[ScanSummary]:
    """List all scans across all users."""
    query = (
        select(Scan)
        .join(Target, Target.id == Scan.target_id)
        .join(User, User.id == Target.user_id)
        .options(selectinload(Scan.vulnerabilities))
        .order_by(desc(Scan.created_at))
        .offset(skip)
        .limit(limit)
    )
    if status:
        query = query.where(Scan.status == status)

    scans = db.scalars(query).all()

    return [
        ScanSummary(
            id=s.id,
            target_id=s.target_id,
            target_url=s.target.url if s.target else "",
            target_owner_email=s.target.user.email if s.target and s.target.user else "",
            status=s.status,
            created_at=s.created_at,
            completed_at=s.completed_at,
            vulnerability_count=len(s.vulnerabilities),
            high_risk_count=sum(1 for v in s.vulnerabilities if v.risk == "High"),
        )
        for s in scans
    ]


@router.get("/targets", response_model=list[dict[str, Any]])
def list_all_targets(
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    verified_only: bool = Query(False),
) -> list[dict[str, Any]]:
    """List all targets across all users."""
    query = (
        select(Target)
        .join(User, User.id == Target.user_id)
        .order_by(desc(Target.created_at))
        .offset(skip)
        .limit(limit)
    )
    if verified_only:
        query = query.where(Target.verified_at.is_not(None))

    targets = db.scalars(query).all()

    return [
        {
            "id": t.id,
            "user_id": t.user_id,
            "user_email": t.user.email if t.user else "",
            "url": t.url,
            "verification_method": t.verification_method,
            "verified_at": t.verified_at.isoformat() if t.verified_at else None,
            "created_at": t.created_at.isoformat(),
            "scan_count": len(t.scans),
        }
        for t in targets
    ]