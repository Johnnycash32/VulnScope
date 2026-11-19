from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.scan import ScheduledScan
from app.models.target import Target
from app.services.scheduler import add_scheduled_scan, remove_scheduled_scan
from app.services.scheduler import update_scheduled_scan as update_scheduler_job

router = APIRouter(prefix="/scheduled-scans", tags=["scheduled-scans"])


class ScheduledScanCreate(BaseModel):
    target_id: int
    name: str
    cron_expression: str

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: str) -> str:
        import croniter
        if not croniter.croniter.is_valid(v):
            raise ValueError("Invalid cron expression")
        return v


class ScheduledScanUpdate(BaseModel):
    name: str | None = None
    cron_expression: str | None = None
    status: str | None = None

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: str | None) -> str | None:
        if v is not None:
            import croniter
            if not croniter.croniter.is_valid(v):
                raise ValueError("Invalid cron expression")
        return v

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str | None) -> str | None:
        if v is not None and v not in {"active", "paused", "disabled"}:
            raise ValueError("Status must be one of: active, paused, disabled")
        return v


class ScheduledScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    name: str
    cron_expression: str
    status: str
    next_run_at: str | None
    last_run_at: str | None
    created_at: str
    updated_at: str
    target_url: str | None = None


@router.post("", status_code=status.HTTP_201_CREATED)
def create_scheduled_scan(
    data: ScheduledScanCreate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScheduledScanOut:
    # Verify target belongs to user
    target = db.get(Target, data.target_id)
    if not target or target.user_id != user.id:
        raise HTTPException(status_code=404, detail="Target not found")

    sched = ScheduledScan(
        target_id=data.target_id,
        name=data.name,
        cron_expression=data.cron_expression,
        status="active",
    )
    # Calculate next run
    import croniter
    cron = croniter.croniter(data.cron_expression, datetime.now(UTC))
    sched.next_run_at = cron.get_next(datetime)

    db.add(sched)
    db.commit()
    db.refresh(sched)

    add_scheduled_scan(sched)

    return ScheduledScanOut(
        id=sched.id,
        target_id=sched.target_id,
        name=sched.name,
        cron_expression=sched.cron_expression,
        status=sched.status,
        next_run_at=sched.next_run_at.isoformat() if sched.next_run_at else None,
        last_run_at=sched.last_run_at.isoformat() if sched.last_run_at else None,
        created_at=sched.created_at.isoformat(),
        updated_at=sched.updated_at.isoformat(),
        target_url=target.url,
    )


@router.get("", status_code=status.HTTP_200_OK)
def list_scheduled_scans(
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ScheduledScanOut]:
    scheds = db.scalars(
        select(ScheduledScan)
        .join(Target, Target.id == ScheduledScan.target_id)
        .where(Target.user_id == user.id)
    ).all()

    return [
        ScheduledScanOut(
            id=s.id,
            target_id=s.target_id,
            name=s.name,
            cron_expression=s.cron_expression,
            status=s.status,
            next_run_at=s.next_run_at.isoformat() if s.next_run_at else None,
            last_run_at=s.last_run_at.isoformat() if s.last_run_at else None,
            created_at=s.created_at.isoformat(),
            updated_at=s.updated_at.isoformat(),
            target_url=s.target.url if s.target else None,
        )
        for s in scheds
    ]


@router.get("/{sched_id}", status_code=status.HTTP_200_OK)
def get_scheduled_scan(
    sched_id: int,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScheduledScanOut:
    sched = db.scalar(
        select(ScheduledScan)
        .join(Target, Target.id == ScheduledScan.target_id)
        .where(ScheduledScan.id == sched_id, Target.user_id == user.id)
    )
    if not sched:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    return ScheduledScanOut(
        id=sched.id,
        target_id=sched.target_id,
        name=sched.name,
        cron_expression=sched.cron_expression,
        status=sched.status,
        next_run_at=sched.next_run_at.isoformat() if sched.next_run_at else None,
        last_run_at=sched.last_run_at.isoformat() if sched.last_run_at else None,
        created_at=sched.created_at.isoformat(),
        updated_at=sched.updated_at.isoformat(),
        target_url=sched.target.url if sched.target else None,
    )


@router.patch("/{sched_id}", status_code=status.HTTP_200_OK)
def update_scheduled_scan(
    sched_id: int,
    data: ScheduledScanUpdate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScheduledScanOut:
    sched = db.scalar(
        select(ScheduledScan)
        .join(Target, Target.id == ScheduledScan.target_id)
        .where(ScheduledScan.id == sched_id, Target.user_id == user.id)
    )
    if not sched:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    if data.name is not None:
        sched.name = data.name
    if data.cron_expression is not None:
        sched.cron_expression = data.cron_expression
        # Recalculate next run
        import croniter
        cron = croniter.croniter(data.cron_expression, datetime.now(UTC))
        sched.next_run_at = cron.get_next(datetime)
    if data.status is not None:
        sched.status = data.status

    db.add(sched)
    db.commit()
    db.refresh(sched)

    update_scheduler_job(sched)

    return ScheduledScanOut(
        id=sched.id,
        target_id=sched.target_id,
        name=sched.name,
        cron_expression=sched.cron_expression,
        status=sched.status,
        next_run_at=sched.next_run_at.isoformat() if sched.next_run_at else None,
        last_run_at=sched.last_run_at.isoformat() if sched.last_run_at else None,
        created_at=sched.created_at.isoformat(),
        updated_at=sched.updated_at.isoformat(),
        target_url=sched.target.url if sched.target else None,
    )


@router.delete("/{sched_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scheduled_scan(
    sched_id: int,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    sched = db.scalar(
        select(ScheduledScan)
        .join(Target, Target.id == ScheduledScan.target_id)
        .where(ScheduledScan.id == sched_id, Target.user_id == user.id)
    )
    if not sched:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    remove_scheduled_scan(sched_id)
    db.delete(sched)
    db.commit()