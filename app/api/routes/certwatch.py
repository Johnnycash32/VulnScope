from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.certwatch import CertWatch
from app.models.user import User
from app.schemas.certwatch import CertWatchCreate, CertWatchOut, CertWatchResult
from app.services import certwatch as certwatch_service

router = APIRouter(prefix="/certwatch", tags=["certwatch"])


def _status_to_badge(status: str) -> str:
    mapping = {
        "valid": "valid",
        "expiring_soon": "expiring_soon",
        "expired": "expired",
        "unknown": "unknown",
        "error": "error",
    }
    return mapping.get(status, "unknown")


@router.get("", response_model=list[CertWatchOut])
def list_cert_watches(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[CertWatch]:
    return list(
        db.scalars(
            select(CertWatch)
            .where(CertWatch.user_id == user.id)
            .order_by(CertWatch.created_at.desc())
        ).all()
    )


@router.post("", response_model=CertWatchOut, status_code=status.HTTP_201_CREATED)
def add_cert_watch(
    payload: CertWatchCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CertWatch:
    # Check for duplicate domain for this user
    existing = db.scalar(
        select(CertWatch).where(
            CertWatch.user_id == user.id,
            CertWatch.domain == payload.domain,
        )
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Domain already being monitored",
        )

    # Fetch live certificate info
    check = certwatch_service.check_certificate(payload.domain)

    watch = CertWatch(
        user_id=user.id,
        domain=payload.domain,
        issuer=check.get("issuer"),
        expiry_date=check.get("expiry_date"),
        status=check.get("status", "unknown"),
        days_remaining=check.get("days_remaining"),
        ssl_grade=check.get("ssl_grade"),
        last_checked=datetime.now(UTC) if check.get("status") != "error" else None,
    )
    db.add(watch)
    db.commit()
    db.refresh(watch)
    return watch


@router.delete("/{watch_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_cert_watch(
    watch_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    watch = db.scalar(
        select(CertWatch).where(CertWatch.id == watch_id, CertWatch.user_id == user.id)
    )
    if watch is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate watch not found",
        )
    db.delete(watch)
    db.commit()


@router.post("/{watch_id}/check", response_model=CertWatchResult)
def recheck_cert_watch(
    watch_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CertWatchResult:
    watch = db.scalar(
        select(CertWatch).where(CertWatch.id == watch_id, CertWatch.user_id == user.id)
    )
    if watch is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate watch not found",
        )

    check = certwatch_service.check_certificate(watch.domain)
    now = datetime.now(UTC)

    watch.issuer = check.get("issuer")
    watch.expiry_date = check.get("expiry_date")
    watch.status = check.get("status", "unknown")
    watch.days_remaining = check.get("days_remaining")
    watch.ssl_grade = check.get("ssl_grade")
    watch.last_checked = now
    db.add(watch)
    db.commit()
    db.refresh(watch)

    return CertWatchResult(
        domain=watch.domain,
        issuer=watch.issuer,
        expiry_date=watch.expiry_date,
        status=watch.status,  # type: ignore[arg-type]
        days_remaining=watch.days_remaining,
        error=check.get("error"),
    )
