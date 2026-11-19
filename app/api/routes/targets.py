from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.target import Target
from app.models.user import User
from app.schemas.target import TargetCreate, TargetCreated, TargetOut
from app.services import ownership

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("", response_model=TargetCreated, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TargetCreated:
    target = Target(
        user_id=user.id,
        url=payload.url,
        verification_token=ownership.generate_token(),
        verification_method=payload.verification_method,
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    verification_url, instructions = ownership.build_verification_instructions(target)
    return TargetCreated(
        target_id=target.id,
        token=target.verification_token,
        verification_url=verification_url,
        instructions=instructions,
    )


@router.post("/{target_id}/verify", response_model=TargetOut)
def verify_target(
    target_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Target:
    target = db.scalar(
        select(Target).where(Target.id == target_id, Target.user_id == user.id)
    )
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    result = ownership.verify_ownership(target)
    if not result.ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Verification failed: {result.reason}",
        )

    target.verified_at = datetime.now(UTC)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("", response_model=list[TargetOut])
def list_targets(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Target]:
    return list(
        db.scalars(
            select(Target)
            .where(Target.user_id == user.id)
            .order_by(Target.created_at.desc())
        ).all()
    )