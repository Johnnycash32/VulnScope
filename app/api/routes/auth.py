from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password, verify_password
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import RegisterRequest, Token
from app.services.oauth import oauth

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> Token:
    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role="user",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return Token(access_token=create_access_token(user.id), token_type="bearer")


@router.get("/google")
async def google_login(request: Request):
    redirect_uri = "http://localhost:8000/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    token = await oauth.google.authorize_access_token(request)
    user_info = token.get("userinfo")
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to fetch user info from Google",
        )

    email = user_info.get("email")
    google_id = user_info.get("sub")
    name = user_info.get("name") or email or "Google User"

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google account has no email",
        )

    user = db.scalar(select(User).where(User.email == email))

    if user is None:
        random_password = secrets.token_urlsafe(32)
        user = User(
            email=email,
            hashed_password=hash_password(random_password),
            full_name=name,
            google_id=google_id,
            role="user",
        )
        db.add(user)
    else:
        user.google_id = google_id

    db.commit()
    db.refresh(user)

    access_token = create_access_token(user.id)
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=2592000,
        samesite="lax",
    )
    return response


@router.post("/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> Token:
    user = db.scalar(select(User).where(User.email == form_data.username))
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return Token(access_token=create_access_token(user.id), token_type="bearer")