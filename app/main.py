from __future__ import annotations

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import (
    get_current_user_from_cookie,
    get_current_user_optional,
)
from app.api.routes import admin, auth, certwatch, reports, scans, scheduled_scans, targets, users
from app.core.config import get_settings
from app.db.session import get_db
from app.models.scan import Scan, Vulnerability
from app.models.target import Target
from app.models.user import User

templates = Jinja2Templates(directory="app/templates")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="VulnScope API",
        version="0.1.0",
        description="VulnScope - vulnerability assessment platform (backend foundation).",
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.mount("/static", StaticFiles(directory="app/static"), name="static")

    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(targets.router)
    app.include_router(scans.router)
    app.include_router(scheduled_scans.router)
    app.include_router(reports.router)
    app.include_router(admin.router)
    app.include_router(certwatch.router)

    # ------------------------------------------------------------------
    # HTML routes (server-rendered)
    # ------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def root(
        request: Request,
        user: User | None = Depends(get_current_user_optional),
    ) -> RedirectResponse:
        if user:
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    @app.get("/auth/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("login.html", {"request": request})

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(
        request: Request,
        user: User = Depends(get_current_user_from_cookie),
        db: Session = Depends(get_db),
    ):
        total_scans = db.scalar(
            select(func.count(Scan.id))
            .join(Target, Target.id == Scan.target_id)
            .where(Target.user_id == user.id)
        ) or 0

        sev_rows = db.execute(
            select(Vulnerability.cvss_severity, func.count(Vulnerability.id))
            .join(Scan, Scan.id == Vulnerability.scan_id)
            .join(Target, Target.id == Scan.target_id)
            .where(Target.user_id == user.id)
            .group_by(Vulnerability.cvss_severity)
        ).all()

        sev_map = {row[0] or "Info": row[1] for row in sev_rows}
        critical_count = sev_map.get("Critical", 0)
        high_count = sev_map.get("High", 0)
        medium_count = sev_map.get("Medium", 0)
        low_count = sev_map.get("Low", 0)
        info_count = sev_map.get("Info", 0)
        issues_found = critical_count + high_count + medium_count + low_count + info_count
        total_vulns = issues_found or 1
        security_score = max(0, round(100 - (critical_count * 10 + high_count * 5), 1))

        recent_scans = db.execute(
            select(Scan)
            .options(selectinload(Scan.vulnerabilities))
            .join(Target, Target.id == Scan.target_id)
            .where(Target.user_id == user.id)
            .order_by(Scan.created_at.desc())
            .limit(5)
        ).scalars().all()

        recent_scan_list = [
            {
                "id": s.id,
                "target_url": s.target.url if s.target else "",
                "status": s.status,
                "updated_at": s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else "",
            }
            for s in recent_scans
        ]

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "user": user,
                "total_scans": total_scans,
                "issues_found": issues_found,
                "security_score": security_score,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "info_count": info_count,
                "total_vulns": total_vulns,
                "critical_pct": round(critical_count / total_vulns * 100, 1),
                "high_pct": round(high_count / total_vulns * 100, 1),
                "medium_pct": round(medium_count / total_vulns * 100, 1),
                "low_pct": round(low_count / total_vulns * 100, 1),
                "info_pct": round(info_count / total_vulns * 100, 1),
                "recent_scans": recent_scan_list,
            },
        )

    @app.get("/certwatch", response_class=HTMLResponse)
    async def certwatch_page(
        request: Request,
        user: User = Depends(get_current_user_from_cookie),
    ):
        return templates.TemplateResponse("certwatch.html", {"request": request, "user": user})

    # ------------------------------------------------------------------
    # System routes
    # ------------------------------------------------------------------

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
