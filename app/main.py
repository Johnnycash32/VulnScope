from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import admin, auth, certwatch, reports, scans, scheduled_scans, targets, users
from app.core.config import get_settings


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

    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(targets.router)
    app.include_router(scans.router)
    app.include_router(scheduled_scans.router)
    app.include_router(reports.router)
    app.include_router(admin.router)
    app.include_router(certwatch.router)

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", tags=["system"])
    def root() -> dict[str, str]:
        return {"name": "VulnScope", "docs": "/docs", "health": "/health"}

    return app


app = create_app()