from __future__ import annotations

from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "vulnscope",
    broker=settings.redis_url,
    backend="cache+memory://",
    include=["app.services.tasks"],
)

celery_app.conf.task_default_queue = "vulnscope"
celery_app.conf.task_track_started = True
celery_app.conf.task_ignore_result = True
celery_app.conf.result_expires = 3600