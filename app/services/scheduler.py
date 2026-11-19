from __future__ import annotations

from datetime import UTC, datetime

import croniter
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.scan import Scan, ScheduledScan
from app.models.target import Target  # noqa: F401
from app.services.tasks import run_zap_scan

_scheduler: BackgroundScheduler | None = None


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(timezone=UTC)
        _scheduler.start()
        _schedule_existing_jobs()
    return _scheduler


def _schedule_existing_jobs() -> None:
    """Load active scheduled scans from DB and schedule them."""
    db = SessionLocal()
    try:
        scheduled_scans = db.scalars(
            select(ScheduledScan).where(ScheduledScan.status == "active")
        ).all()
        for sched in scheduled_scans:
            _add_job(sched)
    finally:
        db.close()


def _add_job(sched: ScheduledScan) -> None:
    scheduler = get_scheduler()
    job_id = f"scheduled_scan_{sched.id}"

    # Remove existing job if any
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    try:
        trigger = CronTrigger.from_crontab(sched.cron_expression, timezone=UTC)
    except Exception:
        # Invalid cron expression, disable the schedule
        db = SessionLocal()
        try:
            sched.status = "disabled"
            db.add(sched)
            db.commit()
        finally:
            db.close()
        return

    def run_scheduled_scan() -> None:
        db = SessionLocal()
        try:
            # Re-fetch the schedule to check status
            sched_refreshed = db.get(ScheduledScan, sched.id)
            if not sched_refreshed or sched_refreshed.status != "active":
                return

            # Create a new scan record
            scan = Scan(target_id=sched_refreshed.target_id, status="pending")
            db.add(scan)
            db.commit()

            # Update schedule timestamps
            sched_refreshed.last_run_at = datetime.now(UTC)
            # Calculate next run
            cron = croniter.croniter(sched_refreshed.cron_expression, datetime.now(UTC))
            sched_refreshed.next_run_at = cron.get_next(datetime)
            db.add(sched_refreshed)
            db.commit()

            # Enqueue the scan task
            run_zap_scan.delay(scan.id, sched_refreshed.target.url)

        except Exception:  # noqa: BLE001
            db.rollback()
        finally:
            db.close()

    scheduler.add_job(
        run_scheduled_scan,
        trigger=trigger,
        id=job_id,
        name=f"Scheduled scan: {sched.name}",
        replace_existing=True,
    )


def add_scheduled_scan(sched: ScheduledScan) -> None:
    """Add a new scheduled scan job."""
    if sched.status == "active":
        _add_job(sched)


def remove_scheduled_scan(sched_id: int) -> None:
    """Remove a scheduled scan job."""
    scheduler = get_scheduler()
    job_id = f"scheduled_scan_{sched_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)


def update_scheduled_scan(sched: ScheduledScan) -> None:
    """Update a scheduled scan job (re-schedule)."""
    remove_scheduled_scan(sched.id)
    if sched.status == "active":
        _add_job(sched)


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown()
        _scheduler = None