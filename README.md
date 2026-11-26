# VulnScope

VulnScope is a web-based vulnerability assessment platform (academic capstone).
This repository contains the **backend foundation plus a scanning engine**.
It implements auth, target ownership verification, and ZAP-based vulnerability
scanning backed by Celery + Redis. CVE/CVSS enrichment, reporting, and
dashboards are planned for future phases (see [What's NOT built
yet](#whats-not-built-yet)).

> **Superpower update:** VulnScope now ships with **CertWatch**, a built-in
> SSL/TLS certificate monitoring API that watches domains for expiry and
> issues alerts — giving the platform proactive certificate intelligence on top
> of its vulnerability scanning.

## Tech stack

- Python 3.11+
- FastAPI + Pydantic v2
- SQLAlchemy 2.0 (typed declarative) + Alembic migrations
- SQLite by default; PostgreSQL via `DATABASE_URL`
- Auth: OAuth2 password flow + JWT (python-jose) + bcrypt (passlib)
- Background tasks: Celery + Redis
- Scanning: OWASP ZAP (Docker sidecar, REST API)
- Config via pydantic-settings reading `.env`
- Docker + docker-compose (api, db, redis, zap, celery_worker)
- Tests: pytest; Lint: Ruff

## Project layout

```
app/
  main.py                 FastAPI app factory + routes + /health
  core/config.py          pydantic-settings config (env/.env)
  core/security.py        password hashing + JWT create/decode
  db/base.py              SQLAlchemy DeclarativeBase
  db/session.py           engine + session factory + get_db dependency
  models/user.py          User ORM model
  models/target.py        Target ORM model
  models/scan.py          Scan + Vulnerability ORM models
  schemas/user.py         User Pydantic schemas
  schemas/target.py       Target Pydantic schemas
  schemas/auth.py         Auth Pydantic schemas
  schemas/scan.py         Scan + Vulnerability Pydantic schemas
  api/deps.py             get_current_user / get_current_admin
  api/routes/auth.py      /auth/register, /auth/login
  api/routes/users.py     /users/me
  api/routes/targets.py   /targets CRUD + verify
  api/routes/scans.py     /scans/{target_id} (start), /scans/{scan_id} (result)
  api/routes/certwatch.py /certwatch/ CRUD + re-check (SSL/TLS monitoring)
  services/ownership.py   SSRF guard + ownership verification
  services/zap_client.py  OWASP ZAP REST API wrapper
  services/tasks.py       Celery task run_zap_scan
  worker.py               Celery app configuration
alembic/                  migrations (initial + scans/vulnerabilities schema)
tests/                    pytest suite
worker.py
Dockerfile
docker-compose.yml
pyproject.toml
.env.example
```

## Configuration

Copy `.env.example` to `.env` and adjust. All settings are read from the
environment (or `.env`) via `pydantic-settings`.

| Variable                     | Default                    | Notes                                                        |
| ---------------------------- | -------------------------- | ------------------------------------------------------------ |
| `DATABASE_URL`               | `sqlite:///./vulnscope.db` | SQLAlchemy URL. Postgres example in `.env.example`.          |
| `JWT_SECRET`                 | _(empty)_                  | Required in production. Empty in dev => ephemeral secret.    |
| `JWT_ALGORITHM`              | `HS256`                    | JWT signing algorithm.                                        |
| `ACCESS_TOKEN_EXPIRE_MINUTES`| `30`                       | Access token lifetime.                                        |
| `ENVIRONMENT`                | `development`              | `production` enforces `JWT_SECRET`.                          |
| `CORS_ORIGINS`               | `[]`                       | JSON array of origins. Empty = no cross-origin (safe default).|
| `REDIS_URL`                  | `redis://redis:6379/0`     | Celery broker + result backend.                               |
| `ZAP_API_URL`                | `http://zap:8080`          | OWASP ZAP sidecar API endpoint.                               |
| `ZAP_API_KEY`                | _(empty)_                  | ZAP API key, only if ZAP auth is enabled.                     |

> `CORS_ORIGINS` is a JSON array, e.g. `["http://localhost:3000"]`.

## Setup

### Windows (PowerShell)

```powershell
# From the vulnscope/ directory
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

copy .env.example .env

# Create tables via migrations
alembic upgrade head

# Run the API
uvicorn app.main:app --reload
```

Then open http://127.0.0.1:8000/docs

> If you use [uv](https://github.com/astral-sh/uv): `uv venv` then
> `uv pip install -e ".[dev]"`.

### Linux / macOS

```bash
# From the vulnscope/ directory
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env

alembic upgrade head

uvicorn app.main:app --reload
```

Then open http://127.0.0.1:8000/docs

### Docker (Windows and Linux)

```bash
# From the vulnscope/ directory
docker compose up --build
```

The stack starts 5 services: `db` (Postgres), `redis`, `zap` (OWASP ZAP),
`api` (FastAPI), and `celery_worker`.

- API: http://localhost:8000/docs
- Health: http://localhost:8000/health -> `{"status":"ok"}`
- ZAP: http://localhost:8080 (ZAP UI/API)
- Postgres data is persisted in the `pgdata` volume.

The API container runs `alembic upgrade head` before starting uvicorn, so the
schema is created automatically against Postgres.

## Running tests

```bash
# From the vulnscope/ directory
pytest
```

Tests use a temporary SQLite database and FastAPI's `TestClient`; no external
services are required. Outbound HTTP in verification tests is mocked.

## Linting

```bash
ruff check .
```

## API overview

| Method | Path                    | Auth | Description                                        |
| ------ | ----------------------- | ---- | -------------------------------------------------- |
| GET    | `/health`               | no   | Liveness probe -> `{"status":"ok"}`                |
| POST   | `/auth/register`        | no   | Create a user, returns a JWT                        |
| POST   | `/auth/login`           | no   | OAuth2 password form, returns a JWT                 |
| GET    | `/users/me`             | yes  | Current user                                        |
| POST   | `/targets`              | yes  | Create a target, returns token + verification info  |
| POST   | `/targets/{id}/verify`  | yes  | Run ownership verification                          |
| GET    | `/targets`              | yes  | List the current user's targets                     |
| POST   | `/scans/{target_id}`    | yes  | Start a ZAP scan for a verified target              |
| GET    | `/scans/{scan_id}`      | yes  | Get scan status and findings                        |
| GET    | `/certwatch/`           | yes  | List monitored domains and certificate status       |
| POST   | `/certwatch/`           | yes  | Add a domain to CertWatch monitoring                |
| DELETE | `/certwatch/{id}`       | yes  | Remove a domain from monitoring                     |
| POST   | `/certwatch/{id}/check` | yes  | Re-check a domain's certificate now                 |

## Ownership verification

- **file** (default): the platform fetches `https://<host>/<token>.txt` (with an
  `http` fallback) using `httpx` (timeout 10s, follows redirects). Verification
  succeeds only if the response is HTTP 200 **and** the body equals the token
  exactly (after stripping whitespace).
- **dns**: the interface exists but returns `not_implemented`; a real DNS TXT
  lookup of `_vulnscope.<host>` is wired in a later phase.

### SSRF protection

All outbound fetches go through `app/services/ownership.py`, which rejects
non-`http(s)` schemes and any host that resolves to private, loopback,
link-local, reserved, multicast, or otherwise non-public IP addresses **before**
fetching.

> Residual risks to address in later phases: DNS-rebinding between the guard's
> resolution and the actual connection, and redirects to internal hosts. The
> current guard resolves and validates before each fetch as required by the spec.

## Scanning

Scanning is orchestrated by Celery and performed by the OWASP ZAP sidecar:

1. `POST /scans/{target_id}` creates a `Scan` record (status `pending`) and
   enqueues the Celery task `run_zap_scan(scan_id, target.url)`.
2. The Celery worker (`celery_worker` service) runs the task:
   - sets the scan to `running`,
   - runs a ZAP spider (crawl) on the target URL and waits for completion,
   - runs a ZAP active scan and waits for completion,
   - fetches the alerts and persists each as a `Vulnerability` linked to the scan,
   - marks the scan `completed` (or `failed` on error).
3. `GET /scans/{scan_id}` returns the scan status and any vulnerabilities found.

All ZAP API calls are isolated in `app/services/zap_client.py`; the task logic
lives in `app/services/tasks.py`. ZAP runs in daemon mode
(`zap.sh -daemon -host 0.0.0.0 -port 8080 ...`) and is reachable at
`http://zap:8080` from the API and worker containers.

## Security notes

- Passwords are hashed with bcrypt; minimum length 8 enforced at the schema layer.
- JWTs are HS256 with a 30-minute expiry by default.
- No secrets are stored in source. `JWT_SECRET` must be provided via the
  environment in production; the app refuses to start without it.
- CORS is closed by default (no wildcard).
- All `/targets` routes require authentication, and users can only access their
  own targets.

## What's NOT built yet

The following are **intentionally not implemented** and are planned for future phases:

- **Dashboards / frontend** — only FastAPI's interactive `/docs` is included (no React/Vue UI)
- **Notifications** — email/Slack/webhook alerts for scan completion or critical findings

## What IS built (this phase)

- **CVE / CVSS / vulnerability data** — Full NVD enrichment: CVSS vectors, CWE IDs, vendor advisories, exploit availability, published/modified dates
- **Reporting** — PDF (WeasyPrint), HTML, and JSON exports with risk summaries, CVE links, evidence, remediation code
- **DNS verification** — Real DNS TXT record lookup for `_vulnscope.<host>` (file method also supported)
- **Admin features** — User management, global scan/target listing, system statistics, role promotion
- **Scheduled/recurring scans** — Cron-based schedules with APScheduler, pause/resume, next-run tracking
- **Scan comparison/diff** — Compare two scans for the same target: added/removed/changed vulnerabilities with risk/CVSS delta
- **CertWatch (SSL/TLS monitoring)** — Monitor domains for certificate expiry, issuer, and days remaining; add/remove watches and re-check on demand. Gives VulnScope proactive certificate intelligence alongside vulnerability scanning.