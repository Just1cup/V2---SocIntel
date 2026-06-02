# SOCINTEL - V2

SOCINTEL - V2 is the multiuser foundation for the next generation of the SOCINTEL platform.

## Goals

- Support multiple concurrent analysts with isolated data contexts.
- Replace the desktop-local execution model with a client-server architecture.
- Persist analysis jobs, analysis results, search history, and audit events centrally.
- Prepare the platform for teams and multi-tenant expansion.

## Initial Architecture

- `apps/api`: FastAPI application for authentication, user management, MITRE catalog access, and analysis jobs.
- `apps/worker`: background worker process for async analysis execution.
- `apps/web`: web frontend entrypoint.
- `packages/shared`: shared contracts and documentation placeholders.
- `infra`: local Docker Compose stack for PostgreSQL and Redis.
- `docs`: architecture notes and roadmap.

## Planned Stack

- Frontend: React + Vite
- API: FastAPI
- Database: PostgreSQL
- Cache/Queue: Redis
- Worker: Celery
- Containers: Docker Compose

## Status

This directory currently contains the initial scaffold only.

## Domain Progress

The current scaffold already includes tenant-aware domain models for:

- tenants
- users
- teams and memberships
- analysis jobs
- analysis results
- search history
- audit logs

## Bootstrapping

### API

Create a local `.env` from `.env.example` and replace every placeholder secret with a generated value before starting the API. The API refuses to start with an empty, short, or default `JWT_SECRET`.

```bash
cd "apps/api"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Migrations

```bash
cd "apps/api"
source .venv/bin/activate
alembic upgrade head
```

### Seed

```bash
cd "apps/api"
source .venv/bin/activate
PYTHONPATH=. python scripts/seed.py
```

### Worker

```bash
cd "apps/api"
source .venv/bin/activate
PYTHONPATH=. celery -A app.workers.celery_app:celery_app worker --loglevel=info
```

Bootstrap admin credentials:

- email: `admin@socintel.dev`
- password: set `SOCINTEL_BOOTSTRAP_ADMIN_PASSWORD` in your local `.env` before running `scripts/seed.py`

Legacy adapter path:

- Default in-repo location: `backend/orchestrator.py`
- Override with `LEGACY_BACKEND_PATH=/path/to/socintel-legacy-backend`

TAXII threat intelligence feed:

- Default source: MITRE ATT&CK TAXII 2.1 at `https://attack-taxii.mitre.org/api/v21`
- API prefix: `/api/v1/threat-feeds/taxii`
- Object queries require at least one filter (`type`, `id`, or `added_after`) to avoid pulling large TAXII collections and to respect MITRE's public rate limits.
- Optional settings: `TAXII_REQUEST_TIMEOUT_SECONDS`, `TAXII_CACHE_TTL_SECONDS`, `TAXII_MITRE_BASE_URL`, `TAXII_MITRE_API_ROOT`

### Web

```bash
cd "apps/web"
npm install
npm run dev
```

Optional frontend API target:

```bash
VITE_API_BASE_URL=http://localhost:8000/api/v1 npm run dev
```

Optional Vite hardening overrides:

```bash
VITE_DEV_HOST=127.0.0.1
VITE_DEV_PORT=5173
VITE_ALLOWED_HOSTS=localhost,127.0.0.1
```

### Infra

```bash
cd "infra"
set -a && source ../.env && set +a
docker compose up -d
```

PostgreSQL and Redis are bound to `127.0.0.1` for local development. Redis requires `REDIS_PASSWORD`; PostgreSQL requires `POSTGRES_PASSWORD`.

### Full App Startup

```bash
./scripts/run_app.sh
```

The launcher starts Vite bound to `127.0.0.1` by default. To expose it intentionally on another interface, set:

```bash
SOCINTEL_WEB_HOST=0.0.0.0 ./scripts/run_app.sh
```

To stop API, worker, web, PostgreSQL, and Redis:

```bash
./scripts/stop_app.sh
```

To stop only API, worker, and web while keeping Docker services running:

```bash
./scripts/stop_app.sh --keep-docker
```

To also delete local Docker volumes, including database data:

```bash
./scripts/stop_app.sh --volumes
```
