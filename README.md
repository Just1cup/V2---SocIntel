# SOCINTEL - V2

SOCINTEL - V2 is the multiuser foundation for the next generation of the SOCINTEL platform.

## Goals

- Support multiple concurrent analysts with isolated data contexts.
- Replace the desktop-local execution model with a client-server architecture.
- Persist cases, investigations, analysis jobs, and audit events centrally.
- Prepare the platform for teams and multi-tenant expansion.

## Initial Architecture

- `apps/api`: FastAPI application for authentication, cases, investigations, and analysis jobs.
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
- cases
- investigations
- analysis jobs
- analysis results
- search history
- audit logs

## Bootstrapping

### API

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

Default bootstrap credentials:

- email: `admin@socintel.dev`
- password: `Admin@123`

Legacy adapter path:

- `LEGACY_BACKEND_PATH=/path/to/socintel-legacy-backend`

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

### Infra

```bash
cd "infra"
docker compose up -d
```

### Full App Startup

```bash
./scripts/run_app.sh
```

To stop API, worker, and web:

```bash
./scripts/stop_app.sh
```
