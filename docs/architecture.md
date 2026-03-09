# Architecture Notes

## Target Shape

- Web frontend for authenticated analysts
- Stateless API for business rules and authorization
- PostgreSQL for central persistence
- Redis and worker queue for async execution
- Analysis workers for provider integrations

## Isolation Model

- `tenant_id`: organization or department boundary
- `team_id`: collaboration boundary inside the tenant
- `owner_user_id`: ownership boundary for private resources

## Core Entities

- tenants
- users
- teams
- memberships
- cases
- investigations
- analysis_jobs
- analysis_results
- search_history
- audit_logs

## Persistence Rules

- Every business entity is tenant-scoped.
- `owner_user_id` defines private ownership.
- `team_id` is optional and enables collaboration inside the tenant.
- Cases and investigations use soft delete so auditability is preserved.
- Analysis jobs and results are immutable enough to preserve traceability.

## Migration Strategy

1. Extract analysis core from the legacy CLI.
2. Expose the core through FastAPI services.
3. Move expensive provider calls to workers.
4. Replace local browser storage with PostgreSQL-backed persistence.
