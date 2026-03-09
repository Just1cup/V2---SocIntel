# Data Model

## Isolation Axes

- `tenant_id`: hard boundary for data separation
- `team_id`: collaboration boundary inside a tenant
- `owner_user_id`: individual ownership

## Main Tables

### tenants

- identity and top-level organization boundary

### users

- analyst identity
- role and status
- belongs to one tenant

### teams

- optional collaboration group within a tenant

### team_memberships

- join table between users and teams
- scoped by tenant

### cases

- top-level investigation container
- supports `private` or `team` visibility

### investigations

- scoped workstream inside a case

### analysis_jobs

- async execution request for IOC enrichment
- linked to case and investigation when present

### analysis_results

- normalized snapshot of the outcome of one job

### search_history

- user-facing search trail

### audit_logs

- immutable action records for access and change tracking
