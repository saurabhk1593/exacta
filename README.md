# GoAuth

> Lightweight, self-hosted auth service for teams who find Keycloak too heavy and Auth0 too expensive.

[![Go 1.22](https://img.shields.io/badge/Go-1.22-00ADD8?logo=go)](https://go.dev/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](docker-compose.yml)

GoAuth is a production-grade, multi-tenant authentication and authorization service built in Go. It gives your SaaS product JWT-based auth, RBAC, refresh token rotation with theft detection, audit logging, and a built-in rate limiter — deployable in under 5 minutes with a single Docker command.

---

## Why GoAuth

| Problem | GoAuth's answer |
|---|---|
| Keycloak is a 500MB JVM behemoth | 12MB Go binary, runs in `scratch` container |
| Auth0/Clerk costs $240/mo for 1000 MAUs | Self-hosted, zero per-user cost |
| Supabase Auth is tightly coupled to Supabase | Drop-in REST service, works with any stack |
| Rolling your own is dangerous | Battle-tested patterns: Argon2id, token family tracking, Lua-atomic rate limiting |

---

## Features

### Authentication
- **Register / Login / Logout** — standard email + password flows
- **JWT access tokens** — 15m expiry, signed HS256, carries roles + permissions in claims
- **Refresh token rotation** — every refresh issues a new token and invalidates the old one
- **Token family tracking** — detects stolen/replayed refresh tokens; revokes the entire family on reuse
- **Logout-all** — revokes all active sessions for a user in one call
- **Token blacklist** — Redis-backed, covers the access token TTL window post-logout

### Security
- **Argon2id password hashing** — OWASP-recommended, memory-hard (64MB, 3 iterations, 2 threads)
- **Sliding window rate limiting** — per-IP and per-user, Lua-script atomic Redis sorted set
- **Fail-open on Redis errors** — rate limiter never blocks legitimate traffic due to Redis downtime
- **Constant-time password comparison** — prevents timing attacks

### Multi-tenancy
- **Shared database, tenant-scoped rows** — every query enforces `tenant_id`
- **Email uniqueness per tenant** — `UNIQUE(tenant_id, email)` constraint
- **Per-tenant roles** — roles are tenant-scoped, not global
- **Tenant slug in JWT claims** — downstream services can read tenant context without a DB lookup

### RBAC
- **Roles and permissions** — many-to-many: roles have permissions, users have roles
- **Fine-grained permission strings** — `users:read`, `users:write`, `roles:write`, `audit:read`, etc.
- **Middleware** — `RequirePermission("users:write")` and `RequireRole("admin")` drop-in Chi middleware
- **Permissions embedded in JWT** — zero additional DB queries per request for authorization

### Audit Logging
- **Every auth event logged** — login, login_failed, logout, logout_all, register, role_assigned, token_family_revoked
- **Async write pattern** — buffered Go channel + batch insert every 100ms; never slows the hot path
- **Queryable via API** — paginated, filterable by tenant

### Ops
- **Health endpoint** — `GET /health` returns version + status
- **Structured JSON logs** — zerolog, request ID on every line
- **Graceful shutdown** — drains audit buffer before exit
- **Docker Compose** — one command to run app + Postgres + Redis + run migrations

---

## Quick start

```bash
# Clone
git clone https://github.com/saurabhkumar/goauth
cd goauth

# Configure
cp .env.example .env
make generate-secrets   # paste output into .env

# Start everything
make docker-up

# Verify
curl http://localhost:8080/health
# {"status":"ok","version":"1.0.0"}
```

---

## API overview

### Auth
```
POST /api/v1/auth/register      Create a user in a tenant
POST /api/v1/auth/login         Get access + refresh token
POST /api/v1/auth/refresh       Rotate refresh token
POST /api/v1/auth/logout        Logout (blacklist access, revoke refresh)
POST /api/v1/auth/logout-all    Revoke all sessions for the user
GET  /api/v1/auth/me            Get current user info from JWT
```

### RBAC
```
GET  /api/v1/roles              List roles for tenant
POST /api/v1/roles              Create role (requires roles:write)
POST /api/v1/users/:id/roles    Assign role to user (requires roles:write)
```

### Audit
```
GET  /api/v1/audit-logs         Paginated audit trail (requires audit:read)
```

### Tenants
```
POST /api/v1/tenants            Create tenant (public, self-service)
GET  /api/v1/tenants            List tenants (requires admin role)
```

---

## Example: Register and login

```bash
# Create a tenant
curl -X POST http://localhost:8080/api/v1/tenants \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Corp","slug":"acme","plan":"free"}'

# Register a user
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"tenant_slug":"acme","email":"admin@acme.com","password":"secure123!"}'

# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"tenant_slug":"acme","email":"admin@acme.com","password":"secure123!"}'

# Response
{
  "access_token":  "eyJhbGci...",
  "refresh_token": "eyJhbGci...",
  "expires_in":    900,
  "token_type":    "Bearer"
}

# Use the token
curl http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer eyJhbGci..."
```

---

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Language | Go 1.22 | Performance, small binary, goroutine concurrency |
| HTTP | Chi v5 | Idiomatic, middleware-first, stdlib compatible |
| Database | PostgreSQL 16 | Reliable, JSONB for metadata, partial indexes |
| ORM | sqlx (raw SQL) | Full control, no magic, easier to debug |
| Cache | Redis 7 | Blacklist + rate limiting sorted sets |
| JWT | golang-jwt/jwt v5 | Standards-compliant, maintained |
| Passwords | Argon2id (stdlib) | OWASP top pick, no extra dependency |
| Logging | zerolog | Zero-allocation structured logs |
| Container | scratch image | 12MB final image, minimal attack surface |

---

## Project structure

```
goauth/
├── cmd/server/main.go          Entry point, DI wiring, graceful shutdown
├── internal/
│   ├── auth/                   Login, register, logout, refresh logic
│   ├── token/                  JWT generation, validation, hashing
│   ├── rbac/                   Role/permission CRUD, assignment
│   ├── tenant/                 Tenant lifecycle
│   ├── audit/                  Async audit event handler
│   ├── middleware/             JWT auth, RBAC, rate limit middleware
│   ├── repository/
│   │   ├── postgres/           User, token, RBAC, tenant, audit repos
│   │   └── redis/              Blacklist, sliding window limiter
│   ├── domain/                 Pure entities (no dependencies)
│   └── config/                 Env-based config
├── migrations/                 SQL migrations (golang-migrate compatible)
├── docker/Dockerfile           Multi-stage scratch build
├── docker-compose.yml
├── Makefile
└── .env.example
```
