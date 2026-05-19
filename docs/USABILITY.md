# GoAuth — Integration & Usability Guide

This guide covers how to integrate GoAuth into your application, configure it for production, and extend it for your use case.

---

## 1. Running GoAuth

### Option A: Docker Compose (recommended)

```bash
cp .env.example .env

# Generate cryptographically secure secrets
openssl rand -hex 32   # use output as JWT_ACCESS_SECRET
openssl rand -hex 32   # use different output as JWT_REFRESH_SECRET

# Edit .env with your secrets, then:
docker compose up -d

# Run migrations
docker compose run --rm migrate
```

GoAuth is now running on `http://localhost:8080`.

### Option B: Local binary

```bash
# Prerequisites: Go 1.22+, Postgres 14+, Redis 7+

go mod download
make migrate-up     # DB_URL env var must be set
make run
```

### Option C: As a sidecar / microservice

GoAuth exposes a REST API — any language can call it. No SDK required.

---

## 2. Multi-tenant setup

GoAuth is built for multi-tenancy from the ground up. Each tenant is isolated at the database row level.

### Create your first tenant

```bash
curl -X POST http://localhost:8080/api/v1/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corp",
    "slug": "acme",
    "plan": "pro"
  }'
```

The `slug` becomes part of every login request and is embedded in the JWT claims. Choose slugs that are URL-safe and stable — they cannot be changed without re-issuing tokens.

### Tenant isolation guarantee

Every database query in GoAuth enforces `tenant_id` as the first filter. Cross-tenant data leakage is impossible at the application layer. The `UNIQUE(tenant_id, email)` constraint means the same email can exist in multiple tenants independently.

---

## 3. Authentication flow

### Register

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_slug": "acme",
    "email": "user@acme.com",
    "password": "minimum8chars"
  }'
```

Password requirements: minimum 8 characters. Stored as Argon2id hash — GoAuth never stores plaintext.

### Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_slug": "acme",
    "email": "user@acme.com",
    "password": "minimum8chars"
  }'

# Response:
{
  "access_token":  "eyJhbGci...",   # valid for 15 minutes
  "refresh_token": "eyJhbGci...",   # valid for 7 days
  "expires_in":    900,
  "token_type":    "Bearer"
}
```

### Refresh

Call this before the access token expires (recommended: at 12 minutes, 3 minutes before expiry).

```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJhbGci..."}'
```

Each refresh issues a **new** access token and a **new** refresh token. The old refresh token is immediately invalidated. Store the new pair.

### Logout

```bash
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer eyJhbGci..." \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJhbGci..."}'
```

### Logout all sessions

Revokes every active session for the authenticated user — useful for "someone else is using my account" scenarios.

```bash
curl -X POST http://localhost:8080/api/v1/auth/logout-all \
  -H "Authorization: Bearer eyJhbGci..."
```

---

## 4. Protecting your own API with GoAuth JWTs

GoAuth issues standard JWTs. Your API validates them directly using the same `JWT_ACCESS_SECRET`.

### Go example

```go
import "github.com/golang-jwt/jwt/v5"

type Claims struct {
    UserID      string   `json:"user_id"`
    TenantID    string   `json:"tenant_id"`
    TenantSlug  string   `json:"tenant_slug"`
    Roles       []string `json:"roles"`
    Permissions []string `json:"permissions"`
    jwt.RegisteredClaims
}

func validateToken(tokenStr, secret string) (*Claims, error) {
    t, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
        return []byte(secret), nil
    })
    if err != nil { return nil, err }
    return t.Claims.(*Claims), nil
}
```

### Node.js example

```js
const jwt = require('jsonwebtoken');

function validateToken(token) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
  // Returns: { user_id, tenant_id, tenant_slug, roles, permissions, ... }
}
```

### What's in the JWT

```json
{
  "user_id":     "uuid",
  "tenant_id":   "uuid",
  "tenant_slug": "acme",
  "roles":       ["admin"],
  "permissions": ["users:read", "users:write", "roles:write", "audit:read"],
  "token_type":  "access",
  "iss":         "goauth",
  "sub":         "user-uuid",
  "iat":         1720000000,
  "exp":         1720000900
}
```

Your downstream services can read `tenant_id`, `roles`, and `permissions` from the token — no additional database call needed.

---

## 5. RBAC — Roles and permissions

### Default permissions

| Permission | Meaning |
|---|---|
| `users:read` | View user list and details |
| `users:write` | Create, update, suspend users |
| `roles:read` | View roles and permissions |
| `roles:write` | Create roles, assign permissions |
| `audit:read` | View audit log |
| `tenants:read` | View tenant info |
| `tenants:write` | Create and modify tenants |

### Assign a role to a user

```bash
# First, get the role ID from list roles
curl http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Assign
curl -X POST http://localhost:8080/api/v1/users/$USER_ID/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role_id": "role-uuid-here"}'
```

### Using permissions in your own API

If you're validating GoAuth JWTs in your own service, check the `permissions` array:

```go
func hasPermission(claims *Claims, required string) bool {
    for _, p := range claims.Permissions {
        if p == required { return true }
    }
    return false
}
```

---

## 6. Rate limiting behaviour

GoAuth applies a sliding window rate limiter to all auth endpoints:

- Default: **60 requests per 60 seconds per IP**
- Failed logins also increment the **per-user counter** (separate bucket)
- On breach: `429 Too Many Requests` with `Retry-After: 60` header
- On Redis failure: **fail-open** — requests are allowed through

Tune via environment variables:
```
RATE_LIMIT_RPM=100         # requests per minute
RATE_LIMIT_WINDOW_SEC=60   # window size in seconds
```

---

## 7. Token theft detection

GoAuth implements refresh token rotation with family tracking:

1. Each login starts a **new family** (UUID)
2. Each refresh: old token → `rotated_at = now`, new token same family
3. If a token with non-null `rotated_at` is used again → **the entire family is revoked**
4. The user must re-authenticate

This catches replay attacks where a token is stolen between rotation and client receipt.

Your application should handle `401 Unauthorized` on refresh gracefully — redirect to login.

---

## 8. Configuration reference

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP server port |
| `ENV` | `development` | Environment label |
| `DB_HOST` | `localhost` | Postgres host |
| `DB_PORT` | `5432` | Postgres port |
| `DB_USER` | `goauth` | Postgres user |
| `DB_PASSWORD` | — | Postgres password |
| `DB_NAME` | `goauth` | Postgres database name |
| `DB_SSLMODE` | `disable` | Postgres SSL mode (`require` in prod) |
| `REDIS_ADDR` | `localhost:6379` | Redis address |
| `REDIS_PASSWORD` | — | Redis password |
| `REDIS_DB` | `0` | Redis database number |
| `JWT_ACCESS_SECRET` | **required** | HMAC secret for access tokens |
| `JWT_REFRESH_SECRET` | **required** | HMAC secret for refresh tokens |
| `JWT_ACCESS_EXPIRY` | `15m` | Access token lifetime |
| `JWT_REFRESH_EXPIRY` | `168h` | Refresh token lifetime (7 days) |
| `RATE_LIMIT_RPM` | `60` | Requests per minute per IP |
| `RATE_LIMIT_WINDOW_SEC` | `60` | Rate limit window in seconds |

---

## 9. Extending GoAuth

### Add a new permission

1. Add to `migrations/004_create_rbac.up.sql` INSERT block
2. Run `make migrate-up`
3. Add to relevant roles via the API

### Add OAuth2 / social login

Add a `/auth/oauth/:provider/callback` handler in `internal/auth/`. The handler receives the OAuth token, upserts the user, and calls the same token generation path as `Login`.

### Add TOTP / MFA

1. Add `totp_secret` column to `users` table
2. Add `POST /auth/totp/setup` and `POST /auth/totp/verify` handlers
3. Add `totp_verified` claim to JWT
4. Protect sensitive routes with `RequirePermission("totp:verified")`

---

## 10. Health check

```bash
curl http://localhost:8080/health
# {"status":"ok","version":"1.0.0"}
```

Use this as your Docker/Kubernetes liveness probe:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```
