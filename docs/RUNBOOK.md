# GoAuth — Production Runbook

Operational guide for running GoAuth in production: deployment, monitoring, incident response, and maintenance procedures.

---

## 1. Deployment checklist

### Pre-deployment

- [ ] Generate secrets: `openssl rand -hex 32` — use different values for `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET`
- [ ] Set `DB_SSLMODE=require` for production Postgres
- [ ] Set Redis password via `REDIS_PASSWORD`
- [ ] Verify `ENV=production`
- [ ] Run migrations on the target database before deploying the binary
- [ ] Test `/health` endpoint after deploy

### Secret rotation policy

- Rotate `JWT_ACCESS_SECRET` every 90 days
- Rotating the secret invalidates all active access tokens immediately (users get a 401, must refresh)
- Rotating `JWT_REFRESH_SECRET` invalidates all refresh tokens (users must re-login)
- For zero-downtime rotation: run two instances with old + new secret briefly, drain old instance

---

## 2. Migration procedure

### Apply migrations

```bash
# Using make (local)
DB_URL="postgres://user:pass@host:5432/dbname?sslmode=require" make migrate-up

# Using Docker Compose
docker compose run --rm migrate

# Using golang-migrate CLI directly
migrate -path ./migrations \
        -database "postgres://user:pass@host:5432/dbname?sslmode=require" \
        up
```

### Check migration version

```bash
migrate -path ./migrations -database "$DB_URL" version
```

### Rollback one migration

```bash
make migrate-down
# or
migrate -path ./migrations -database "$DB_URL" down 1
```

### Emergency rollback (full)

```bash
migrate -path ./migrations -database "$DB_URL" drop -f
# WARNING: destroys all data — only for disaster recovery on a restore
```

---

## 3. Monitoring

### Key metrics to track

| Metric | Source | Alert threshold |
|---|---|---|
| `POST /api/v1/auth/login` 5xx rate | Access logs | > 1% over 5 min |
| `POST /api/v1/auth/login` 401 rate | Access logs | > 20% over 5 min (brute force signal) |
| `POST /api/v1/auth/refresh` 401 rate | Access logs | > 5% (stolen token signal) |
| `audit.token_family_revoked` events | Audit log | > 10/min (active theft) |
| Postgres connection pool saturation | App logs | Pool > 80% capacity |
| Redis latency | App logs | p99 > 10ms |
| Rate-limited IPs | Audit log | Spike |

### Log format

GoAuth uses zerolog structured JSON logs:

```json
{
  "level": "info",
  "time": "2025-01-01T10:00:00Z",
  "request_id": "abc123",
  "method": "POST",
  "path": "/api/v1/auth/login",
  "status": 200,
  "latency_ms": 12
}
```

Filter for auth failures:

```bash
docker logs goauth-app 2>&1 | jq 'select(.status == 401)'
```

Filter for rate limit events:

```bash
docker logs goauth-app 2>&1 | jq 'select(.status == 429)'
```

### Audit log query

```sql
-- Failed logins in last hour
SELECT ip_address, COUNT(*) as attempts
FROM audit_logs
WHERE action = 'auth.login_failed'
  AND tenant_id = '<tenant-uuid>'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY ip_address
ORDER BY attempts DESC;

-- Token theft events
SELECT * FROM audit_logs
WHERE action = 'token.family_revoked'
ORDER BY created_at DESC
LIMIT 50;

-- Active users per tenant today
SELECT tenant_id, COUNT(DISTINCT user_id) as dau
FROM audit_logs
WHERE action = 'auth.login'
  AND created_at > NOW() - INTERVAL '24 hours'
GROUP BY tenant_id;
```

---

## 4. Incident response

### Incident: Brute force attack on tenant

**Symptoms:** High `auth.login_failed` rate from one or few IPs.

**Response:**

1. Check if IPs are already rate-limited:
   ```sql
   SELECT ip_address, COUNT(*) FROM audit_logs
   WHERE action = 'auth.login_failed' AND created_at > NOW() - INTERVAL '10 minutes'
   GROUP BY ip_address;
   ```

2. If GoAuth rate limiting hasn't caught it (Redis issue), manually block at ingress/CDN level.

3. Temporarily reduce rate limit:
   ```bash
   # Update env and restart
   RATE_LIMIT_RPM=20
   ```

4. Notify affected tenant if specific user accounts were targeted.

---

### Incident: Token theft detected

**Symptoms:** `token.family_revoked` events appearing in audit log. Users report being suddenly logged out.

**What happened:** A refresh token was used twice. GoAuth automatically revoked the entire token family. The user must re-login.

**Response:**

1. Identify affected user:
   ```sql
   SELECT user_id, metadata, created_at FROM audit_logs
   WHERE action = 'token.family_revoked'
   ORDER BY created_at DESC LIMIT 10;
   ```

2. If the user did not log in from the suspicious IP, their session was genuinely compromised.

3. Force password reset for the user:
   ```sql
   UPDATE users SET password_hash = 'RESET_REQUIRED', updated_at = NOW()
   WHERE id = '<user-uuid>';
   ```
   (Implement a reset flow in your application.)

4. Check if other users in the same tenant show similar patterns.

---

### Incident: Redis is down

**Effect:** Rate limiting is disabled (fail-open). Token blacklist is unavailable — logged-out access tokens remain valid until natural expiry (15 minutes max).

**Acceptable risk:** Documented design decision. Access tokens are short-lived. Maximum exposure: 15 minutes per token.

**Response:**

1. Restore Redis. GoAuth reconnects automatically.
2. If Redis was down during a known security event, rotate `JWT_ACCESS_SECRET` to immediately invalidate all access tokens.
3. Monitor login rates manually during outage.

---

### Incident: Postgres is down

**Effect:** All auth requests fail (500). GoAuth cannot function without the database.

**Response:**

1. Check connection pool:
   ```bash
   docker logs goauth-app 2>&1 | grep "postgres"
   ```

2. If using Postgres HA (Patroni/pgBouncer), check failover status.

3. GoAuth will reconnect automatically when Postgres is restored — no restart needed.

4. Audit buffer: GoAuth holds up to 512 audit events in memory. Events may be lost if the process is killed during extended Postgres downtime. This is documented and acceptable.

---

### Incident: High memory usage

**Symptoms:** GoAuth container memory growing unexpectedly.

**Checks:**

1. Audit buffer: if Postgres is slow, the 512-event buffer may be full and dropping events (check logs for "audit buffer full").

2. Goroutine leak check:
   ```bash
   curl http://localhost:8080/debug/pprof/goroutine?debug=1
   ```
   (Enable pprof in development mode only.)

3. Normal memory footprint: GoAuth should use 20-50MB under typical load.

---

## 5. Database maintenance

### Purge expired refresh tokens (run weekly)

```sql
DELETE FROM refresh_tokens
WHERE expires_at < NOW() - INTERVAL '1 day';
```

Recommended: set up a cron job or pg_cron extension.

### Archive old audit logs (run monthly)

```sql
-- Move to audit_logs_archive table (create same schema)
INSERT INTO audit_logs_archive
SELECT * FROM audit_logs
WHERE created_at < NOW() - INTERVAL '90 days';

DELETE FROM audit_logs
WHERE created_at < NOW() - INTERVAL '90 days';
```

### Vacuum and analyze (run weekly)

```sql
VACUUM ANALYZE users;
VACUUM ANALYZE refresh_tokens;
VACUUM ANALYZE audit_logs;
```

---

## 6. Scaling

### Horizontal scaling

GoAuth is stateless at the application layer. Run multiple instances behind a load balancer. All state lives in Postgres and Redis.

```yaml
# docker-compose scale
docker compose up --scale app=3
```

Ensure sticky sessions are NOT required — GoAuth is fully stateless per request.

### Connection pool tuning

Default: 25 max open connections, 5 idle.

Rule of thumb: `max_connections = (number of instances × 25) < postgres max_connections`.

For Postgres with `max_connections=200` and 4 GoAuth instances:
```
4 × 25 = 100 connections used (50% headroom — good)
```

### Redis cluster

For high availability, configure Redis Sentinel or Cluster. Update `REDIS_ADDR` to your Sentinel/Cluster endpoint and update the Redis client initialization in `main.go` to use `redis.NewFailoverClient` or `redis.NewClusterClient`.

---

## 7. Backup and recovery

### Postgres backup

```bash
# Full backup
pg_dump -U goauth -h localhost goauth | gzip > goauth_$(date +%Y%m%d).sql.gz

# Restore
gunzip -c goauth_20250101.sql.gz | psql -U goauth -h localhost goauth
```

### What to back up

| Data | Location | RPO |
|---|---|---|
| Users, tenants, roles | Postgres | Daily minimum |
| Refresh tokens | Postgres | Not critical (users re-login) |
| Audit logs | Postgres | Daily minimum, compliance-driven |
| Token blacklist | Redis | Not critical (15m TTL anyway) |
| Rate limit counters | Redis | Not critical |

---

## 8. Known limitations and design decisions

| Decision | Tradeoff |
|---|---|
| Shared database multi-tenancy | Lower complexity vs. per-tenant database isolation |
| Fail-open on Redis errors | Availability over strict rate limiting during Redis outage |
| Async audit writes (100ms batch) | Up to 100ms of audit events lost on hard crash |
| JWT blacklist TTL = access token TTL | Blacklist auto-expires; no manual cleanup needed |
| No refresh token sliding expiry | Simpler; refresh tokens expire at fixed 7-day TTL regardless of activity |
| HMAC-SHA256 (not RSA) | Symmetric; downstream services must share the secret. Use RSA for multi-service setups |

---

## 9. Security hardening checklist

- [ ] Run behind TLS termination (nginx / Caddy / ALB)
- [ ] Set `DB_SSLMODE=require`
- [ ] Use strong Postgres password (20+ chars)
- [ ] Set Redis `requirepass` and `bind 127.0.0.1`
- [ ] Do not expose Postgres or Redis ports externally
- [ ] Rotate JWT secrets every 90 days
- [ ] Enable Postgres audit logging for DML on `users` table
- [ ] Set up log aggregation (Loki / CloudWatch / Datadog)
- [ ] Configure alerting on `auth.login_failed` spike and `token.family_revoked`
