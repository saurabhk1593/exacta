-- 003_create_refresh_tokens.up.sql
CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) UNIQUE NOT NULL,
    family      UUID NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    rotated_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rt_user_id  ON refresh_tokens(user_id);
CREATE INDEX idx_rt_family   ON refresh_tokens(family);
-- Auto-clean expired tokens
CREATE INDEX idx_rt_expires  ON refresh_tokens(expires_at);
