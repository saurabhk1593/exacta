-- 004_create_rbac.up.sql
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        VARCHAR(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    UNIQUE(tenant_id, name)
);

CREATE TABLE permissions (
    id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action  VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE role_permissions (
    role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id   UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY(role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY(user_id, role_id)
);

-- Seed core permissions
INSERT INTO permissions (id, action) VALUES
    (gen_random_uuid(), 'users:read'),
    (gen_random_uuid(), 'users:write'),
    (gen_random_uuid(), 'roles:read'),
    (gen_random_uuid(), 'roles:write'),
    (gen_random_uuid(), 'audit:read'),
    (gen_random_uuid(), 'tenants:read'),
    (gen_random_uuid(), 'tenants:write');
