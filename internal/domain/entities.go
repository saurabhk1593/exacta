package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID  `db:"id"`
	TenantID     uuid.UUID  `db:"tenant_id"`
	Email        string     `db:"email"`
	PasswordHash string     `db:"password_hash"`
	IsActive     bool       `db:"is_active"`
	LastLoginAt  *time.Time `db:"last_login_at"`
	CreatedAt    time.Time  `db:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at"`
}

type Tenant struct {
	ID        uuid.UUID `db:"id"`
	Name      string    `db:"name"`
	Slug      string    `db:"slug"`
	Plan      string    `db:"plan"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

type Role struct {
	ID          uuid.UUID `db:"id"`
	TenantID    uuid.UUID `db:"tenant_id"`
	Name        string    `db:"name"`
	Description string    `db:"description"`
}

type Permission struct {
	ID     uuid.UUID `db:"id"`
	Action string    `db:"action"`
}

type RefreshToken struct {
	ID        uuid.UUID  `db:"id"`
	UserID    uuid.UUID  `db:"user_id"`
	TenantID  uuid.UUID  `db:"tenant_id"`
	TokenHash string     `db:"token_hash"`
	Family    uuid.UUID  `db:"family"`
	ExpiresAt time.Time  `db:"expires_at"`
	RotatedAt *time.Time `db:"rotated_at"`
	CreatedAt time.Time  `db:"created_at"`
}

type AuditEvent struct {
	ID        uuid.UUID  `db:"id"`
	TenantID  uuid.UUID  `db:"tenant_id"`
	UserID    *uuid.UUID `db:"user_id"`
	Action    string     `db:"action"`
	IPAddress string     `db:"ip_address"`
	UserAgent string     `db:"user_agent"`
	Metadata  string     `db:"metadata"`
	CreatedAt time.Time  `db:"created_at"`
}
