package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/saurabhkumar/goauth/internal/domain"
)

type UserRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, u *domain.User) error {
	query := `
		INSERT INTO users (id, tenant_id, email, password_hash, is_active, created_at, updated_at)
		VALUES (:id, :tenant_id, :email, :password_hash, :is_active, :created_at, :updated_at)`
	_, err := r.db.NamedExecContext(ctx, query, u)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*domain.User, error) {
	var u domain.User
	err := r.db.GetContext(ctx, &u,
		`SELECT * FROM users WHERE tenant_id=$1 AND email=$2 AND deleted_at IS NULL`,
		tenantID, email)
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return &u, nil
}

func (r *UserRepository) FindByID(ctx context.Context, tenantID, userID uuid.UUID) (*domain.User, error) {
	var u domain.User
	err := r.db.GetContext(ctx, &u,
		`SELECT * FROM users WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`,
		tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("find user by id: %w", err)
	}
	return &u, nil
}

func (r *UserRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]domain.User, error) {
	var users []domain.User
	err := r.db.SelectContext(ctx, &users,
		`SELECT * FROM users WHERE tenant_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET last_login_at=$1, updated_at=$2 WHERE id=$3`,
		now, now, userID)
	return err
}

func (r *UserRepository) SoftDelete(ctx context.Context, tenantID, userID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET deleted_at=NOW(), updated_at=NOW() WHERE tenant_id=$1 AND id=$2`,
		tenantID, userID)
	return err
}

func (r *UserRepository) SetActive(ctx context.Context, tenantID, userID uuid.UUID, active bool) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET is_active=$1, updated_at=NOW() WHERE tenant_id=$2 AND id=$3`,
		active, tenantID, userID)
	return err
}
