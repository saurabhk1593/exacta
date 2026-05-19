package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/saurabhkumar/goauth/internal/domain"
)

type TenantRepository struct {
	db *sqlx.DB
}

func NewTenantRepository(db *sqlx.DB) *TenantRepository {
	return &TenantRepository{db: db}
}

func (r *TenantRepository) Create(ctx context.Context, t *domain.Tenant) error {
	_, err := r.db.NamedExecContext(ctx,
		`INSERT INTO tenants (id, name, slug, plan, created_at, updated_at) VALUES (:id, :name, :slug, :plan, :created_at, :updated_at)`,
		t)
	if err != nil {
		return fmt.Errorf("create tenant: %w", err)
	}
	return nil
}

func (r *TenantRepository) FindBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	var t domain.Tenant
	err := r.db.GetContext(ctx, &t,
		`SELECT * FROM tenants WHERE slug=$1 AND deleted_at IS NULL`, slug)
	if err != nil {
		return nil, fmt.Errorf("find tenant by slug: %w", err)
	}
	return &t, nil
}

func (r *TenantRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error) {
	var t domain.Tenant
	err := r.db.GetContext(ctx, &t,
		`SELECT * FROM tenants WHERE id=$1 AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, fmt.Errorf("find tenant by id: %w", err)
	}
	return &t, nil
}

func (r *TenantRepository) List(ctx context.Context) ([]domain.Tenant, error) {
	var tenants []domain.Tenant
	err := r.db.SelectContext(ctx, &tenants,
		`SELECT * FROM tenants WHERE deleted_at IS NULL ORDER BY created_at DESC`)
	return tenants, err
}
