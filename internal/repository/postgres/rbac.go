package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/saurabhkumar/goauth/internal/domain"
)

type RBACRepository struct {
	db *sqlx.DB
}

func NewRBACRepository(db *sqlx.DB) *RBACRepository {
	return &RBACRepository{db: db}
}

func (r *RBACRepository) CreateRole(ctx context.Context, role *domain.Role) error {
	_, err := r.db.NamedExecContext(ctx,
		`INSERT INTO roles (id, tenant_id, name, description) VALUES (:id, :tenant_id, :name, :description)`,
		role)
	return fmt.Errorf("create role: %w", err)
}

func (r *RBACRepository) ListRoles(ctx context.Context, tenantID uuid.UUID) ([]domain.Role, error) {
	var roles []domain.Role
	err := r.db.SelectContext(ctx, &roles,
		`SELECT * FROM roles WHERE tenant_id=$1 ORDER BY name`, tenantID)
	return roles, err
}

func (r *RBACRepository) DeleteRole(ctx context.Context, tenantID, roleID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM roles WHERE tenant_id=$1 AND id=$2`, tenantID, roleID)
	return err
}

func (r *RBACRepository) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		userID, roleID)
	return err
}

func (r *RBACRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2`, userID, roleID)
	return err
}

func (r *RBACRepository) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	var perms []string
	err := r.db.SelectContext(ctx, &perms, `
		SELECT DISTINCT p.action
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		JOIN user_roles ur ON ur.role_id = rp.role_id
		WHERE ur.user_id = $1`, userID)
	return perms, err
}

func (r *RBACRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	var roles []string
	err := r.db.SelectContext(ctx, &roles, `
		SELECT r.name
		FROM roles r
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1`, userID)
	return roles, err
}

func (r *RBACRepository) AddPermissionToRole(ctx context.Context, roleID, permID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		roleID, permID)
	return err
}

func (r *RBACRepository) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	var perms []domain.Permission
	err := r.db.SelectContext(ctx, &perms, `SELECT * FROM permissions ORDER BY action`)
	return perms, err
}
