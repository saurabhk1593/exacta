package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/saurabhkumar/goauth/internal/domain"
)

type TokenRepository struct {
	db *sqlx.DB
}

func NewTokenRepository(db *sqlx.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) Create(ctx context.Context, t *domain.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, family, expires_at, created_at)
		VALUES (:id, :user_id, :tenant_id, :token_hash, :family, :expires_at, :created_at)`
	_, err := r.db.NamedExecContext(ctx, query, t)
	return fmt.Errorf("create refresh token: %w", err)
}

func (r *TokenRepository) FindByHash(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	var t domain.RefreshToken
	err := r.db.GetContext(ctx, &t,
		`SELECT * FROM refresh_tokens WHERE token_hash=$1`, hash)
	if err != nil {
		return nil, fmt.Errorf("find refresh token: %w", err)
	}
	return &t, nil
}

// RotateToken marks old token as rotated and inserts new one atomically.
// If old token was already rotated → THEFT DETECTED → revoke entire family.
func (r *TokenRepository) RotateToken(ctx context.Context, oldHash string, newToken *domain.RefreshToken) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var old domain.RefreshToken
	err = tx.GetContext(ctx, &old,
		`SELECT * FROM refresh_tokens WHERE token_hash=$1 FOR UPDATE`, oldHash)
	if err != nil {
		return fmt.Errorf("token not found: %w", err)
	}

	// Theft detection: token was already rotated
	if old.RotatedAt != nil {
		// Revoke entire family
		_, err = tx.ExecContext(ctx,
			`DELETE FROM refresh_tokens WHERE family=$1`, old.Family)
		if err != nil {
			return fmt.Errorf("revoke family: %w", err)
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		return ErrTokenFamilyRevoked
	}

	// Mark old as rotated
	_, err = tx.ExecContext(ctx,
		`UPDATE refresh_tokens SET rotated_at=NOW() WHERE token_hash=$1`, oldHash)
	if err != nil {
		return fmt.Errorf("mark rotated: %w", err)
	}

	// Insert new token
	_, err = tx.NamedExecContext(ctx, `
		INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, family, expires_at, created_at)
		VALUES (:id, :user_id, :tenant_id, :token_hash, :family, :expires_at, :created_at)`, newToken)
	if err != nil {
		return fmt.Errorf("insert new token: %w", err)
	}

	return tx.Commit()
}

func (r *TokenRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE user_id=$1`, userID)
	return err
}

func (r *TokenRepository) RevokeFamily(ctx context.Context, family uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE family=$1`, family)
	return err
}

var ErrTokenFamilyRevoked = fmt.Errorf("refresh token family revoked: possible token theft detected")
