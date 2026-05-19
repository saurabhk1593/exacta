package token

import (
	"crypto/sha256"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/saurabhkumar/goauth/internal/config"
)

type Claims struct {
	UserID      uuid.UUID `json:"user_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	TenantSlug  string    `json:"tenant_slug"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
	TokenType   string    `json:"token_type"` // "access" | "refresh"
	Family      uuid.UUID `json:"family,omitempty"`
	jwt.RegisteredClaims
}

type Service struct {
	cfg config.JWTConfig
}

func NewService(cfg config.JWTConfig) *Service {
	return &Service{cfg: cfg}
}

func (s *Service) GenerateAccessToken(userID, tenantID uuid.UUID, tenantSlug string, roles, permissions []string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:      userID,
		TenantID:    tenantID,
		TenantSlug:  tenantSlug,
		Roles:       roles,
		Permissions: permissions,
		TokenType:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTokenExpiry)),
			Issuer:    "goauth",
			Subject:   userID.String(),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(s.cfg.AccessSecret))
}

// GenerateRefreshToken returns (rawToken, tokenHash, family, error).
// family is a new UUID; on rotation caller passes existing family.
func (s *Service) GenerateRefreshToken(userID, tenantID uuid.UUID, family uuid.UUID) (string, string, error) {
	// Generate 32 random bytes for the token
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}
	rawToken := hex.EncodeToString(raw)

	// Embed claims so we can validate family on rotation
	now := time.Now()
	claims := Claims{
		UserID:    userID,
		TenantID:  tenantID,
		TokenType: "refresh",
		Family:    family,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.RefreshTokenExpiry)),
			Issuer:    "goauth",
			Subject:   userID.String(),
			JWTID:     rawToken, // embed raw for hash
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := t.SignedString([]byte(s.cfg.RefreshSecret))
	if err != nil {
		return "", "", err
	}

	hash := HashToken(signed)
	return signed, hash, nil
}

func (s *Service) ValidateAccessToken(tokenStr string) (*Claims, error) {
	return s.validate(tokenStr, s.cfg.AccessSecret, "access")
}

func (s *Service) ValidateRefreshToken(tokenStr string) (*Claims, error) {
	return s.validate(tokenStr, s.cfg.RefreshSecret, "refresh")
}

func (s *Service) validate(tokenStr, secret, expectedType string) (*Claims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := t.Claims.(*Claims)
	if !ok || !t.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	if claims.TokenType != expectedType {
		return nil, fmt.Errorf("wrong token type: expected %s", expectedType)
	}
	return claims, nil
}

func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
