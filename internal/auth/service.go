package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/saurabhkumar/goauth/internal/domain"
	"github.com/saurabhkumar/goauth/internal/repository/postgres"
	redisrepo "github.com/saurabhkumar/goauth/internal/repository/redis"
	"github.com/saurabhkumar/goauth/internal/token"
	"golang.org/x/crypto/argon2"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

type Service struct {
	users     *postgres.UserRepository
	tokens    *postgres.TokenRepository
	rbac      *postgres.RBACRepository
	tenants   *postgres.TenantRepository
	audit     *postgres.AuditRepository
	blacklist *redisrepo.BlacklistStore
	limiter   *redisrepo.RateLimiter
	jwt       *token.Service
}

func NewService(
	users *postgres.UserRepository,
	tokens *postgres.TokenRepository,
	rbac *postgres.RBACRepository,
	tenants *postgres.TenantRepository,
	audit *postgres.AuditRepository,
	blacklist *redisrepo.BlacklistStore,
	limiter *redisrepo.RateLimiter,
	jwt *token.Service,
) *Service {
	return &Service{
		users: users, tokens: tokens, rbac: rbac,
		tenants: tenants, audit: audit, blacklist: blacklist,
		limiter: limiter, jwt: jwt,
	}
}

type RegisterInput struct {
	TenantSlug string
	Email      string
	Password   string
	IP         string
	UserAgent  string
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds
	TokenType    string `json:"token_type"`
}

func (s *Service) Register(ctx context.Context, in RegisterInput) (*domain.User, error) {
	tenant, err := s.tenants.FindBySlug(ctx, in.TenantSlug)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	hash, err := hashArgon2(in.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now()
	user := &domain.User{
		ID:           uuid.New(),
		TenantID:     tenant.ID,
		Email:        in.Email,
		PasswordHash: hash,
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}

	uid := user.ID
	s.audit.Log(tenant.ID, &uid, "auth.register", in.IP, in.UserAgent, `{}`)
	return user, nil
}

type LoginInput struct {
	TenantSlug string
	Email      string
	Password   string
	IP         string
	UserAgent  string
}

func (s *Service) Login(ctx context.Context, in LoginInput) (*TokenPair, error) {
	// Rate limit by IP
	if ok, _ := s.limiter.Allow(ctx, "ip:"+in.IP); !ok {
		return nil, ErrRateLimited
	}

	tenant, err := s.tenants.FindBySlug(ctx, in.TenantSlug)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	user, err := s.users.FindByEmail(ctx, tenant.ID, in.Email)
	if err != nil {
		s.audit.Log(tenant.ID, nil, "auth.login_failed", in.IP, in.UserAgent, `{"reason":"user_not_found"}`)
		return nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		return nil, ErrAccountDisabled
	}

	if !verifyArgon2(in.Password, user.PasswordHash) {
		s.audit.Log(tenant.ID, &user.ID, "auth.login_failed", in.IP, in.UserAgent, `{"reason":"wrong_password"}`)
		// Also rate limit by user after failed attempt
		s.limiter.Allow(ctx, "user:"+user.ID.String())
		return nil, ErrInvalidCredentials
	}

	roles, _ := s.rbac.GetUserRoles(ctx, user.ID)
	perms, _ := s.rbac.GetUserPermissions(ctx, user.ID)

	accessToken, err := s.jwt.GenerateAccessToken(user.ID, tenant.ID, tenant.Slug, roles, perms)
	if err != nil {
		return nil, err
	}

	family := uuid.New()
	rawRefresh, hash, err := s.jwt.GenerateRefreshToken(user.ID, tenant.ID, family)
	if err != nil {
		return nil, err
	}

	rt := &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		TenantID:  tenant.ID,
		TokenHash: hash,
		Family:    family,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}
	if err := s.tokens.Create(ctx, rt); err != nil {
		return nil, err
	}

	s.users.UpdateLastLogin(ctx, user.ID)
	s.audit.Log(tenant.ID, &user.ID, "auth.login", in.IP, in.UserAgent, `{}`)

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresIn:    900,
		TokenType:    "Bearer",
	}, nil
}

func (s *Service) Refresh(ctx context.Context, rawRefreshToken, ip, ua string) (*TokenPair, error) {
	claims, err := s.jwt.ValidateRefreshToken(rawRefreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	oldHash := token.HashToken(rawRefreshToken)
	newFamily := claims.Family // same family

	newRaw, newHash, err := s.jwt.GenerateRefreshToken(claims.UserID, claims.TenantID, newFamily)
	if err != nil {
		return nil, err
	}

	newRT := &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    claims.UserID,
		TenantID:  claims.TenantID,
		TokenHash: newHash,
		Family:    newFamily,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}

	if err := s.tokens.RotateToken(ctx, oldHash, newRT); err != nil {
		if err == postgres.ErrTokenFamilyRevoked {
			s.audit.Log(claims.TenantID, &claims.UserID, "token.family_revoked", ip, ua, `{"reason":"reuse_detected"}`)
		}
		return nil, err
	}

	tenant, err := s.tenants.FindByID(ctx, claims.TenantID)
	if err != nil {
		return nil, err
	}

	roles, _ := s.rbac.GetUserRoles(ctx, claims.UserID)
	perms, _ := s.rbac.GetUserPermissions(ctx, claims.UserID)

	accessToken, err := s.jwt.GenerateAccessToken(claims.UserID, claims.TenantID, tenant.Slug, roles, perms)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRaw,
		ExpiresIn:    900,
		TokenType:    "Bearer",
	}, nil
}

func (s *Service) Logout(ctx context.Context, accessToken, rawRefreshToken, ip, ua string) error {
	claims, err := s.jwt.ValidateAccessToken(accessToken)
	if err != nil {
		return ErrInvalidToken
	}

	// Blacklist the access token until it expires
	s.blacklist.Add(ctx, token.HashToken(accessToken), 15*time.Minute)

	// Revoke refresh token
	if rawRefreshToken != "" {
		hash := token.HashToken(rawRefreshToken)
		s.tokens.RevokeFamily(ctx, claims.UserID) // revoke by user — simplified
		_ = hash
	}

	s.audit.Log(claims.TenantID, &claims.UserID, "auth.logout", ip, ua, `{}`)
	return nil
}

func (s *Service) LogoutAll(ctx context.Context, accessToken, ip, ua string) error {
	claims, err := s.jwt.ValidateAccessToken(accessToken)
	if err != nil {
		return ErrInvalidToken
	}
	s.blacklist.Add(ctx, token.HashToken(accessToken), 15*time.Minute)
	s.tokens.RevokeAllForUser(ctx, claims.UserID)
	s.audit.Log(claims.TenantID, &claims.UserID, "auth.logout_all", ip, ua, `{}`)
	return nil
}

// Argon2id password hashing — OWASP recommended params
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

func hashArgon2(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads, b64Salt, b64Hash), nil
}

func verifyArgon2(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return false
	}
	var memory, timeCost uint32
	var threads uint8
	fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads)
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	computed := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(hash)))
	return subtle.ConstantTimeCompare(hash, computed) == 1
}

var (
	ErrInvalidCredentials = fmt.Errorf("invalid email or password")
	ErrAccountDisabled    = fmt.Errorf("account is disabled")
	ErrRateLimited        = fmt.Errorf("too many requests, please try again later")
	ErrInvalidToken       = fmt.Errorf("invalid or expired token")
)
