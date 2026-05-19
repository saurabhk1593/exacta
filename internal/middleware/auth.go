package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/saurabhkumar/goauth/internal/repository/redis"
	"github.com/saurabhkumar/goauth/internal/token"
)

type contextKey string

const claimsKey contextKey = "claims"

type AuthMiddleware struct {
	jwt       *token.Service
	blacklist *redis.BlacklistStore
}

func NewAuthMiddleware(jwt *token.Service, blacklist *redis.BlacklistStore) *AuthMiddleware {
	return &AuthMiddleware{jwt: jwt, blacklist: blacklist}
}

// Authenticate validates the JWT and injects claims into the request context.
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		// Check blacklist (logged-out tokens)
		hash := token.HashToken(tokenStr)
		if blacklisted, _ := m.blacklist.IsBlacklisted(r.Context(), hash); blacklisted {
			http.Error(w, `{"error":"token has been revoked"}`, http.StatusUnauthorized)
			return
		}

		claims, err := m.jwt.ValidateAccessToken(tokenStr)
		if err != nil {
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission checks that the authenticated user has the given permission.
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, `{"error":"not authenticated"}`, http.StatusUnauthorized)
				return
			}
			for _, p := range claims.Permissions {
				if p == permission {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, `{"error":"forbidden: missing permission `+permission+`"}`, http.StatusForbidden)
		})
	}
}

// RequireRole checks that the authenticated user has the given role.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, `{"error":"not authenticated"}`, http.StatusUnauthorized)
				return
			}
			for _, ro := range claims.Roles {
				if ro == role {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, `{"error":"forbidden: missing role `+role+`"}`, http.StatusForbidden)
		})
	}
}

func ClaimsFromContext(ctx context.Context) *token.Claims {
	c, _ := ctx.Value(claimsKey).(*token.Claims)
	return c
}
