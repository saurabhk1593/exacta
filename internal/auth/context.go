package auth

import (
	"context"

	"github.com/saurabhkumar/goauth/internal/middleware"
	"github.com/saurabhkumar/goauth/internal/token"
)

func claimsFromContext(ctx context.Context) *token.Claims {
	return middleware.ClaimsFromContext(ctx)
}
