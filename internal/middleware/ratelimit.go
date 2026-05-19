package middleware

import (
	"net/http"
	"strings"

	redisrepo "github.com/saurabhkumar/goauth/internal/repository/redis"
)

type RateLimitMiddleware struct {
	limiter *redisrepo.RateLimiter
}

func NewRateLimitMiddleware(limiter *redisrepo.RateLimiter) *RateLimitMiddleware {
	return &RateLimitMiddleware{limiter: limiter}
}

// LimitByIP applies rate limiting keyed by client IP.
func (m *RateLimitMiddleware) LimitByIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := realIP(r)
		allowed, err := m.limiter.Allow(r.Context(), "ip:"+ip)
		if err != nil {
			// Fail open on Redis error
			next.ServeHTTP(w, r)
			return
		}
		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return r.RemoteAddr
}
