package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/saurabhkumar/goauth/internal/audit"
	"github.com/saurabhkumar/goauth/internal/auth"
	"github.com/saurabhkumar/goauth/internal/config"
	"github.com/saurabhkumar/goauth/internal/middleware"
	"github.com/saurabhkumar/goauth/internal/rbac"
	"github.com/saurabhkumar/goauth/internal/repository/postgres"
	redisrepo "github.com/saurabhkumar/goauth/internal/repository/redis"
	"github.com/saurabhkumar/goauth/internal/tenant"
	"github.com/saurabhkumar/goauth/internal/token"
)

func main() {
	_ = godotenv.Load()

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	// ── Database ─────────────────────────────────────────────────────────────
	connStr := cfg.DB.DSN()
	pgConn, err := stdlib.Open(nil) // pgx stdlib driver
	_ = pgConn
	db, err := sqlx.Connect("pgx", connStr)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to postgres")
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	defer db.Close()
	log.Info().Msg("postgres connected")

	// ── Redis ─────────────────────────────────────────────────────────────────
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Fatal().Err(err).Msg("failed to connect to redis")
	}
	defer rdb.Close()
	log.Info().Msg("redis connected")

	// ── Repositories ──────────────────────────────────────────────────────────
	userRepo    := postgres.NewUserRepository(db)
	tokenRepo   := postgres.NewTokenRepository(db)
	rbacRepo    := postgres.NewRBACRepository(db)
	tenantRepo  := postgres.NewTenantRepository(db)
	auditRepo   := postgres.NewAuditRepository(db)
	blacklist   := redisrepo.NewBlacklistStore(rdb)
	limiter     := redisrepo.NewRateLimiter(rdb, cfg.RateLimit.WindowSeconds, cfg.RateLimit.RequestsPerMinute)

	// ── Services ──────────────────────────────────────────────────────────────
	jwtSvc      := token.NewService(cfg.JWT)
	authSvc     := auth.NewService(userRepo, tokenRepo, rbacRepo, tenantRepo, auditRepo, blacklist, limiter, jwtSvc)
	rbacSvc     := rbac.NewService(rbacRepo)
	tenantSvc   := tenant.NewService(tenantRepo)

	// ── Handlers ──────────────────────────────────────────────────────────────
	authHandler   := auth.NewHandler(authSvc)
	rbacHandler   := rbac.NewHandler(rbacSvc)
	tenantHandler := tenant.NewHandler(tenantSvc)
	auditHandler  := audit.NewHandler(auditRepo)

	// ── Middleware ────────────────────────────────────────────────────────────
	authMW    := middleware.NewAuthMiddleware(jwtSvc, blacklist)
	rateMW    := middleware.NewRateLimitMiddleware(limiter)

	// ── Router ────────────────────────────────────────────────────────────────
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Compress(5))
	r.Use(chimw.Timeout(30 * time.Second))
	r.Use(corsMiddleware)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":"1.0.0"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		// Public auth routes (rate limited)
		r.With(rateMW.LimitByIP).Post("/auth/register", authHandler.Register)
		r.With(rateMW.LimitByIP).Post("/auth/login", authHandler.Login)
		r.Post("/auth/refresh", authHandler.Refresh)

		// Public tenant creation (for self-service onboarding)
		r.Post("/tenants", tenantHandler.Create)

		// Authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(authMW.Authenticate)

			r.Post("/auth/logout", authHandler.Logout)
			r.Post("/auth/logout-all", authHandler.LogoutAll)
			r.Get("/auth/me", authHandler.Me)

			// Users
			r.Get("/users", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"message":"list users - requires users:read permission"}`)
			})

			// RBAC
			r.Get("/roles", rbacHandler.ListRoles)
			r.With(middleware.RequirePermission("roles:write")).Post("/roles", rbacHandler.CreateRole)
			r.With(middleware.RequirePermission("roles:write")).Post("/users/{userID}/roles", rbacHandler.AssignRoleToUser)

			// Audit logs
			r.With(middleware.RequirePermission("audit:read")).Get("/audit-logs", auditHandler.List)

			// Tenants (admin only)
			r.With(middleware.RequireRole("admin")).Get("/tenants", tenantHandler.List)
		})
	})

	// ── Server ────────────────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Info().Str("port", cfg.Server.Port).Msg("goauth server starting")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	log.Info().Msg("shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	auditRepo.Shutdown(5 * time.Second)

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("server forced to shutdown")
	}
	log.Info().Msg("server stopped")
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
