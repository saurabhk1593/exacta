package tenant

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/saurabhkumar/goauth/internal/domain"
	"github.com/saurabhkumar/goauth/internal/repository/postgres"
)

type Service struct {
	repo *postgres.TenantRepository
}

func NewService(repo *postgres.TenantRepository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Create(ctx context.Context, name, slug, plan string) (*domain.Tenant, error) {
	now := time.Now()
	t := &domain.Tenant{
		ID:        uuid.New(),
		Name:      name,
		Slug:      strings.ToLower(slug),
		Plan:      plan,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.repo.Create(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Service) List(ctx context.Context) ([]domain.Tenant, error) {
	return s.repo.List(ctx)
}

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
		Plan string `json:"plan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Plan == "" {
		req.Plan = "free"
	}
	t, err := h.svc.Create(r.Context(), req.Name, req.Slug, req.Plan)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respond(w, http.StatusCreated, t)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.svc.List(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respond(w, http.StatusOK, tenants)
}

func respond(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}
