package rbac

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/saurabhkumar/goauth/internal/domain"
	"github.com/saurabhkumar/goauth/internal/middleware"
	"github.com/saurabhkumar/goauth/internal/repository/postgres"
)

type Service struct {
	repo *postgres.RBACRepository
}

func NewService(repo *postgres.RBACRepository) *Service {
	return &Service{repo: repo}
}

func (s *Service) CreateRole(ctx context.Context, tenantID uuid.UUID, name, desc string) (*domain.Role, error) {
	role := &domain.Role{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        name,
		Description: desc,
	}
	if err := s.repo.CreateRole(ctx, role); err != nil {
		return nil, err
	}
	return role, nil
}

func (s *Service) ListRoles(ctx context.Context, tenantID uuid.UUID) ([]domain.Role, error) {
	return s.repo.ListRoles(ctx, tenantID)
}

func (s *Service) AssignRole(ctx context.Context, userID, roleID uuid.UUID) error {
	return s.repo.AssignRoleToUser(ctx, userID, roleID)
}

func (s *Service) RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error {
	return s.repo.RemoveRoleFromUser(ctx, userID, roleID)
}

// Handler wires RBAC HTTP routes.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	roles, err := h.svc.ListRoles(r.Context(), claims.TenantID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respond(w, http.StatusOK, roles)
}

func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}
	role, err := h.svc.CreateRole(r.Context(), claims.TenantID, req.Name, req.Description)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respond(w, http.StatusCreated, role)
}

func (h *Handler) AssignRoleToUser(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	var req struct {
		RoleID uuid.UUID `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := h.svc.AssignRole(r.Context(), userID, req.RoleID); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respond(w, http.StatusOK, map[string]string{"message": "role assigned"})
}

// SeedDefaultRoles seeds standard roles for a new tenant.
func SeedDefaultRoles(ctx context.Context, repo *postgres.RBACRepository, tenantID uuid.UUID) error {
	roles := []domain.Role{
		{ID: uuid.New(), TenantID: tenantID, Name: "admin", Description: "Full access"},
		{ID: uuid.New(), TenantID: tenantID, Name: "editor", Description: "Read and write"},
		{ID: uuid.New(), TenantID: tenantID, Name: "viewer", Description: "Read only"},
	}
	for _, r := range roles {
		_ = repo.CreateRole(ctx, &r)
	}
	return nil
}

func respond(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}

// Unused import guard
var _ = time.Now
