package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantSlug string `json:"tenant_slug"`
		Email      string `json:"email"`
		Password   string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" || req.Password == "" || req.TenantSlug == "" {
		respondError(w, http.StatusBadRequest, "tenant_slug, email, and password are required")
		return
	}
	if len(req.Password) < 8 {
		respondError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	user, err := h.svc.Register(r.Context(), RegisterInput{
		TenantSlug: req.TenantSlug,
		Email:      req.Email,
		Password:   req.Password,
		IP:         realIP(r),
		UserAgent:  r.UserAgent(),
	})
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respond(w, http.StatusCreated, map[string]interface{}{
		"id":         user.ID,
		"email":      user.Email,
		"tenant_id":  user.TenantID,
		"created_at": user.CreatedAt,
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantSlug string `json:"tenant_slug"`
		Email      string `json:"email"`
		Password   string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	pair, err := h.svc.Login(r.Context(), LoginInput{
		TenantSlug: req.TenantSlug,
		Email:      req.Email,
		Password:   req.Password,
		IP:         realIP(r),
		UserAgent:  r.UserAgent(),
	})
	if err != nil {
		switch err {
		case ErrRateLimited:
			respondError(w, http.StatusTooManyRequests, err.Error())
		case ErrAccountDisabled:
			respondError(w, http.StatusForbidden, err.Error())
		default:
			respondError(w, http.StatusUnauthorized, ErrInvalidCredentials.Error())
		}
		return
	}

	respond(w, http.StatusOK, pair)
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	pair, err := h.svc.Refresh(r.Context(), req.RefreshToken, realIP(r), r.UserAgent())
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}

	respond(w, http.StatusOK, pair)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	accessToken := bearerToken(r)
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if err := h.svc.Logout(r.Context(), accessToken, req.RefreshToken, realIP(r), r.UserAgent()); err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	respond(w, http.StatusOK, map[string]string{"message": "logged out"})
}

func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	accessToken := bearerToken(r)
	if err := h.svc.LogoutAll(r.Context(), accessToken, realIP(r), r.UserAgent()); err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	respond(w, http.StatusOK, map[string]string{"message": "all sessions revoked"})
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	// Claims injected by auth middleware
	claims := claimsFromContext(r.Context())
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	respond(w, http.StatusOK, map[string]interface{}{
		"user_id":     claims.UserID,
		"tenant_id":   claims.TenantID,
		"tenant_slug": claims.TenantSlug,
		"roles":       claims.Roles,
		"permissions": claims.Permissions,
	})
}

func respond(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
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
