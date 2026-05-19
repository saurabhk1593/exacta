package audit

import (
	"net/http"
	"strconv"

	"github.com/saurabhkumar/goauth/internal/middleware"
	"github.com/saurabhkumar/goauth/internal/repository/postgres"
	"encoding/json"
)

type Handler struct {
	repo *postgres.AuditRepository
}

func NewHandler(repo *postgres.AuditRepository) *Handler {
	return &Handler{repo: repo}
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())

	limit := 50
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 200 {
			limit = v
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	events, err := h.repo.Query(r.Context(), claims.TenantID, limit, offset)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":   events,
		"limit":  limit,
		"offset": offset,
	})
}
