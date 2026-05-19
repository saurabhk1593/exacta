package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
	"github.com/saurabhkumar/goauth/internal/domain"
)

type AuditRepository struct {
	db     *sqlx.DB
	buffer chan domain.AuditEvent
	done   chan struct{}
}

func NewAuditRepository(db *sqlx.DB) *AuditRepository {
	r := &AuditRepository{
		db:     db,
		buffer: make(chan domain.AuditEvent, 512),
		done:   make(chan struct{}),
	}
	go r.worker()
	return r
}

// Log enqueues an audit event asynchronously — never blocks the hot path.
func (r *AuditRepository) Log(tenantID uuid.UUID, userID *uuid.UUID, action, ip, ua, meta string) {
	event := domain.AuditEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		Action:    action,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  meta,
		CreatedAt: time.Now(),
	}
	select {
	case r.buffer <- event:
	default:
		// Buffer full — drop and log. Acceptable tradeoff documented in runbook.
		log.Warn().Str("action", action).Msg("audit buffer full, event dropped")
	}
}

func (r *AuditRepository) Query(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]domain.AuditEvent, error) {
	var events []domain.AuditEvent
	err := r.db.SelectContext(ctx, &events, `
		SELECT * FROM audit_logs
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`,
		tenantID, limit, offset)
	return events, err
}

// Shutdown drains the buffer gracefully.
func (r *AuditRepository) Shutdown(timeout time.Duration) {
	close(r.buffer)
	select {
	case <-r.done:
	case <-time.After(timeout):
		log.Warn().Msg("audit shutdown timed out")
	}
}

// worker batch-inserts events every 100ms or every 100 events.
func (r *AuditRepository) worker() {
	defer close(r.done)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]domain.AuditEvent, 0, 100)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx := context.Background()
		_, err := r.db.NamedExecContext(ctx, `
			INSERT INTO audit_logs (id, tenant_id, user_id, action, ip_address, user_agent, metadata, created_at)
			VALUES (:id, :tenant_id, :user_id, :action, :ip_address, :user_agent, :metadata, :created_at)`,
			batch)
		if err != nil {
			log.Error().Err(err).Int("count", len(batch)).Msg("audit batch insert failed")
		}
		batch = batch[:0]
	}

	for {
		select {
		case event, ok := <-r.buffer:
			if !ok {
				flush()
				return
			}
			batch = append(batch, event)
			if len(batch) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
