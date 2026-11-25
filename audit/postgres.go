package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os/user"
	"strings"
	"time"
)

// Handle implements Auditor. Database failures are logged rather than causing
// log.Fatal, because audit availability must not terminate decryption.
func (p *PostgresAuditor) Handle(event interface{}) {
	if p == nil || p.DB == nil {
		log.Warn("Audit Postgres backend is not initialized")
		return
	}
	e := NormalizeEvent(event)
	if p.Redactor != nil {
		e = p.Redactor.RedactEvent(e)
	}
	if err := p.SaveAuditEvent(context.Background(), e); err != nil {
		log.WithField("error", err).Warn("Failed to insert audit record")
	}
}

// Save persists one canonical event. Repeating an event with the same ID uses
// ON CONFLICT DO NOTHING, making retries and duplicate submission idempotent.
func (p *PostgresAuditor) SaveAuditEvent(ctx context.Context, event Event) error {
	if p == nil || p.DB == nil {
		return fmt.Errorf("postgres audit backend is not initialized")
	}
	if p.Redactor != nil {
		event = p.Redactor.RedactEvent(event)
	} else {
		event = DefaultRedactor().RedactEvent(event)
	}
	event = event.Normalize()

	username := event.Username
	if username == "" {
		username = currentUsername()
	}

	var details any
	if len(event.Details) > 0 {
		b, err := json.Marshal(event.Details)
		if err != nil {
			return fmt.Errorf("marshal audit details: %w", err)
		}
		details = b
	}

	const query = `
INSERT INTO audit_event
	(event_id, timestamp, action, username, file, key_group_id, result, details)
VALUES
	($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (event_id) DO NOTHING`
	_, err := p.DB.ExecContext(ctx, query,
		event.ID,
		event.Timestamp,
		event.Action,
		nullString(username),
		event.File,
		nullString(event.KeyGroupID),
		event.Result,
		details,
	)
	if err != nil {
		return fmt.Errorf("insert audit record: %w", err)
	}
	return nil
}

// SaveEvent is an alternate name for SaveAuditEvent.
func (p *PostgresAuditor) SaveEvent(ctx context.Context, event Event) error {
	return p.SaveAuditEvent(ctx, event)
}

// Save accepts either a canonical Event or one of the legacy event structs.
func (p *PostgresAuditor) Save(ctx context.Context, event any) error {
	return p.SaveAuditEvent(ctx, NormalizeEvent(event))
}

// QueryFilter constrains audit event queries. File and Action are the primary
// operational filters and are covered by the schema index.
type QueryFilter struct {
	File       string
	FilePath   string
	Action     string
	Operation  string
	KeyGroupID string
	Result     string
	Username   string
	From       time.Time
	StartTime  time.Time
	To         time.Time
	EndTime    time.Time
	Limit      int
	Offset     int
}

// AuditFilter is an alternate name for QueryFilter.
type AuditFilter = QueryFilter

// QueryEvents returns matching audit events.
func (p *PostgresAuditor) QueryEvents(ctx context.Context, filter QueryFilter) ([]Event, error) {
	if p == nil || p.DB == nil {
		return nil, fmt.Errorf("postgres audit backend is not initialized")
	}
	filter.File = firstNonEmpty(filter.File, filter.FilePath)
	filter.FilePath = filter.File
	filter.Action = firstNonEmpty(filter.Action, filter.Operation)
	filter.Operation = filter.Action
	filter.From = firstTime(filter.From, filter.StartTime)
	filter.StartTime = filter.From
	filter.To = firstTime(filter.To, filter.EndTime)
	filter.EndTime = filter.To

	var where []string
	var args []any
	add := func(condition string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(condition, len(args)))
	}
	if filter.File != "" {
		add("file = $%d", filter.File)
	}
	if filter.Action != "" {
		add("action = $%d", filter.Action)
	}
	if filter.KeyGroupID != "" {
		add("key_group_id = $%d", filter.KeyGroupID)
	}
	if filter.Result != "" {
		add("result = $%d", filter.Result)
	}
	if filter.Username != "" {
		add("username = $%d", filter.Username)
	}
	if !filter.From.IsZero() {
		add("timestamp >= $%d", filter.From.UTC())
	}
	if !filter.To.IsZero() {
		add("timestamp <= $%d", filter.To.UTC())
	}

	query := `
SELECT event_id, timestamp, action, username, file, key_group_id, result, details
FROM audit_event`
	if len(where) > 0 {
		query += "\nWHERE " + strings.Join(where, " AND ")
	}
	query += "\nORDER BY timestamp DESC, id DESC"
	if filter.Limit > 0 {
		args = append(args, filter.Limit)
		query += fmt.Sprintf("\nLIMIT $%d", len(args))
	}
	if filter.Offset > 0 {
		args = append(args, filter.Offset)
		query += fmt.Sprintf("\nOFFSET $%d", len(args))
	}

	rows, err := p.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var (
			id, action, file, result string
			timestamp                time.Time
			username, keyGroupID     sql.NullString
			detailsJSON              []byte
		)
		if err := rows.Scan(&id, &timestamp, &action, &username, &file, &keyGroupID, &result, &detailsJSON); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		e := Event{
			ID:         id,
			EventID:    id,
			Action:     action,
			File:       file,
			Timestamp:  timestamp.UTC(),
			Result:     result,
			Username:   username.String,
			KeyGroupID: keyGroupID.String,
		}
		if len(detailsJSON) > 0 && string(detailsJSON) != "null" {
			if err := json.Unmarshal(detailsJSON, &e.Details); err != nil {
				return nil, fmt.Errorf("unmarshal audit details for %s: %w", id, err)
			}
		}
		events = append(events, e.Canonical())
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return events, nil
}

// QueryAuditEvents is an alternate name for QueryEvents.
func (p *PostgresAuditor) QueryAuditEvents(ctx context.Context, filter QueryFilter) ([]Event, error) {
	return p.QueryEvents(ctx, filter)
}

// ListEvents is an alternate name for QueryEvents.
func (p *PostgresAuditor) ListEvents(ctx context.Context, filter QueryFilter) ([]Event, error) {
	return p.QueryEvents(ctx, filter)
}

// DeleteOlderThan deletes events older than now-RetentionPeriod. It returns
// the number deleted. Call it daily or from an external scheduler.
func (p *PostgresAuditor) DeleteOlderThan(ctx context.Context, now time.Time, retention time.Duration) (int64, error) {
	if p == nil || p.DB == nil {
		return 0, fmt.Errorf("postgres audit backend is not initialized")
	}
	if retention <= 0 {
		retention = DefaultRetention
	}
	cutoff := now.UTC().Add(-retention)
	result, err := p.DB.ExecContext(ctx, `DELETE FROM audit_event WHERE timestamp < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete expired audit events: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read deleted audit event count: %w", err)
	}
	return n, nil
}

// DeleteExpired applies the default 180-day retention window.
func (p *PostgresAuditor) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	retention := DefaultRetention
	if p != nil && p.Retention > 0 {
		retention = p.Retention
	}
	return p.DeleteOlderThan(ctx, now, retention)
}

func currentUsername() string {
	u, err := user.Current()
	if err != nil || u == nil {
		return "unknown"
	}
	return u.Username
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
