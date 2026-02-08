package ratelimit

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"gohst/internal/db"
)

// ──────────────────────────────────────────────
// Rate-limit deny log
// ──────────────────────────────────────────────

// LogEntry is a single denied-request record.
type LogEntry struct {
	Method     string
	Path       string
	KeyType    string
	KeyHash    string
	Scope      string
	RetryAfter int
	ClientIP   string
}

// LogStore persists denied-request log entries.
type LogStore interface {
	Log(entry LogEntry) error
}

// ──────────────────────────────────────────────
// Database log store (PostgreSQL)
// ──────────────────────────────────────────────

// DBLogStore writes denied-request records to the rate_limit_logs table.
type DBLogStore struct {
	db *sql.DB
}

// NewDBLogStore creates a database-backed log store using the primary DB.
func NewDBLogStore() *DBLogStore {
	primary := db.GetPrimaryDB()
	if primary == nil {
		log.Println("[ratelimit] warning: no primary DB available for log store")
		return &DBLogStore{}
	}
	return &DBLogStore{db: primary.DB}
}

// Log inserts a denied-request entry.
func (s *DBLogStore) Log(entry LogEntry) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}

	query := `
		INSERT INTO rate_limit_logs (method, path, key_type, key_hash, scope, retry_after, client_ip, denied_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := s.db.Exec(query,
		entry.Method,
		entry.Path,
		entry.KeyType,
		entry.KeyHash,
		entry.Scope,
		entry.RetryAfter,
		entry.ClientIP,
		time.Now().UTC(),
	)
	return err
}

// ──────────────────────────────────────────────
// No-op log store (discard)
// ──────────────────────────────────────────────

// NopLogStore discards all log entries. Used when DB logging is disabled.
type NopLogStore struct{}

func (NopLogStore) Log(_ LogEntry) error { return nil }
