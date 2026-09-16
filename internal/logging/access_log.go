// Package logging provides structured access logging for the IAP. Every
// request that reaches the proxy's decision point gets one log entry,
// whether it was allowed or denied — this is the audit trail that makes
// "who accessed what, and why was it allowed" answerable after the fact,
// which is the whole point of centralizing access through an IAP instead
// of a flat VPN.
package logging

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Entry is one access decision record.
type Entry struct {
	Timestamp  time.Time `json:"timestamp"`
	Subject    string    `json:"subject"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	RemoteAddr string    `json:"remote_addr"`
	Allowed    bool      `json:"allowed"`
	Reason     string    `json:"reason"`
	PolicyID   string    `json:"policy_id,omitempty"`
	AuthMethod string    `json:"auth_method"` // "mtls" | "jwt"
	SPIFFEID   string    `json:"spiffe_id,omitempty"`
	LatencyMs  int64     `json:"latency_ms"`
	StatusCode int       `json:"status_code,omitempty"`
}

// Logger writes structured entries to a file (append-only JSON lines) and
// keeps a bounded in-memory ring buffer so the admin UI can query recent
// activity without re-reading the whole file on every request.
type Logger struct {
	mu      sync.Mutex
	file    *os.File
	ring    []Entry
	ringCap int
	ringPos int
	filled  bool
}

// NewLogger opens (creating if needed) the access log file at path and
// prepares an in-memory ring buffer of the given capacity.
func NewLogger(path string, ringCapacity int) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	if ringCapacity <= 0 {
		ringCapacity = 500
	}
	return &Logger{
		file:    f,
		ring:    make([]Entry, ringCapacity),
		ringCap: ringCapacity,
	}, nil
}

// Log appends an entry to the file and the ring buffer.
func (l *Logger) Log(e Entry) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.ring[l.ringPos] = e
	l.ringPos = (l.ringPos + 1) % l.ringCap
	if l.ringPos == 0 {
		l.filled = true
	}

	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = l.file.Write(b)
}

// Recent returns up to `limit` most-recent entries, newest first.
func (l *Logger) Recent(limit int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	var all []Entry
	if l.filled {
		all = append(all, l.ring[l.ringPos:]...)
		all = append(all, l.ring[:l.ringPos]...)
	} else {
		all = append(all, l.ring[:l.ringPos]...)
	}
	// reverse to newest-first
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	if limit > 0 && limit < len(all) {
		all = all[:limit]
	}
	return all
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}
