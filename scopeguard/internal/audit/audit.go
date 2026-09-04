// Package audit provides an append-only, tamper-evident event log per
// engagement. Every host touched, tool run, agent action, scope decision and
// finding is written here with a timestamp. The log is JSON Lines so it streams
// cheaply and each line is independently parseable.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Event is one audit record. PrevHash + Hash form a hash chain so a deleted or
// altered line is detectable after the fact.
type Event struct {
	Time         time.Time      `json:"time"`
	EngagementID string         `json:"engagement_id"`
	Kind         string         `json:"kind"` // scope_decision | request | tool | agent | finding | note
	Actor        string         `json:"actor,omitempty"`
	Target       string         `json:"target,omitempty"`
	Allowed      *bool          `json:"allowed,omitempty"`
	Reason       string         `json:"reason,omitempty"`
	Detail       map[string]any `json:"detail,omitempty"`
	PrevHash     string         `json:"prev_hash"`
	Hash         string         `json:"hash"`
}

// Logger writes events to an io.Writer under a mutex, maintaining the hash chain.
type Logger struct {
	mu           sync.Mutex
	w            io.Writer
	engagementID string
	prev         string
}

// NewLogger writes to w. genesisHash seeds the chain (use "" for a fresh log).
func NewLogger(w io.Writer, engagementID string) *Logger {
	return &Logger{w: w, engagementID: engagementID, prev: "genesis"}
}

// Open appends to (or creates) a log file for the engagement.
func Open(path, engagementID string) (*Logger, io.Closer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return NewLogger(f, engagementID), f, nil
}

func hashEvent(e Event) string {
	// Hash the canonical content excluding the Hash field itself.
	e.Hash = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Log writes one event, filling in time, engagement, and chain hashes.
func (l *Logger) Log(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.EngagementID = l.engagementID
	e.PrevHash = l.prev
	e.Hash = hashEvent(e)
	l.prev = e.Hash
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(l.w, string(b)); err != nil {
		return err
	}
	return nil
}

// Decision is a convenience for the most common event: a scope check result.
func (l *Logger) Decision(actor, target string, allowed bool, reason string) error {
	return l.Log(Event{Kind: "scope_decision", Actor: actor, Target: target, Allowed: &allowed, Reason: reason})
}

// Verify re-reads a JSONL audit stream and confirms the hash chain is intact.
// It returns the number of records and the first broken line (0 if intact).
func Verify(r io.Reader) (records int, brokenLine int, err error) {
	dec := json.NewDecoder(r)
	prev := "genesis"
	line := 0
	for dec.More() {
		line++
		var e Event
		if err := dec.Decode(&e); err != nil {
			return records, line, err
		}
		if e.PrevHash != prev {
			return records, line, nil
		}
		if hashEvent(e) != e.Hash {
			return records, line, nil
		}
		prev = e.Hash
		records++
	}
	return records, 0, nil
}
