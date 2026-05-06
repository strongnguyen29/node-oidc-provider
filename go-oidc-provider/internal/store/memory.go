package store

import (
"bytes"
"context"
"encoding/gob"
"fmt"
"sync"
"time"

"github.com/strongnguyen29/go-oidc-provider/internal/models"
)

func init() {
	// Register every concrete type that may travel through Find/Upsert so
	// gob can round-trip them via deep copy. Without registration the
	// generic interface{} encode would fail at runtime.
	gob.Register(&models.Session{})
	gob.Register(&models.ClientSession{})
	gob.Register(&models.Grant{})
	gob.Register(&models.AuthorizationCode{})
	gob.Register(&models.RefreshToken{})
	gob.Register(&models.DeviceCode{})
	gob.Register(&models.Interaction{})
	gob.Register(&models.InteractionResult{})
	gob.Register(&models.LoginResult{})
	gob.Register(&models.ConsentResult{})
	gob.Register([]string{})
	gob.Register(map[string]*models.ClientSession{})
}

type entry struct {
payload   interface{}
expiresAt time.Time
consumed  bool
}

// MemoryStore is a thread-safe in-memory adapter with TTL eviction.
type MemoryStore struct {
mu      sync.RWMutex
entries map[string]*entry
quit    chan struct{}
}

// NewMemoryStore creates a new MemoryStore and starts the eviction goroutine.
func NewMemoryStore() *MemoryStore {
s := &MemoryStore{
entries: make(map[string]*entry),
quit:    make(chan struct{}),
}
go s.evict()
return s
}

func (s *MemoryStore) evict() {
ticker := time.NewTicker(30 * time.Second)
defer ticker.Stop()
for {
select {
case <-ticker.C:
s.mu.Lock()
now := time.Now()
for k, e := range s.entries {
if now.After(e.expiresAt) {
delete(s.entries, k)
}
}
s.mu.Unlock()
case <-s.quit:
return
}
}
}

// Stop shuts down the background eviction goroutine.
// It should be called when the store is no longer needed to prevent goroutine leaks.
func (s *MemoryStore) Stop() {
close(s.quit)
}

func (s *MemoryStore) Upsert(_ context.Context, id string, payload interface{}, expiresIn time.Duration) error {
s.mu.Lock()
defer s.mu.Unlock()
s.entries[id] = &entry{
payload:   payload,
expiresAt: time.Now().Add(expiresIn),
}
return nil
}

func (s *MemoryStore) Find(_ context.Context, id string) (interface{}, error) {
s.mu.RLock()
defer s.mu.RUnlock()
e, ok := s.entries[id]
if !ok {
return nil, fmt.Errorf("not found: %s", id)
}
if time.Now().After(e.expiresAt) {
return nil, fmt.Errorf("expired: %s", id)
}
// Return a deep copy so callers can mutate the result without racing
// with concurrent Find/Upsert callers that share the same underlying
// pointer. When the payload type is not registered with gob (e.g. a
// local test type) the original value is returned: the deep-copy
// guarantee is best-effort and the gob registry above covers every
// concrete model used by the OIDC flows.
return deepCopy(e.payload), nil
}

// deepCopy serialises and reconstitutes v through gob so the caller receives
// an isolated value graph. Used by Find to prevent concurrent mutation of
// stored objects (sessions in particular are deeply nested and previously
// shared pointers across concurrent requests). Falls back to the original
// value when v's concrete type is not gob-registerable, so callers always
// get back something useful.
func deepCopy(v interface{}) interface{} {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&v); err != nil {
		return v
	}
	var out interface{}
	if err := gob.NewDecoder(&buf).Decode(&out); err != nil {
		return v
	}
	return out
}

func (s *MemoryStore) Consume(_ context.Context, id string) error {
s.mu.Lock()
defer s.mu.Unlock()
e, ok := s.entries[id]
if !ok {
return fmt.Errorf("not found: %s", id)
}
e.consumed = true
return nil
}

func (s *MemoryStore) Destroy(_ context.Context, id string) error {
s.mu.Lock()
defer s.mu.Unlock()
delete(s.entries, id)
return nil
}

// AppendString atomically appends value to the []string payload at id, creating
// the entry if it does not exist. Used by grant-family bookkeeping so that
// concurrent token issuance for the same grant cannot lose entries through a
// read-modify-write race.
func (s *MemoryStore) AppendString(_ context.Context, id, value string, expiresIn time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if e, ok := s.entries[id]; ok && now.Before(e.expiresAt) {
		list, _ := e.payload.([]string)
		e.payload = append(list, value)
		newExpiry := now.Add(expiresIn)
		if newExpiry.After(e.expiresAt) {
			e.expiresAt = newExpiry
		}
		return nil
	}
	s.entries[id] = &entry{
		payload:   []string{value},
		expiresAt: now.Add(expiresIn),
	}
	return nil
}
