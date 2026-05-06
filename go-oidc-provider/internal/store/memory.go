package store

import (
"context"
"fmt"
"sync"
"time"
)

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
return e.payload, nil
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
