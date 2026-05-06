// Package store là public re-export của internal/store dành cho external
// consumer. Các type alias bảo toàn type identity với internal/store, do đó
// adapter tạo ra ở đây có thể truyền thẳng vào provider.New.
package store

import internal "github.com/strongnguyen29/go-oidc-provider/internal/store"

// Adapter is the interface every storage backend must implement.
type Adapter = internal.Adapter

// MemoryStore is the default in-memory adapter (volatile, single process).
type MemoryStore = internal.MemoryStore

// RedisClusterAdapter persists data in Redis (standalone or cluster).
type RedisClusterAdapter = internal.RedisClusterAdapter

// RedisClusterOptions configures a RedisClusterAdapter.
type RedisClusterOptions = internal.RedisClusterOptions

// NewMemoryStore returns a fresh in-memory adapter.
func NewMemoryStore() *MemoryStore {
	return internal.NewMemoryStore()
}

// NewRedisClusterAdapter creates an adapter backed by Redis. Pass a single
// address for standalone Redis or multiple addresses for Redis Cluster.
func NewRedisClusterAdapter(opts RedisClusterOptions) (*RedisClusterAdapter, error) {
	return internal.NewRedisClusterAdapter(opts)
}
