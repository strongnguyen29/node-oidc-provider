package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/strongnguyen29/go-oidc-provider/internal/models"
)

// RedisClusterAdapter implements Adapter using a Redis Cluster (or a single
// standalone Redis node).  Every value is stored as a JSON object that
// contains the concrete Go type name alongside the actual payload so that
// Find can deserialize back to the right struct pointer.
//
// Key layout (mirrors the in-memory store):
//
//	"session:<id>"        → *models.Session
//	"code:<code>"         → *models.AuthorizationCode
//	"rt:<id>"             → *models.RefreshToken
//	"device:<code>"       → *models.DeviceCode
//	"usercode:<code>"     → string  (raw device-code value)
//	"grant:<id>"          → *models.Grant
//	"interaction:<uid>"   → *models.Interaction
//	"at:<jti>"            → *accessTokenEntry  (opaque revocation marker)
type RedisClusterAdapter struct {
	client redis.UniversalClient
}

// RedisClusterOptions configures a RedisClusterAdapter.
type RedisClusterOptions struct {
	// Addrs is the list of cluster node addresses (host:port).
	// For a single-node / sentinel setup, provide just one address.
	Addrs []string

	// Password for Redis AUTH.
	Password string

	// DB is the database index (only used for single-node / sentinel mode;
	// Redis Cluster always uses DB 0).
	DB int

	// PoolSize is the number of connections per node.  Defaults to
	// runtime.NumCPU * 10 when set to 0.
	PoolSize int

	// DialTimeout / ReadTimeout / WriteTimeout for network operations.
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// NewRedisClusterAdapter creates an adapter backed by Redis.
// When len(opts.Addrs) > 1 a ClusterClient is used; otherwise a single-node
// Client is created so the same constructor works for both topologies.
func NewRedisClusterAdapter(opts RedisClusterOptions) (*RedisClusterAdapter, error) {
	if len(opts.Addrs) == 0 {
		return nil, fmt.Errorf("redis_cluster: at least one address is required")
	}

	uopts := &redis.UniversalOptions{
		Addrs:        opts.Addrs,
		Password:     opts.Password,
		DB:           opts.DB,
		PoolSize:     opts.PoolSize,
		DialTimeout:  opts.DialTimeout,
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
	}

	client := redis.NewUniversalClient(uopts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis_cluster: ping failed: %w", err)
	}

	return &RedisClusterAdapter{client: client}, nil
}

// Close releases the underlying Redis connection pool.
func (a *RedisClusterAdapter) Close() error {
	return a.client.Close()
}

// ---------------------------------------------------------------------------
// wire format stored in Redis
// ---------------------------------------------------------------------------

type redisEntry struct {
	// Type is the fully-qualified Go type name used to pick the right
	// concrete struct during deserialization (e.g. "*models.Session").
	Type string `json:"type"`
	// Consumed mirrors the Consumed flag on tokens; kept out-of-band so
	// Find can read it without re-serializing the whole payload.
	Consumed bool `json:"consumed"`
	// Payload is the JSON-encoded concrete value.
	Payload json.RawMessage `json:"payload"`
}

// ---------------------------------------------------------------------------
// Adapter interface
// ---------------------------------------------------------------------------

// Upsert stores payload under id with the given TTL.
// The value is JSON-encoded and tagged with its concrete Go type so that
// Find can reconstruct the original struct.
func (a *RedisClusterAdapter) Upsert(ctx context.Context, id string, payload interface{}, expiresIn time.Duration) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("redis_cluster upsert marshal: %w", err)
	}

	entry := redisEntry{
		Type:    typeName(payload),
		Payload: data,
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("redis_cluster upsert marshal entry: %w", err)
	}

	return a.client.Set(ctx, id, raw, expiresIn).Err()
}

// Find retrieves and deserializes the value stored under id.
// It returns an error when the key is absent or has expired (Redis handles
// TTL expiry natively, so a missing key always means "not found or expired").
func (a *RedisClusterAdapter) Find(ctx context.Context, id string) (interface{}, error) {
	raw, err := a.client.Get(ctx, id).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("redis_cluster find: %w", err)
	}

	var entry redisEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, fmt.Errorf("redis_cluster find unmarshal entry: %w", err)
	}

	return deserializePayload(entry.Type, entry.Payload)
}

// Consume marks the token stored under id as consumed without deleting it.
// This preserves the entry so replay-detection (checking the Consumed flag)
// still works until the natural TTL expires.
func (a *RedisClusterAdapter) Consume(ctx context.Context, id string) error {
	raw, err := a.client.Get(ctx, id).Bytes()
	if err == redis.Nil {
		return fmt.Errorf("not found: %s", id)
	}
	if err != nil {
		return fmt.Errorf("redis_cluster consume get: %w", err)
	}

	var entry redisEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return fmt.Errorf("redis_cluster consume unmarshal: %w", err)
	}

	entry.Consumed = true

	// Propagate the consumed flag into the inner payload where the struct
	// has a Consumed field (AuthorizationCode, RefreshToken).
	updatedPayload, err := setConsumedField(entry.Type, entry.Payload)
	if err == nil {
		entry.Payload = updatedPayload
	}

	updated, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("redis_cluster consume marshal: %w", err)
	}

	// Preserve the remaining TTL.
	ttl, err := a.client.PTTL(ctx, id).Result()
	if err != nil || ttl <= 0 {
		ttl = 0 // will be stored without expiry if we can't determine it
	}

	return a.client.Set(ctx, id, updated, ttl).Err()
}

// Destroy deletes the key from Redis immediately.
func (a *RedisClusterAdapter) Destroy(ctx context.Context, id string) error {
	return a.client.Del(ctx, id).Err()
}

// ---------------------------------------------------------------------------
// type registry helpers
// ---------------------------------------------------------------------------

// typeName returns a stable string identifier for the concrete type behind
// payload so we can select the right target during deserialization.
func typeName(payload interface{}) string {
	switch payload.(type) {
	case *models.Session:
		return "Session"
	case *models.AuthorizationCode:
		return "AuthorizationCode"
	case *models.RefreshToken:
		return "RefreshToken"
	case *models.DeviceCode:
		return "DeviceCode"
	case *models.Grant:
		return "Grant"
	case *models.Interaction:
		return "Interaction"
	case string:
		return "string"
	default:
		return "unknown"
	}
}

// deserializePayload decodes data into the concrete struct indicated by typ.
func deserializePayload(typ string, data json.RawMessage) (interface{}, error) {
	switch typ {
	case "Session":
		var v models.Session
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("redis_cluster deserialize Session: %w", err)
		}
		return &v, nil
	case "AuthorizationCode":
		var v models.AuthorizationCode
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("redis_cluster deserialize AuthorizationCode: %w", err)
		}
		return &v, nil
	case "RefreshToken":
		var v models.RefreshToken
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("redis_cluster deserialize RefreshToken: %w", err)
		}
		return &v, nil
	case "DeviceCode":
		var v models.DeviceCode
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("redis_cluster deserialize DeviceCode: %w", err)
		}
		return &v, nil
	case "Grant":
		var v models.Grant
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("redis_cluster deserialize Grant: %w", err)
		}
		return &v, nil
	case "Interaction":
		var v models.Interaction
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("redis_cluster deserialize Interaction: %w", err)
		}
		return &v, nil
	case "string":
		var v string
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("redis_cluster deserialize string: %w", err)
		}
		return v, nil
	default:
		// Fallback: return raw map for unknown types.
		var v interface{}
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("redis_cluster deserialize unknown: %w", err)
		}
		return v, nil
	}
}

// setConsumedField re-encodes the payload with Consumed = true for structs
// that carry that field (AuthorizationCode, RefreshToken).
func setConsumedField(typ string, data json.RawMessage) (json.RawMessage, error) {
	switch typ {
	case "AuthorizationCode":
		var v models.AuthorizationCode
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, err
		}
		v.Consumed = true
		return json.Marshal(v)
	case "RefreshToken":
		var v models.RefreshToken
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, err
		}
		v.Consumed = true
		return json.Marshal(v)
	default:
		return data, nil
	}
}
