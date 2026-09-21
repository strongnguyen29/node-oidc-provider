package store

import (
"context"
"time"
)

// Adapter is the interface for persistence backends.
type Adapter interface {
Upsert(ctx context.Context, id string, payload interface{}, expiresIn time.Duration) error
Find(ctx context.Context, id string) (interface{}, error)
Consume(ctx context.Context, id string) error
Destroy(ctx context.Context, id string) error
}
