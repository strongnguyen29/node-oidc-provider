package store

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/strongnguyen29/go-oidc-provider/internal/logging"
)

// loggingAdapter wraps an Adapter and emits a DEBUG-level log line for every
// store operation. It is intentionally small: production deployments only opt
// in to this when LogLevel="debug" because store traffic is high-volume and
// each entry adds a syscall + serialisation cost.
//
// The wrapper exposes the optional stringAppender behaviour (AppendString)
// when the wrapped adapter implements it, so grant-family bookkeeping stays
// on the atomic fast path. Without this passthrough the type assertion in
// internal/handlers/utils.go would silently fall back to read-modify-write.
type loggingAdapter struct {
	inner Adapter
	base  *slog.Logger
}

// NewLoggingAdapter returns an Adapter that wraps inner and logs each call at
// DEBUG level. base is used as the fallback logger when no per-request logger
// is present on the context (e.g. background eviction goroutines).
func NewLoggingAdapter(inner Adapter, base *slog.Logger) Adapter {
	if inner == nil {
		return nil
	}
	if base == nil {
		base = slog.Default()
	}
	la := &loggingAdapter{inner: inner, base: base}
	if _, ok := inner.(stringAppender); ok {
		return &loggingAppender{loggingAdapter: la}
	}
	return la
}

// stringAppender mirrors the optional interface defined in
// internal/handlers/utils.go. We declare it locally to avoid an import cycle
// (handlers imports store, not the other way round).
type stringAppender interface {
	AppendString(ctx context.Context, id, value string, expiresIn time.Duration) error
}

// loggingAppender is the loggingAdapter variant that preserves the optional
// AppendString fast path. Returned only when the wrapped Adapter exposes it.
type loggingAppender struct {
	*loggingAdapter
}

func (l *loggingAdapter) logger(ctx context.Context) *slog.Logger {
	if logger := logging.FromContext(ctx); logger != nil {
		return logger
	}
	return l.base
}

// keyPrefix returns the namespace portion of a store key (e.g. "code:abc123"
// → "code"). Logging only the prefix prevents accidentally writing tokens or
// session identifiers to log files while still allowing operators to see
// which family of records is being touched.
func keyPrefix(id string) string {
	if i := strings.IndexByte(id, ':'); i > 0 {
		return id[:i]
	}
	return id
}

func (l *loggingAdapter) Upsert(ctx context.Context, id string, payload interface{}, expiresIn time.Duration) error {
	err := l.inner.Upsert(ctx, id, payload, expiresIn)
	l.logger(ctx).LogAttrs(ctx, slog.LevelDebug, "store_op",
		slog.String("op", "upsert"),
		slog.String("key_prefix", keyPrefix(id)),
		slog.Int64("ttl_ms", expiresIn.Milliseconds()),
		slog.Bool("ok", err == nil),
	)
	return err
}

func (l *loggingAdapter) Find(ctx context.Context, id string) (interface{}, error) {
	v, err := l.inner.Find(ctx, id)
	l.logger(ctx).LogAttrs(ctx, slog.LevelDebug, "store_op",
		slog.String("op", "find"),
		slog.String("key_prefix", keyPrefix(id)),
		slog.Bool("hit", err == nil),
	)
	return v, err
}

func (l *loggingAdapter) Consume(ctx context.Context, id string) error {
	err := l.inner.Consume(ctx, id)
	l.logger(ctx).LogAttrs(ctx, slog.LevelDebug, "store_op",
		slog.String("op", "consume"),
		slog.String("key_prefix", keyPrefix(id)),
		slog.Bool("ok", err == nil),
	)
	return err
}

func (l *loggingAdapter) Destroy(ctx context.Context, id string) error {
	err := l.inner.Destroy(ctx, id)
	l.logger(ctx).LogAttrs(ctx, slog.LevelDebug, "store_op",
		slog.String("op", "destroy"),
		slog.String("key_prefix", keyPrefix(id)),
		slog.Bool("ok", err == nil),
	)
	return err
}

// AppendString delegates to the wrapped adapter's atomic implementation when
// available. The fast path is preserved so concurrent token issuance does
// not lose entries to a read-modify-write race.
func (l *loggingAppender) AppendString(ctx context.Context, id, value string, expiresIn time.Duration) error {
	err := l.inner.(stringAppender).AppendString(ctx, id, value, expiresIn)
	l.logger(ctx).LogAttrs(ctx, slog.LevelDebug, "store_op",
		slog.String("op", "append"),
		slog.String("key_prefix", keyPrefix(id)),
		slog.Int64("ttl_ms", expiresIn.Milliseconds()),
		slog.Bool("ok", err == nil),
	)
	return err
}
