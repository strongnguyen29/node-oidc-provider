// Package logging provides a small structured-logging facade over log/slog
// for the OIDC provider. It owns three concerns:
//
//  1. Building a *slog.Logger from a string level (config.Config.LogLevel).
//  2. Threading a per-request logger through context.Context so handlers can
//     emit log lines stamped with the active request_id without changing
//     constructor signatures.
//  3. Centralised redaction helpers for security-sensitive values
//     (authorization codes, refresh tokens, jti, …) so call sites cannot
//     accidentally log raw secrets.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// LevelFromString converts the provider's textual LogLevel ("debug", "info",
// "warn", "error") into an slog.Level. Unknown values fall back to info.
func LevelFromString(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// New builds a *slog.Logger writing text-format records to stderr at the given
// level. Stderr is the conventional destination for server logs so stdout
// remains free for structured data such as health-check probes.
func New(level string) *slog.Logger {
	return NewWithWriter(os.Stderr, level)
}

// NewWithWriter is the test-friendly variant of New that lets callers redirect
// log output to an arbitrary writer.
func NewWithWriter(w io.Writer, level string) *slog.Logger {
	h := slog.NewTextHandler(w, &slog.HandlerOptions{Level: LevelFromString(level)})
	return slog.New(h)
}

type loggerCtxKey struct{}

// WithLogger returns a copy of ctx that carries logger so it can be retrieved
// by FromContext anywhere downstream of the RequestLogger middleware.
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	if logger == nil {
		return ctx
	}
	return context.WithValue(ctx, loggerCtxKey{}, logger)
}

// FromContext returns the *slog.Logger stored on ctx by the RequestLogger
// middleware. When no logger is present (tests, raw handler invocation), the
// process-wide slog default is returned so callers never have to nil-check.
func FromContext(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return slog.Default()
	}
	if l, ok := ctx.Value(loggerCtxKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// RedactToken returns a short, log-safe representation of a token-like value:
// the first 8 characters followed by an ellipsis. Empty input becomes the
// literal "<empty>" so absence is distinguishable from presence in log output.
// Use this for authorization codes, jti, refresh-token IDs, device codes, and
// anything else whose raw value an attacker could replay if it leaked into
// log files.
func RedactToken(s string) string {
	if s == "" {
		return "<empty>"
	}
	const keep = 8
	if len(s) <= keep {
		return s + "…"
	}
	return s[:keep] + "…"
}
