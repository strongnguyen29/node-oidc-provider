package middleware

import (
	"log/slog"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/strongnguyen29/go-oidc-provider/internal/logging"
)

// requestIDHeader is the HTTP header used for cross-service correlation. The
// middleware honours an inbound value so a calling proxy / load balancer can
// stitch the provider's logs into a wider trace; otherwise a UUID is
// generated locally.
const requestIDHeader = "X-Request-ID"

// RequestLogger returns a chi middleware that:
//
//  1. Extracts (or mints) a request ID and echoes it back on the response so
//     callers can correlate logs across services.
//  2. Builds a per-request *slog.Logger, attaches it to the request context
//     via logging.WithLogger, and emits an INFO "http_request" access-log
//     line on completion with the response status, byte count and duration.
//
// All downstream handlers and middleware should retrieve the logger via
// logging.FromContext(r.Context()) so every line they emit is automatically
// stamped with request_id, method and path.
func RequestLogger(base *slog.Logger) func(http.Handler) http.Handler {
	if base == nil {
		base = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := r.Header.Get(requestIDHeader)
			if reqID == "" {
				reqID = uuid.New().String()
			}
			w.Header().Set(requestIDHeader, reqID)

			reqLogger := base.With(
				slog.String("request_id", reqID),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
			)

			ctx := logging.WithLogger(r.Context(), reqLogger)

			// chi's WrapResponseWriter captures status code and bytes written
			// without us having to re-implement the http.ResponseWriter
			// optional interfaces (Flusher, Hijacker, Pusher).
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

			start := time.Now()
			next.ServeHTTP(ww, r.WithContext(ctx))
			elapsed := time.Since(start)

			status := ww.Status()
			if status == 0 {
				// Handler returned without writing — net/http defaults to 200.
				status = http.StatusOK
			}

			reqLogger.LogAttrs(ctx, slog.LevelInfo, "http_request",
				slog.Int("status", status),
				slog.Int("bytes", ww.BytesWritten()),
				slog.Int64("duration_ms", elapsed.Milliseconds()),
				slog.String("remote_addr", clientIP(r)),
			)
		})
	}
}

// clientIP returns a best-effort remote address for access-log purposes. It
// prefers the first entry of X-Forwarded-For (when set by a trusted proxy)
// and falls back to RemoteAddr. No spoofing protection is applied here — the
// caller is expected to deploy the provider behind a proxy it trusts to
// rewrite the header, or to scrub it at ingress.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the leftmost entry; X-Forwarded-For is comma-separated.
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	return r.RemoteAddr
}
