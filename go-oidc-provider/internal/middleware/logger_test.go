package middleware_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/strongnguyen29/go-oidc-provider/internal/logging"
	"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
)

func TestRequestLogger_AddsRequestIDHeader(t *testing.T) {
	var buf bytes.Buffer
	h := middleware.RequestLogger(logging.NewWithWriter(&buf, "info"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got == "" {
		t.Fatal("expected X-Request-ID to be set on response")
	}
	if !strings.Contains(buf.String(), "http_request") {
		t.Fatalf("expected access log line, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "status=204") {
		t.Fatalf("expected status=204 in log, got: %s", buf.String())
	}
}

func TestRequestLogger_HonoursInboundRequestID(t *testing.T) {
	var buf bytes.Buffer
	h := middleware.RequestLogger(logging.NewWithWriter(&buf, "info"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Request-ID", "trace-abc-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got != "trace-abc-123" {
		t.Fatalf("expected inbound X-Request-ID to be echoed, got %q", got)
	}
	if !strings.Contains(buf.String(), "trace-abc-123") {
		t.Fatalf("expected request_id=trace-abc-123 in log, got: %s", buf.String())
	}
}

func TestRequestLogger_InjectsLoggerIntoContext(t *testing.T) {
	var buf bytes.Buffer
	h := middleware.RequestLogger(logging.NewWithWriter(&buf, "debug"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logging.FromContext(r.Context()).Info("from_handler", "k", "v")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(buf.String(), "from_handler") || !strings.Contains(buf.String(), "k=v") {
		t.Fatalf("expected handler log to be emitted via context logger, got: %s", buf.String())
	}
}
