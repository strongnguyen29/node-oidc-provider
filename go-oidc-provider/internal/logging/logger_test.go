package logging_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/strongnguyen29/go-oidc-provider/internal/logging"
)

func TestLevelFromString(t *testing.T) {
	tests := []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{" debug ", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"weird", slog.LevelInfo},
	}
	for _, tt := range tests {
		if got := logging.LevelFromString(tt.in); got != tt.want {
			t.Errorf("LevelFromString(%q)=%v want %v", tt.in, got, tt.want)
		}
	}
}

func TestRedactToken(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "<empty>"},
		{"abc", "abc…"},
		{"abcdefgh", "abcdefgh…"},
		{"abcdefghij", "abcdefgh…"},
	}
	for _, tt := range tests {
		if got := logging.RedactToken(tt.in); got != tt.want {
			t.Errorf("RedactToken(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestContextRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	l := logging.NewWithWriter(&buf, "debug")
	ctx := logging.WithLogger(context.Background(), l)

	got := logging.FromContext(ctx)
	got.Info("hello", slog.String("x", "y"))

	if !strings.Contains(buf.String(), "hello") || !strings.Contains(buf.String(), "x=y") {
		t.Fatalf("expected log line to contain msg + attr, got: %s", buf.String())
	}
}

func TestFromContextFallsBackToDefault(t *testing.T) {
	if logging.FromContext(nil) == nil {
		t.Fatal("FromContext(nil) returned nil; expected slog.Default()")
	}
	if logging.FromContext(context.Background()) == nil {
		t.Fatal("FromContext(empty ctx) returned nil; expected slog.Default()")
	}
}

func TestDebugLevelEmitsDebug(t *testing.T) {
	var buf bytes.Buffer
	l := logging.NewWithWriter(&buf, "debug")
	l.Debug("dbg-msg")
	if !strings.Contains(buf.String(), "dbg-msg") {
		t.Fatalf("debug log not emitted at debug level: %s", buf.String())
	}
}

func TestInfoLevelSuppressesDebug(t *testing.T) {
	var buf bytes.Buffer
	l := logging.NewWithWriter(&buf, "info")
	l.Debug("dbg-msg")
	if strings.Contains(buf.String(), "dbg-msg") {
		t.Fatalf("debug log should be suppressed at info level: %s", buf.String())
	}
}
