package middleware_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/strongnguyen29/go-oidc-provider/internal/config"
	"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func testClient() config.ClientConfig {
	return config.ClientConfig{
		ID:                      "test-client",
		Secret:                  "test-secret",
		TokenEndpointAuthMethod: "client_secret_basic",
	}
}

func testConfig(client config.ClientConfig) *config.Config {
	return &config.Config{
		Clients: []config.ClientConfig{client},
	}
}

func basicAuthHeader(id, secret string) string {
	creds := base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
	return "Basic " + creds
}

// ---------------------------------------------------------------------------
// ClientAuthMiddleware — Basic auth
// ---------------------------------------------------------------------------

func TestClientAuth_BasicAuth_Valid(t *testing.T) {
	client := testClient()
	cfg := testConfig(client)

	reached := false
	handler := middleware.ClientAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		c := middleware.ClientFromContext(r.Context())
		if c == nil {
			t.Error("expected client in context")
		}
		if c != nil && c.ID != "test-client" {
			t.Errorf("expected client ID=test-client, got %s", c.ID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/token", nil)
	req.Header.Set("Authorization", basicAuthHeader("test-client", "test-secret"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !reached {
		t.Error("inner handler was not reached")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestClientAuth_BasicAuth_WrongSecret(t *testing.T) {
	client := testClient()
	cfg := testConfig(client)

	handler := middleware.ClientAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be reached with wrong secret")
	}))

	req := httptest.NewRequest("POST", "/token", nil)
	req.Header.Set("Authorization", basicAuthHeader("test-client", "wrong-secret"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestClientAuth_BasicAuth_UnknownClient(t *testing.T) {
	cfg := testConfig(testClient())

	handler := middleware.ClientAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be reached for unknown client")
	}))

	req := httptest.NewRequest("POST", "/token", nil)
	req.Header.Set("Authorization", basicAuthHeader("unknown-client", "secret"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// ClientAuthMiddleware — form parameters
// ---------------------------------------------------------------------------

func TestClientAuth_FormParams_Valid(t *testing.T) {
	client := testClient()
	cfg := testConfig(client)

	reached := false
	handler := middleware.ClientAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		c := middleware.ClientFromContext(r.Context())
		if c == nil || c.ID != "test-client" {
			t.Errorf("expected client test-client in context, got %v", c)
		}
		w.WriteHeader(http.StatusOK)
	}))

	body := url.Values{
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !reached {
		t.Error("inner handler was not reached")
	}
}

func TestClientAuth_FormParams_WrongSecret(t *testing.T) {
	cfg := testConfig(testClient())

	handler := middleware.ClientAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be reached with wrong secret")
	}))

	body := url.Values{
		"client_id":     {"test-client"},
		"client_secret": {"bad-secret"},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// ClientAuthMiddleware — public client (TokenEndpointAuthMethod = "none")
// ---------------------------------------------------------------------------

func TestClientAuth_PublicClient_NoSecretRequired(t *testing.T) {
	client := config.ClientConfig{
		ID:                      "public-client",
		Secret:                  "",
		TokenEndpointAuthMethod: "none",
	}
	cfg := testConfig(client)

	reached := false
	handler := middleware.ClientAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	body := url.Values{"client_id": {"public-client"}}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !reached {
		t.Error("public client should be allowed without a secret")
	}
}

// ---------------------------------------------------------------------------
// ClientFromContext
// ---------------------------------------------------------------------------

func TestClientFromContext_Nil(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	c := middleware.ClientFromContext(req.Context())
	if c != nil {
		t.Errorf("expected nil client from bare context, got %+v", c)
	}
}

// ---------------------------------------------------------------------------
// WriteOAuthError
// ---------------------------------------------------------------------------

func TestWriteOAuthError_StatusAndBody(t *testing.T) {
	rr := httptest.NewRecorder()
	middleware.WriteOAuthError(rr, http.StatusBadRequest, "invalid_request", "missing param")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "invalid_request") {
		t.Errorf("response body should contain error code: %s", body)
	}
	if !strings.Contains(body, "missing param") {
		t.Errorf("response body should contain description: %s", body)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %s", ct)
	}
}

func TestWriteOAuthError_401(t *testing.T) {
	rr := httptest.NewRecorder()
	middleware.WriteOAuthError(rr, http.StatusUnauthorized, "invalid_client", "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// RedirectOAuthError
// ---------------------------------------------------------------------------

func TestRedirectOAuthError_ValidURI_RedirectsWithError(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/authorize", nil)
	registeredURIs := []string{"https://app.example.com/callback"}

	middleware.RedirectOAuthError(rr, req, "https://app.example.com/callback", registeredURIs, "access_denied", "user denied", "state-123")

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=access_denied") {
		t.Errorf("Location should contain error=access_denied: %s", loc)
	}
	if !strings.Contains(loc, "state=state-123") {
		t.Errorf("Location should contain state: %s", loc)
	}
}

func TestRedirectOAuthError_UnregisteredURI_Returns400(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/authorize", nil)
	registeredURIs := []string{"https://app.example.com/callback"}

	middleware.RedirectOAuthError(rr, req, "https://evil.example.com/steal", registeredURIs, "access_denied", "denied", "")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unregistered URI, got %d", rr.Code)
	}
}

func TestRedirectOAuthError_EmptyRegisteredList_Returns400(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/authorize", nil)

	middleware.RedirectOAuthError(rr, req, "https://app.example.com/callback", nil, "server_error", "", "")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty registered list, got %d", rr.Code)
	}
}

func TestRedirectOAuthError_NoState_NoStateParam(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/authorize", nil)
	registeredURIs := []string{"https://app.example.com/callback"}

	middleware.RedirectOAuthError(rr, req, "https://app.example.com/callback", registeredURIs, "invalid_request", "bad", "")

	loc := rr.Header().Get("Location")
	if strings.Contains(loc, "state=") {
		t.Errorf("Location should not contain state when it's empty: %s", loc)
	}
}

// ---------------------------------------------------------------------------
// SessionMiddleware
// ---------------------------------------------------------------------------

func newSessionMW(t *testing.T) *middleware.SessionMiddleware {
	t.Helper()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	return middleware.NewSessionMiddleware(secret, false)
}

func TestSessionMiddleware_SaveAndGet(t *testing.T) {
	sm := newSessionMW(t)

	rr := httptest.NewRecorder()
	if err := sm.SaveSessionID(rr, "sess-abc"); err != nil {
		t.Fatalf("SaveSessionID: %v", err)
	}

	// Build a request from the response cookies.
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}

	sid := sm.GetSessionID(req)
	if sid != "sess-abc" {
		t.Errorf("expected sess-abc, got %q", sid)
	}
}

func TestSessionMiddleware_GetWithoutCookie_ReturnsEmpty(t *testing.T) {
	sm := newSessionMW(t)
	req := httptest.NewRequest("GET", "/", nil)
	if sid := sm.GetSessionID(req); sid != "" {
		t.Errorf("expected empty string without cookie, got %q", sid)
	}
}

func TestSessionMiddleware_TamperedCookie_ReturnsEmpty(t *testing.T) {
	sm := newSessionMW(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "_session", Value: "tampered-garbage"})
	if sid := sm.GetSessionID(req); sid != "" {
		t.Errorf("expected empty string for tampered cookie, got %q", sid)
	}
}

func TestSessionMiddleware_ClearSession(t *testing.T) {
	sm := newSessionMW(t)

	rr := httptest.NewRecorder()
	sm.ClearSession(rr)

	cookies := rr.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "_session" {
			found = true
			if c.MaxAge != -1 {
				t.Errorf("expected MaxAge=-1 on cleared session, got %d", c.MaxAge)
			}
		}
	}
	if !found {
		t.Error("ClearSession should set the session cookie with MaxAge=-1")
	}
}

func TestSessionMiddleware_SecureFlag_TrueForHTTPS(t *testing.T) {
	secret := make([]byte, 32)
	sm := middleware.NewSessionMiddleware(secret, true) // secure=true

	rr := httptest.NewRecorder()
	sm.SaveSessionID(rr, "s-id")

	for _, c := range rr.Result().Cookies() {
		if c.Name == "_session" && !c.Secure {
			t.Error("expected Secure=true for HTTPS session middleware")
		}
	}
}

func TestSessionMiddleware_SecureFlag_FalseForHTTP(t *testing.T) {
	secret := make([]byte, 32)
	sm := middleware.NewSessionMiddleware(secret, false) // secure=false

	rr := httptest.NewRecorder()
	sm.SaveSessionID(rr, "s-id")

	for _, c := range rr.Result().Cookies() {
		if c.Name == "_session" && c.Secure {
			t.Error("expected Secure=false for HTTP session middleware")
		}
	}
}

// ============================================================
// CSRF token (Fix #10)
// ============================================================

func TestCSRFTokenDeterministicForSameInputs(t *testing.T) {
	secret := []byte("a-secret-thats-32-bytes-long-aaaaaa")
	sm := middleware.NewSessionMiddleware(secret, false)

	a := sm.CSRFToken("uid-1")
	b := sm.CSRFToken("uid-1")
	if a != b {
		t.Errorf("expected same token for same uid, got %q vs %q", a, b)
	}
	if a == "" {
		t.Error("CSRFToken returned empty string")
	}
}

func TestCSRFTokenDiffersByID(t *testing.T) {
	secret := []byte("a-secret-thats-32-bytes-long-aaaaaa")
	sm := middleware.NewSessionMiddleware(secret, false)

	if sm.CSRFToken("uid-1") == sm.CSRFToken("uid-2") {
		t.Error("expected different tokens for different ids")
	}
}

func TestCSRFTokenDiffersBySecret(t *testing.T) {
	a := middleware.NewSessionMiddleware([]byte("secret-a-pad-out-to-32-bytes-aaaa"), false)
	b := middleware.NewSessionMiddleware([]byte("secret-b-pad-out-to-32-bytes-bbbb"), false)

	if a.CSRFToken("uid") == b.CSRFToken("uid") {
		t.Error("expected different tokens for different cookie secrets")
	}
}

func TestValidateCSRFAcceptsCorrectToken(t *testing.T) {
	sm := middleware.NewSessionMiddleware([]byte("secret-pad-out-to-32-bytes-aaaaaaa"), false)
	tok := sm.CSRFToken("uid-x")
	if !sm.ValidateCSRF("uid-x", tok) {
		t.Error("ValidateCSRF returned false for valid token")
	}
}

func TestValidateCSRFRejectsTampered(t *testing.T) {
	sm := middleware.NewSessionMiddleware([]byte("secret-pad-out-to-32-bytes-aaaaaaa"), false)
	tok := sm.CSRFToken("uid-x")
	if sm.ValidateCSRF("uid-x", tok+"x") {
		t.Error("ValidateCSRF accepted tampered token")
	}
	if sm.ValidateCSRF("uid-y", tok) {
		t.Error("ValidateCSRF accepted token bound to different uid")
	}
}

func TestValidateCSRFRejectsEmpty(t *testing.T) {
	sm := middleware.NewSessionMiddleware([]byte("secret-pad-out-to-32-bytes-aaaaaaa"), false)
	if sm.ValidateCSRF("uid", "") {
		t.Error("ValidateCSRF accepted empty token")
	}
	if sm.ValidateCSRF("", sm.CSRFToken("uid")) {
		t.Error("ValidateCSRF accepted empty id")
	}
}
