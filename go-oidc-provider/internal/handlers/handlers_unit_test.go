package handlers_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/strongnguyen29/go-oidc-provider/internal/config"
	"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
	"github.com/strongnguyen29/go-oidc-provider/internal/handlers"
	mw "github.com/strongnguyen29/go-oidc-provider/internal/middleware"
	"github.com/strongnguyen29/go-oidc-provider/internal/models"
	"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

// ---------------------------------------------------------------------------
// Test fixtures / helpers
// ---------------------------------------------------------------------------

func newCfg() *config.Config {
	cfg := &config.Config{
		Issuer: "https://iss.example.com",
		Clients: []config.ClientConfig{
			{
				ID:           "client-1",
				Secret:       "secret-1",
				RedirectURIs: []string{"https://app.example.com/cb"},
				PostLogoutRedirectURIs: []string{"https://app.example.com/"},
				GrantTypes:             []string{"authorization_code", "refresh_token", "password", "urn:ietf:params:oauth:grant-type:device_code"},
				Scopes:                 []string{"openid", "profile", "email", "offline_access"},
				TokenEndpointAuthMethod: "client_secret_basic",
			},
		},
		FindAccount: func(ctx context.Context, sub string) (*config.Account, error) {
			return &config.Account{
				Sub: sub,
				Claims: map[string]interface{}{
					"name":  "Test " + sub,
					"email": sub + "@example.com",
				},
			}, nil
		},
		AuthenticateAccount: func(ctx context.Context, login, password string) (*config.Account, error) {
			if password == "correct" {
				return &config.Account{Sub: login}, nil
			}
			return nil, nil
		},
	}
	cfg.Defaults()
	return cfg
}

func newKS(t *testing.T) *crypto.Keystore {
	t.Helper()
	ks, err := crypto.NewKeystore()
	if err != nil {
		t.Fatalf("NewKeystore: %v", err)
	}
	return ks
}

func newAdapter() *store.MemoryStore {
	return store.NewMemoryStore()
}

func newSM() *mw.SessionMiddleware {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	return mw.NewSessionMiddleware(secret, false)
}

// withClient injects a client into the request context (simulates ClientAuthMiddleware).
func withClient(r *http.Request, client *config.ClientConfig) *http.Request {
	ctx := context.WithValue(r.Context(), mw.ClientContextKey, client)
	return r.WithContext(ctx)
}

// withChiUID injects a chi URL param "uid" (simulates chi router).
func withChiUID(r *http.Request, uid string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("uid", uid)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// decodeJSON decodes the response body into a string→interface map.
func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&m); err != nil {
		t.Fatalf("decodeJSON: %v (body: %s)", err, rr.Body.String())
	}
	return m
}

// formReq creates a POST request with URL-encoded form body.
func formReq(target string, form url.Values) *http.Request {
	req := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// s256Challenge computes the S256 PKCE code_challenge for a given verifier.
func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// issueAT issues an access token directly (bypasses the store-based flow).
func issueAT(t *testing.T, cfg *config.Config, ks *crypto.Keystore, sub, scope string) string {
	t.Helper()
	now := time.Now()
	claims := crypto.AccessTokenClaims{
		Issuer:    cfg.Issuer,
		Subject:   sub,
		Audience:  []string{cfg.Issuer},
		Scope:     scope,
		IssuedAt:  now,
		ExpiresAt: now.Add(cfg.AccessTokenTTL),
		ClientID:  "client-1",
	}
	tok, err := crypto.IssueAccessToken(ks, claims)
	if err != nil {
		t.Fatalf("issueAT: %v", err)
	}
	return tok
}

func storeRefreshToken(t *testing.T, adapter store.Adapter, rtID string, cfg *config.Config) *models.RefreshToken {
	t.Helper()
	rt := &models.RefreshToken{
		ID:        rtID,
		AccountID: "alice",
		ClientID:  "client-1",
		Scopes:    []string{"openid", "profile"},
		GrantID:   "grant-1",
		CreatedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(cfg.RefreshTokenTTL).Unix(),
	}
	adapter.Upsert(context.Background(), "rt:"+rtID, rt, cfg.RefreshTokenTTL)
	return rt
}

func storeAuthCode(t *testing.T, adapter store.Adapter, code string) *models.AuthorizationCode {
	t.Helper()
	ac := &models.AuthorizationCode{
		Code:        code,
		ClientID:    "client-1",
		RedirectURI: "https://app.example.com/cb",
		Scopes:      []string{"openid", "profile"},
		AccountID:   "alice",
		SessionID:   "sess-1",
		GrantID:     "grant-1",
		CreatedAt:   time.Now().Unix(),
		ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
	}
	adapter.Upsert(context.Background(), "code:"+code, ac, 10*time.Minute)
	return ac
}

func storeSession(adapter store.Adapter, sessID, accountID string) *models.Session {
	sess := &models.Session{
		ID:        sessID,
		AccountID: accountID,
		LoginTime: time.Now().Unix(),
		Clients:   map[string]*models.ClientSession{},
	}
	adapter.Upsert(context.Background(), "session:"+sessID, sess, 24*time.Hour)
	return sess
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ============================================================
// Discovery
// ============================================================

func TestDiscoveryHandler_RequiredFields(t *testing.T) {
	cfg := newCfg()
	h := handlers.NewDiscoveryHandler(cfg)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr)
	for _, f := range []string{
		"issuer", "authorization_endpoint", "token_endpoint",
		"userinfo_endpoint", "jwks_uri", "introspection_endpoint",
		"revocation_endpoint", "end_session_endpoint",
	} {
		if _, ok := m[f]; !ok {
			t.Errorf("missing discovery field: %s", f)
		}
	}
}

func TestDiscoveryHandler_IssuerMatchesConfig(t *testing.T) {
	cfg := newCfg()
	h := handlers.NewDiscoveryHandler(cfg)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))

	m := decodeJSON(t, rr)
	if m["issuer"] != cfg.Issuer {
		t.Errorf("issuer: want %s, got %v", cfg.Issuer, m["issuer"])
	}
}

func TestDiscoveryHandler_ResponseTypesPresent(t *testing.T) {
	cfg := newCfg()
	h := handlers.NewDiscoveryHandler(cfg)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))

	m := decodeJSON(t, rr)
	if _, ok := m["response_types_supported"]; !ok {
		t.Error("expected response_types_supported in discovery document")
	}
}

// ============================================================
// JWKS
// ============================================================

func TestJWKSHandler_ReturnsRS256Key(t *testing.T) {
	ks := newKS(t)
	h := handlers.NewJWKSHandler(ks)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest("GET", "/jwks", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr)
	keys, _ := m["keys"].([]interface{})
	if len(keys) == 0 {
		t.Fatal("JWKS should contain at least one key")
	}
	k := keys[0].(map[string]interface{})
	if k["alg"] != "RS256" {
		t.Errorf("expected alg=RS256, got %v", k["alg"])
	}
	if k["use"] != "sig" {
		t.Errorf("expected use=sig, got %v", k["use"])
	}
	if k["kid"] == "" {
		t.Error("expected non-empty kid")
	}
}

func TestJWKSHandler_ContentType(t *testing.T) {
	ks := newKS(t)
	h := handlers.NewJWKSHandler(ks)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest("GET", "/jwks", nil))

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %s", ct)
	}
}

// ============================================================
// UserInfo
// ============================================================

func TestUserInfoHandler_ValidToken_ReturnsSub(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	at := issueAT(t, cfg, ks, "alice", "openid profile")
	storeJTI(t, adapter, at, ks, cfg)

	h := handlers.NewUserInfoHandler(cfg, ks, adapter)
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	m := decodeJSON(t, rr)
	if m["sub"] != "alice" {
		t.Errorf("expected sub=alice, got %v", m["sub"])
	}
}

func TestUserInfoHandler_ProfileScope_IncludesName(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	at := issueAT(t, cfg, ks, "bob", "openid profile")
	storeJTI(t, adapter, at, ks, cfg)

	h := handlers.NewUserInfoHandler(cfg, ks, adapter)
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	rr := httptest.NewRecorder()
	h(rr, req)

	m := decodeJSON(t, rr)
	if _, ok := m["name"]; !ok {
		t.Error("expected 'name' claim with profile scope")
	}
}

func TestUserInfoHandler_NoProfileScope_OmitsName(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	at := issueAT(t, cfg, ks, "carol", "openid") // no profile
	storeJTI(t, adapter, at, ks, cfg)

	h := handlers.NewUserInfoHandler(cfg, ks, adapter)
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	rr := httptest.NewRecorder()
	h(rr, req)

	m := decodeJSON(t, rr)
	if _, ok := m["name"]; ok {
		t.Error("'name' must not appear without profile scope")
	}
}

func TestUserInfoHandler_EmailScope_IncludesEmail(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	at := issueAT(t, cfg, ks, "dave", "openid email")
	storeJTI(t, adapter, at, ks, cfg)

	h := handlers.NewUserInfoHandler(cfg, ks, adapter)
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	rr := httptest.NewRecorder()
	h(rr, req)

	m := decodeJSON(t, rr)
	if _, ok := m["email"]; !ok {
		t.Error("expected 'email' claim with email scope")
	}
}

func TestUserInfoHandler_NoEmailScope_OmitsEmail(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	at := issueAT(t, cfg, ks, "eve", "openid profile") // no email scope
	storeJTI(t, adapter, at, ks, cfg)

	h := handlers.NewUserInfoHandler(cfg, ks, adapter)
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	rr := httptest.NewRecorder()
	h(rr, req)

	m := decodeJSON(t, rr)
	if _, ok := m["email"]; ok {
		t.Error("'email' must not appear without email scope")
	}
}

func TestUserInfoHandler_NoToken_Returns401(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	h := handlers.NewUserInfoHandler(cfg, ks, adapter)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest("GET", "/userinfo", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	if challenge := rr.Header().Get("WWW-Authenticate"); !strings.Contains(challenge, "Bearer") {
		t.Errorf("expected Bearer WWW-Authenticate challenge, got %q", challenge)
	}
}

func TestUserInfoHandler_InvalidToken_Returns401(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	h := handlers.NewUserInfoHandler(cfg, ks, adapter)

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer not.a.jwt")
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	if challenge := rr.Header().Get("WWW-Authenticate"); !strings.Contains(challenge, `error="invalid_token"`) {
		t.Errorf("expected error=invalid_token in challenge, got %q", challenge)
	}
}

func TestUserInfoHandler_RevokedJTI_Returns401(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	at := issueAT(t, cfg, ks, "alice", "openid")
	// Intentionally do NOT seed the JTI — simulates a revoked or unknown token.

	h := handlers.NewUserInfoHandler(cfg, ks, adapter)
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked JTI, got %d", rr.Code)
	}
}

func TestUserInfoHandler_WrongIssuer_Returns401(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	// Issue a token whose iss claim does not match cfg.Issuer.
	now := time.Now()
	tok, err := crypto.IssueAccessToken(ks, crypto.AccessTokenClaims{
		Issuer:    "https://evil.example.com",
		Subject:   "alice",
		Audience:  []string{"https://evil.example.com"},
		Scope:     "openid",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		ClientID:  "client-1",
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	storeJTI(t, adapter, tok, ks, cfg)

	h := handlers.NewUserInfoHandler(cfg, ks, adapter)
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong issuer, got %d", rr.Code)
	}
}

func TestUserInfoHandler_TokenInFormParam(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	at := issueAT(t, cfg, ks, "frank", "openid")
	storeJTI(t, adapter, at, ks, cfg)

	h := handlers.NewUserInfoHandler(cfg, ks, adapter)
	req := formReq("/userinfo", url.Values{"access_token": {at}})
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for token in form param, got %d", rr.Code)
	}
}

// ============================================================
// Token — ROPC
// ============================================================

func TestTokenHandler_ROPC_ValidCredentials(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"password":   {"correct"},
		"scope":      {"openid"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	m := decodeJSON(t, rr)
	if m["access_token"] == nil {
		t.Error("expected access_token")
	}
}

func TestTokenHandler_ROPC_WithIDToken(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"password":   {"correct"},
		"scope":      {"openid"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	m := decodeJSON(t, rr)
	if m["id_token"] == nil {
		t.Error("expected id_token when openid scope present in ROPC")
	}
}

func TestTokenHandler_ROPC_OfflineAccess_IssuesRefreshToken(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"password":   {"correct"},
		"scope":      {"openid offline_access"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr)
	if m["refresh_token"] == nil {
		t.Error("expected refresh_token when offline_access scope requested")
	}
}

func TestTokenHandler_ROPC_InvalidCredentials_Returns401(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"password":   {"wrong"},
		"scope":      {"openid"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for bad credentials, got %d", rr.Code)
	}
}

func TestTokenHandler_UnsupportedGrantType(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	// Client with permissive (empty) GrantTypes so the per-client whitelist
	// added by Fix #4 doesn't short-circuit before the dispatcher reaches its
	// "unknown grant_type" branch.
	client := &config.ClientConfig{
		ID:                      "permissive",
		Secret:                  "secret",
		RedirectURIs:            []string{"https://app.example.com/cb"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{"grant_type": {"magic_beans"}})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	m := decodeJSON(t, rr)
	if m["error"] != "unsupported_grant_type" {
		t.Errorf("expected unsupported_grant_type, got %v", m["error"])
	}
}

func TestTokenHandler_NoClientInContext_Returns401(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	h := handlers.NewTokenHandler(cfg, ks, adapter)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest("POST", "/token", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without client, got %d", rr.Code)
	}
}

// ============================================================
// Token — authorization_code
// ============================================================

func TestTokenHandler_AuthCode_Valid(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	storeSession(adapter, "sess-1", "alice")
	storeAuthCode(t, adapter, "code-valid")

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"code-valid"},
		"redirect_uri": {"https://app.example.com/cb"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	m := decodeJSON(t, rr)
	if m["access_token"] == nil {
		t.Error("expected access_token")
	}
	if m["id_token"] == nil {
		t.Error("expected id_token (openid scope)")
	}
	if m["refresh_token"] == nil {
		t.Error("expected refresh_token")
	}
}

func TestTokenHandler_AuthCode_MissingCode(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":   {"authorization_code"},
		"redirect_uri": {"https://app.example.com/cb"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing code, got %d", rr.Code)
	}
}

func TestTokenHandler_AuthCode_UnknownCode(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"no-such-code"},
		"redirect_uri": {"https://app.example.com/cb"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	m := decodeJSON(t, rr)
	if m["error"] != "invalid_grant" {
		t.Errorf("expected invalid_grant, got %v", m["error"])
	}
}

func TestTokenHandler_AuthCode_ConsumedCode(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	ac := storeAuthCode(t, adapter, "code-consumed")
	ac.Consumed = true
	adapter.Upsert(context.Background(), "code:code-consumed", ac, 10*time.Minute)

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"code-consumed"},
		"redirect_uri": {"https://app.example.com/cb"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for consumed code, got %d", rr.Code)
	}
}

func TestTokenHandler_AuthCode_WrongClient(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	storeAuthCode(t, adapter, "code-wrong-client")
	other := &config.ClientConfig{ID: "other-client", TokenEndpointAuthMethod: "none"}
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"code-wrong-client"},
		"redirect_uri": {"https://app.example.com/cb"},
	})
	req = withClient(req, other)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for client mismatch, got %d", rr.Code)
	}
}

func TestTokenHandler_AuthCode_WrongRedirectURI(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	storeAuthCode(t, adapter, "code-wrong-redir")
	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"code-wrong-redir"},
		"redirect_uri": {"https://evil.example.com/cb"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for redirect_uri mismatch, got %d", rr.Code)
	}
}

func TestTokenHandler_AuthCode_PKCEWrongVerifier(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	verifier := "long-test-verifier-at-least-43-characters-0123456789"
	ac := &models.AuthorizationCode{
		Code:                "code-pkce-bad",
		ClientID:            "client-1",
		RedirectURI:         "https://app.example.com/cb",
		Scopes:              []string{"openid"},
		AccountID:           "alice",
		SessionID:           "sess-1",
		GrantID:             "grant-1",
		CodeChallenge:       s256Challenge(verifier),
		CodeChallengeMethod: "S256",
		CreatedAt:           time.Now().Unix(),
		ExpiresAt:           time.Now().Add(10 * time.Minute).Unix(),
	}
	adapter.Upsert(context.Background(), "code:code-pkce-bad", ac, 10*time.Minute)

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-pkce-bad"},
		"redirect_uri":  {"https://app.example.com/cb"},
		"code_verifier": {"wrong-verifier-totally-wrong"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for wrong PKCE verifier, got %d", rr.Code)
	}
}

func TestTokenHandler_AuthCode_PKCECorrectVerifier(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	storeSession(adapter, "sess-1", "alice")

	verifier := "long-test-verifier-at-least-43-characters-0123456789"
	ac := &models.AuthorizationCode{
		Code:                "code-pkce-ok",
		ClientID:            "client-1",
		RedirectURI:         "https://app.example.com/cb",
		Scopes:              []string{"openid"},
		AccountID:           "alice",
		SessionID:           "sess-1",
		GrantID:             "grant-1",
		CodeChallenge:       s256Challenge(verifier),
		CodeChallengeMethod: "S256",
		CreatedAt:           time.Now().Unix(),
		ExpiresAt:           time.Now().Add(10 * time.Minute).Unix(),
	}
	adapter.Upsert(context.Background(), "code:code-pkce-ok", ac, 10*time.Minute)

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-pkce-ok"},
		"redirect_uri":  {"https://app.example.com/cb"},
		"code_verifier": {verifier},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for correct PKCE, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ============================================================
// Token — refresh_token
// ============================================================

func TestTokenHandler_RefreshToken_Valid(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	storeRefreshToken(t, adapter, "rt-valid", cfg)
	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"rt-valid"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	m := decodeJSON(t, rr)
	if m["access_token"] == nil {
		t.Error("expected new access_token")
	}
	if m["refresh_token"] == nil {
		t.Error("expected new refresh_token (rotation)")
	}
}

func TestTokenHandler_RefreshToken_Consumed_Returns400(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	rt := storeRefreshToken(t, adapter, "rt-consumed", cfg)
	rt.Consumed = true
	adapter.Upsert(context.Background(), "rt:rt-consumed", rt, cfg.RefreshTokenTTL)

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"rt-consumed"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for consumed RT, got %d", rr.Code)
	}
}

func TestTokenHandler_RefreshToken_Missing_Returns400(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{"grant_type": {"refresh_token"}})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing RT, got %d", rr.Code)
	}
}

func TestTokenHandler_RefreshToken_WrongClient_Returns400(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	storeRefreshToken(t, adapter, "rt-other-client", cfg)
	other := &config.ClientConfig{ID: "other-client", TokenEndpointAuthMethod: "none"}
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"rt-other-client"},
	})
	req = withClient(req, other)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for client mismatch, got %d", rr.Code)
	}
}

// ============================================================
// Token — device_code
// ============================================================

func storeDeviceCode(adapter store.Adapter, dc *models.DeviceCode, cfg *config.Config) {
	adapter.Upsert(context.Background(), "device:"+dc.DeviceCode, dc, cfg.DeviceCodeTTL)
}

func TestTokenHandler_DeviceCode_Pending_Returns400(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	dc := &models.DeviceCode{
		DeviceCode: "dev-pending",
		ClientID:   "client-1",
		Scopes:     []string{"openid"},
		Verified:   false,
		ExpiresAt:  time.Now().Add(5 * time.Minute).Unix(),
	}
	storeDeviceCode(adapter, dc, cfg)

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {"dev-pending"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	m := decodeJSON(t, rr)
	if m["error"] != "authorization_pending" {
		t.Errorf("expected authorization_pending, got %v", m["error"])
	}
}

func TestTokenHandler_DeviceCode_Denied_Returns400(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	dc := &models.DeviceCode{
		DeviceCode: "dev-denied",
		ClientID:   "client-1",
		Denied:     true,
		ExpiresAt:  time.Now().Add(5 * time.Minute).Unix(),
	}
	storeDeviceCode(adapter, dc, cfg)

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {"dev-denied"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	m := decodeJSON(t, rr)
	if m["error"] != "access_denied" {
		t.Errorf("expected access_denied, got %v", m["error"])
	}
}

func TestTokenHandler_DeviceCode_Missing_Returns400(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
		// no device_code
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_code, got %d", rr.Code)
	}
}

func TestTokenHandler_DeviceCode_Verified_Returns200(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	dc := &models.DeviceCode{
		DeviceCode: "dev-verified",
		ClientID:   "client-1",
		Scopes:     []string{"openid"},
		AccountID:  "alice",
		GrantID:    "grant-dev",
		Verified:   true,
		ExpiresAt:  time.Now().Add(5 * time.Minute).Unix(),
	}
	storeDeviceCode(adapter, dc, cfg)

	client := cfg.FindClient("client-1")
	h := handlers.NewTokenHandler(cfg, ks, adapter)

	req := formReq("/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {"dev-verified"},
	})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for verified device code, got %d: %s", rr.Code, rr.Body.String())
	}
	m := decodeJSON(t, rr)
	if m["access_token"] == nil {
		t.Error("expected access_token")
	}
}

// ============================================================
// Introspection
// ============================================================

func storeJTI(t *testing.T, adapter store.Adapter, tok string, ks *crypto.Keystore, cfg *config.Config) string {
	t.Helper()
	parsed, err := crypto.ParseAccessToken(ks, tok)
	if err != nil {
		t.Fatalf("ParseAccessToken in storeJTI: %v", err)
	}
	jti, _ := (*parsed)["jti"].(string)
	adapter.Upsert(context.Background(), "jti:"+jti, jti, cfg.AccessTokenTTL)
	return jti
}

func TestIntrospectionHandler_ActiveToken(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	at := issueAT(t, cfg, ks, "alice", "openid")
	storeJTI(t, adapter, at, ks, cfg)

	client := cfg.FindClient("client-1")
	h := handlers.NewIntrospectionHandler(cfg, ks, adapter)

	req := formReq("/introspect", url.Values{"token": {at}})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr)
	if active, _ := m["active"].(bool); !active {
		t.Errorf("expected active=true, got %v", m["active"])
	}
	if m["sub"] != "alice" {
		t.Errorf("expected sub=alice, got %v", m["sub"])
	}
}

func TestIntrospectionHandler_RevokedJTI_ReturnsFalse(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	// JTI not stored → revoked/unknown.
	at := issueAT(t, cfg, ks, "bob", "openid")

	client := cfg.FindClient("client-1")
	h := handlers.NewIntrospectionHandler(cfg, ks, adapter)

	req := formReq("/introspect", url.Values{"token": {at}})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	m := decodeJSON(t, rr)
	if active, _ := m["active"].(bool); active {
		t.Error("expected active=false for token with unknown JTI")
	}
}

func TestIntrospectionHandler_EmptyToken_ReturnsFalse(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	client := cfg.FindClient("client-1")
	h := handlers.NewIntrospectionHandler(cfg, ks, adapter)

	req := formReq("/introspect", url.Values{"token": {""}})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	m := decodeJSON(t, rr)
	if active, _ := m["active"].(bool); active {
		t.Error("expected active=false for empty token")
	}
}

func TestIntrospectionHandler_RefreshToken_Active(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	storeRefreshToken(t, adapter, "rt-introspect", cfg)

	client := cfg.FindClient("client-1")
	h := handlers.NewIntrospectionHandler(cfg, ks, adapter)

	req := formReq("/introspect", url.Values{"token": {"rt-introspect"}})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	m := decodeJSON(t, rr)
	if active, _ := m["active"].(bool); !active {
		t.Error("expected active=true for valid refresh token")
	}
}

func TestIntrospectionHandler_NoClient_Returns401(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	h := handlers.NewIntrospectionHandler(cfg, ks, adapter)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest("POST", "/introspect", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without client, got %d", rr.Code)
	}
}

// ============================================================
// Revocation
// ============================================================

func TestRevocationHandler_AccessToken_Returns200(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	at := issueAT(t, cfg, ks, "alice", "openid")
	storeJTI(t, adapter, at, ks, cfg)

	client := cfg.FindClient("client-1")
	h := handlers.NewRevocationHandler(cfg, ks, adapter)

	req := formReq("/revoke", url.Values{"token": {at}})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRevocationHandler_RefreshToken_DeletedFromStore(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	storeRefreshToken(t, adapter, "rt-revoke", cfg)

	client := cfg.FindClient("client-1")
	h := handlers.NewRevocationHandler(cfg, ks, adapter)

	req := formReq("/revoke", url.Values{"token": {"rt-revoke"}})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if _, err := adapter.Find(context.Background(), "rt:rt-revoke"); err == nil {
		t.Error("refresh token should be deleted after revocation")
	}
}

func TestRevocationHandler_EmptyToken_Returns200(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	client := cfg.FindClient("client-1")
	h := handlers.NewRevocationHandler(cfg, ks, adapter)

	req := formReq("/revoke", url.Values{"token": {""}})
	req = withClient(req, client)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for empty token (RFC 7009 requires success), got %d", rr.Code)
	}
}

func TestRevocationHandler_NoClient_Returns401(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()

	h := handlers.NewRevocationHandler(cfg, ks, adapter)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest("POST", "/revoke", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without client, got %d", rr.Code)
	}
}

// ============================================================
// Authorization
// ============================================================

func TestAuthorizationHandler_UnknownClient_Returns400(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	h := handlers.NewAuthorizationHandler(cfg, ks, adapter, sm)
	req := httptest.NewRequest("GET",
		"/authorize?client_id=unknown&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code",
		nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown client, got %d", rr.Code)
	}
}

func TestAuthorizationHandler_UnregisteredRedirectURI_Returns400(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	h := handlers.NewAuthorizationHandler(cfg, ks, adapter, sm)
	req := httptest.NewRequest("GET",
		"/authorize?client_id=client-1&redirect_uri=https%3A%2F%2Fevil.example.com%2Fcb&response_type=code",
		nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unregistered redirect_uri, got %d", rr.Code)
	}
}

func TestAuthorizationHandler_NoSession_RedirectsToLoginInteraction(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	h := handlers.NewAuthorizationHandler(cfg, ks, adapter, sm)
	req := httptest.NewRequest("GET",
		"/authorize?client_id=client-1&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=openid",
		nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "/interaction/") {
		t.Errorf("expected redirect to /interaction/, got %s", loc)
	}
}

func TestAuthorizationHandler_PKCERequired_NoChallenge_RedirectsError(t *testing.T) {
	cfg := newCfg()
	cfg.PKCERequired = true
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	h := handlers.NewAuthorizationHandler(cfg, ks, adapter, sm)
	req := httptest.NewRequest("GET",
		"/authorize?client_id=client-1&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=openid",
		nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	// With PKCERequired, missing code_challenge → redirect with error.
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("expected error=invalid_request in redirect, got %s", loc)
	}
}

// ============================================================
// Interaction — GET
// ============================================================

func TestInteractionGetHandler_LoginPrompt(t *testing.T) {
	cfg := newCfg()
	adapter := newAdapter()
	defer adapter.Stop()

	uid := "uid-login"
	ia := &models.Interaction{
		UID:      uid,
		Prompt:   "login",
		ClientID: "client-1",
		Params:   map[string]string{"scope": "openid"},
	}
	adapter.Upsert(context.Background(), "interaction:"+uid, ia, 10*time.Minute)

	sm := newSM()
	h := handlers.NewInteractionGetHandler(cfg, adapter, sm)
	req := withChiUID(httptest.NewRequest("GET", "/interaction/"+uid, nil), uid)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("expected text/html, got %s", ct)
	}
}

func TestInteractionGetHandler_ConsentPrompt(t *testing.T) {
	cfg := newCfg()
	adapter := newAdapter()
	defer adapter.Stop()

	uid := "uid-consent"
	ia := &models.Interaction{
		UID:      uid,
		Prompt:   "consent",
		ClientID: "client-1",
		Params:   map[string]string{"scope": "openid profile"},
	}
	adapter.Upsert(context.Background(), "interaction:"+uid, ia, 10*time.Minute)

	sm := newSM()
	h := handlers.NewInteractionGetHandler(cfg, adapter, sm)
	req := withChiUID(httptest.NewRequest("GET", "/interaction/"+uid, nil), uid)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestInteractionGetHandler_NotFound_ShowsErrorPage(t *testing.T) {
	cfg := newCfg()
	adapter := newAdapter()
	defer adapter.Stop()

	sm := newSM()
	h := handlers.NewInteractionGetHandler(cfg, adapter, sm)
	req := withChiUID(httptest.NewRequest("GET", "/interaction/ghost", nil), "ghost")
	rr := httptest.NewRecorder()
	h(rr, req)

	body, _ := io.ReadAll(rr.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "Not Found") &&
		!strings.Contains(bodyStr, "expired") &&
		!strings.Contains(bodyStr, "does not exist") &&
		!strings.Contains(bodyStr, "Interaction") {
		t.Errorf("expected error page for missing interaction, got: %s", truncate(bodyStr, 300))
	}
}

// ============================================================
// Interaction — login POST
// ============================================================

func TestInteractionLoginHandler_ValidCredentials_Redirects(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	uid := "uid-login-ok"
	ia := &models.Interaction{
		UID:      uid,
		Prompt:   "login",
		ClientID: "client-1",
		Params: map[string]string{
			"response_type": "code",
			"client_id":     "client-1",
			"redirect_uri":  "https://app.example.com/cb",
			"scope":         "openid",
		},
	}
	adapter.Upsert(context.Background(), "interaction:"+uid, ia, 10*time.Minute)

	h := handlers.NewInteractionLoginHandler(cfg, ks, adapter, sm)
	req := formReq("/interaction/"+uid+"/login", url.Values{
		"login":      {"alice"},
		"password":   {"correct"},
		"csrf_token": {sm.CSRFToken(uid)},
	})
	req = withChiUID(req, uid)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
}

func TestInteractionLoginHandler_InvalidCredentials_ShowsError(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	uid := "uid-login-fail"
	ia := &models.Interaction{
		UID:    uid,
		Prompt: "login",
		Params: map[string]string{"scope": "openid"},
	}
	adapter.Upsert(context.Background(), "interaction:"+uid, ia, 10*time.Minute)

	h := handlers.NewInteractionLoginHandler(cfg, ks, adapter, sm)
	req := formReq("/interaction/"+uid+"/login", url.Values{
		"login":      {"alice"},
		"password":   {"wrong"},
		"csrf_token": {sm.CSRFToken(uid)},
	})
	req = withChiUID(req, uid)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code == http.StatusFound {
		t.Error("should not redirect for invalid credentials")
	}
	body := rr.Body.String()
	if !strings.Contains(strings.ToLower(body), "invalid") {
		t.Errorf("expected error message in response, got: %s", truncate(body, 200))
	}
}

func TestInteractionLoginHandler_NotFound_Returns404(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	h := handlers.NewInteractionLoginHandler(cfg, ks, adapter, sm)
	req := formReq("/interaction/ghost/login", url.Values{
		"login":      {"alice"},
		"password":   {"correct"},
		"csrf_token": {sm.CSRFToken("ghost")},
	})
	req = withChiUID(req, "ghost")
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// ============================================================
// Interaction — abort POST
// ============================================================

func TestInteractionAbortHandler_RedirectsWithError(t *testing.T) {
	cfg := newCfg()
	adapter := newAdapter()
	defer adapter.Stop()

	uid := "uid-abort"
	ia := &models.Interaction{
		UID:      uid,
		ClientID: "client-1",
		Params: map[string]string{
			"redirect_uri": "https://app.example.com/cb",
			"state":        "state-xyz",
		},
	}
	adapter.Upsert(context.Background(), "interaction:"+uid, ia, 10*time.Minute)

	sm := newSM()
	h := handlers.NewInteractionAbortHandler(cfg, adapter, sm)
	req := formReq("/interaction/"+uid+"/abort", url.Values{"csrf_token": {sm.CSRFToken(uid)}})
	req = withChiUID(req, uid)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=access_denied") {
		t.Errorf("expected error=access_denied in redirect, got %s", loc)
	}
	if !strings.Contains(loc, "state=state-xyz") {
		t.Errorf("expected state in redirect, got %s", loc)
	}
}

func TestInteractionAbortHandler_NotFound_Returns404(t *testing.T) {
	cfg := newCfg()
	adapter := newAdapter()
	defer adapter.Stop()

	sm := newSM()
	h := handlers.NewInteractionAbortHandler(cfg, adapter, sm)
	req := withChiUID(httptest.NewRequest("POST", "/interaction/ghost/abort", nil), "ghost")
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// ============================================================
// End session
// ============================================================

func TestEndSessionHandler_ClearsSession(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	storeSession(adapter, "sess-logout", "alice")

	// Create a request with a valid session cookie.
	cookieRR := httptest.NewRecorder()
	sm.SaveSessionID(cookieRR, "sess-logout")

	h := handlers.NewEndSessionHandler(cfg, adapter, sm, ks)
	req := httptest.NewRequest("GET", "/logout", nil)
	for _, c := range cookieRR.Result().Cookies() {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h(rr, req)

	if _, err := adapter.Find(context.Background(), "session:sess-logout"); err == nil {
		t.Error("session should be deleted after logout")
	}
}

func TestEndSessionHandler_ValidPostLogoutURI_Redirects(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	h := handlers.NewEndSessionHandler(cfg, adapter, sm, ks)
	req := httptest.NewRequest("GET",
		"/logout?client_id=client-1&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2F&state=end-state",
		nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "https://app.example.com/") {
		t.Errorf("expected redirect to post_logout_redirect_uri, got %s", loc)
	}
	if !strings.Contains(loc, "state=end-state") {
		t.Errorf("expected state in redirect, got %s", loc)
	}
}

func TestEndSessionHandler_UnregisteredPostLogoutURI_ShowsSignedOutPage(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	h := handlers.NewEndSessionHandler(cfg, adapter, sm, ks)
	req := httptest.NewRequest("GET",
		"/logout?client_id=client-1&post_logout_redirect_uri=https%3A%2F%2Fevil.example.com%2F",
		nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code == http.StatusFound {
		t.Error("should not redirect to unregistered post_logout_redirect_uri")
	}
}

func TestEndSessionHandler_NoSession_JustShowsPage(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	h := handlers.NewEndSessionHandler(cfg, adapter, sm, ks)
	req := httptest.NewRequest("GET", "/logout", nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	// Without a session cookie, it should still render the signed-out page.
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for logout without session, got %d", rr.Code)
	}
}

// ============================================================
// CSRF protection on interaction forms (Fix #10)
// ============================================================

func TestInteractionLoginRejectsMissingCSRF(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	uid := "uid-csrf-missing"
	ia := &models.Interaction{
		UID:    uid,
		Prompt: "login",
		Params: map[string]string{
			"response_type": "code",
			"client_id":     "client-1",
			"redirect_uri":  "https://app.example.com/cb",
			"scope":         "openid",
		},
	}
	adapter.Upsert(context.Background(), "interaction:"+uid, ia, 10*time.Minute)

	h := handlers.NewInteractionLoginHandler(cfg, ks, adapter, sm)
	req := formReq("/interaction/"+uid+"/login", url.Values{
		"login":    {"alice"},
		"password": {"correct"},
	})
	req = withChiUID(req, uid)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing csrf_token, got %d body=%s", rr.Code, truncate(rr.Body.String(), 200))
	}
}

func TestInteractionLoginRejectsTamperedCSRF(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	uid := "uid-csrf-tampered"
	ia := &models.Interaction{
		UID:    uid,
		Prompt: "login",
		Params: map[string]string{
			"response_type": "code",
			"client_id":     "client-1",
			"redirect_uri":  "https://app.example.com/cb",
			"scope":         "openid",
		},
	}
	adapter.Upsert(context.Background(), "interaction:"+uid, ia, 10*time.Minute)

	h := handlers.NewInteractionLoginHandler(cfg, ks, adapter, sm)
	req := formReq("/interaction/"+uid+"/login", url.Values{
		"login":      {"alice"},
		"password":   {"correct"},
		"csrf_token": {"this-is-not-a-valid-token"},
	})
	req = withChiUID(req, uid)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for tampered csrf_token, got %d", rr.Code)
	}
}

func TestInteractionLoginAcceptsValidCSRF(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	uid := "uid-csrf-valid"
	ia := &models.Interaction{
		UID:      uid,
		Prompt:   "login",
		ClientID: "client-1",
		Params: map[string]string{
			"response_type": "code",
			"client_id":     "client-1",
			"redirect_uri":  "https://app.example.com/cb",
			"scope":         "openid",
		},
	}
	adapter.Upsert(context.Background(), "interaction:"+uid, ia, 10*time.Minute)

	h := handlers.NewInteractionLoginHandler(cfg, ks, adapter, sm)
	req := formReq("/interaction/"+uid+"/login", url.Values{
		"login":      {"alice"},
		"password":   {"correct"},
		"csrf_token": {sm.CSRFToken(uid)},
	})
	req = withChiUID(req, uid)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 redirect for valid csrf_token, got %d body=%s", rr.Code, truncate(rr.Body.String(), 200))
	}
}

func TestInteractionConfirmRequiresCSRF(t *testing.T) {
	cfg := newCfg()
	ks := newKS(t)
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	uid := "uid-confirm-csrf"
	ia := &models.Interaction{
		UID:      uid,
		Prompt:   "consent",
		ClientID: "client-1",
		Params: map[string]string{
			"response_type": "code",
			"client_id":     "client-1",
			"redirect_uri":  "https://app.example.com/cb",
			"scope":         "openid profile",
		},
	}
	adapter.Upsert(context.Background(), "interaction:"+uid, ia, 10*time.Minute)

	h := handlers.NewInteractionConfirmHandler(cfg, ks, adapter, sm)
	req := formReq("/interaction/"+uid+"/confirm", url.Values{
		"granted_scopes": {"openid"},
	})
	req = withChiUID(req, uid)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing csrf_token on confirm, got %d", rr.Code)
	}
}

func TestInteractionAbortRequiresCSRF(t *testing.T) {
	cfg := newCfg()
	adapter := newAdapter()
	defer adapter.Stop()
	sm := newSM()

	uid := "uid-abort-csrf"
	ia := &models.Interaction{
		UID:      uid,
		ClientID: "client-1",
		Params: map[string]string{
			"redirect_uri": "https://app.example.com/cb",
		},
	}
	adapter.Upsert(context.Background(), "interaction:"+uid, ia, 10*time.Minute)

	h := handlers.NewInteractionAbortHandler(cfg, adapter, sm)
	req := formReq("/interaction/"+uid+"/abort", url.Values{})
	req = withChiUID(req, uid)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing csrf_token on abort, got %d", rr.Code)
	}
}
