package test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Client authentication
// ---------------------------------------------------------------------------

func TestClientAuthRequired_Token(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	// POST /token without any client credentials.
	resp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"password":   {"password"},
		"scope":      {"openid"},
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 401 without client auth, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestClientAuthRequired_Introspect(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/introspect", url.Values{"token": {"some-token"}})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without client auth, got %d", resp.StatusCode)
	}
}

func TestClientAuthRequired_Revoke(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/revoke", url.Values{"token": {"some-token"}})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without client auth, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Authorization endpoint — validation errors
// ---------------------------------------------------------------------------

func TestAuthorize_UnknownClient_Returns400(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/authorize?client_id=no-such-client&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&response_type=code")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown client, got %d", resp.StatusCode)
	}
}

func TestAuthorize_InvalidRedirectURI_Returns400(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	resp, err := http.Get(fmt.Sprintf("%s/authorize?client_id=test-client&redirect_uri=%s&response_type=code",
		srv.URL, url.QueryEscape("https://evil.example.com/callback")))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for unregistered redirect_uri, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Token — authorization_code error cases
// ---------------------------------------------------------------------------

func TestToken_AuthCode_UnknownCode(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"no-such-code"},
		"redirect_uri":  {"https://example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 400, got %d: %s", resp.StatusCode, string(body))
	}

	var m map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&m)
}

func TestToken_AuthCode_WrongClientID(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"some-code"},
		"redirect_uri":  {"https://example.com/callback"},
		"client_id":     {"wrong-client"},
		"client_secret": {"test-secret"},
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for unknown client_id, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Token — ROPC error cases
// ---------------------------------------------------------------------------

func TestToken_ROPC_InvalidCredentials(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"password"},
		"username":      {"alice"},
		"password":      {"wrong-password"},
		"scope":         {"openid"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	})
	if err != nil {
		t.Fatalf("ROPC request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 401 for invalid credentials, got %d: %s", resp.StatusCode, string(body))
	}
}

// ---------------------------------------------------------------------------
// Token — refresh_token error cases
// ---------------------------------------------------------------------------

func TestToken_RefreshToken_ReusedAfterRotation(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	// Issue a token via ROPC with offline_access.
	tokenResp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"password"},
		"username":      {"alice"},
		"password":      {"password"},
		"scope":         {"openid offline_access"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	})
	if err != nil {
		t.Fatalf("ROPC request failed: %v", err)
	}
	var tokenData map[string]interface{}
	json.NewDecoder(tokenResp.Body).Decode(&tokenData)
	tokenResp.Body.Close()

	originalRT, ok := tokenData["refresh_token"].(string)
	if !ok || originalRT == "" {
		t.Skip("no refresh_token issued")
	}

	// First refresh — should succeed and rotate the token.
	refresh1, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {originalRT},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	})
	if err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}
	if refresh1.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(refresh1.Body)
		t.Fatalf("expected 200 on first refresh, got %d: %s", refresh1.StatusCode, string(body))
	}
	refresh1.Body.Close()

	// Second refresh using the original (now rotated) token — must fail.
	refresh2, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {originalRT},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	})
	if err != nil {
		t.Fatalf("second refresh request failed: %v", err)
	}
	defer refresh2.Body.Close()

	if refresh2.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(refresh2.Body)
		t.Errorf("expected 400 for replayed refresh token, got %d: %s", refresh2.StatusCode, string(body))
	}
}

// ---------------------------------------------------------------------------
// UserInfo — error cases
// ---------------------------------------------------------------------------

func TestUserInfo_NoToken_Returns401(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/userinfo")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", resp.StatusCode)
	}
}

func TestUserInfo_InvalidToken_Returns401(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-not-a-jwt")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", resp.StatusCode)
	}
}

func TestUserInfo_ScopeFiltering_ProfileOnly(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	// Get a token with only profile scope (no email).
	tokenResp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"password"},
		"username":      {"alice"},
		"password":      {"password"},
		"scope":         {"openid profile"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	var tokenData map[string]interface{}
	json.NewDecoder(tokenResp.Body).Decode(&tokenData)
	tokenResp.Body.Close()

	at := tokenData["access_token"].(string)

	req, _ := http.NewRequest("GET", srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	var ui map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&ui)

	if _, ok := ui["name"]; !ok {
		t.Error("expected 'name' with profile scope")
	}
	if _, ok := ui["email"]; ok {
		t.Error("should NOT have 'email' without email scope")
	}
}

// ---------------------------------------------------------------------------
// Introspection — after revocation
// ---------------------------------------------------------------------------

func TestIntrospect_AfterRevocation_InactiveToken(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	// Issue token via ROPC.
	tokenResp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"password"},
		"username":      {"carol"},
		"password":      {"password"},
		"scope":         {"openid"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	var tokenData map[string]interface{}
	json.NewDecoder(tokenResp.Body).Decode(&tokenData)
	tokenResp.Body.Close()

	at := tokenData["access_token"].(string)

	// Introspect before revocation — should be active.
	intr1, err := http.PostForm(srv.URL+"/introspect", url.Values{
		"token":         {at},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	})
	if err != nil {
		t.Fatalf("introspect before revocation failed: %v", err)
	}
	var i1 map[string]interface{}
	json.NewDecoder(intr1.Body).Decode(&i1)
	intr1.Body.Close()
	if active, _ := i1["active"].(bool); !active {
		t.Error("expected active=true before revocation")
	}

	// Revoke.
	revokeResp, err := http.PostForm(srv.URL+"/revoke", url.Values{
		"token":         {at},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	})
	if err != nil {
		t.Fatalf("revoke request failed: %v", err)
	}
	revokeResp.Body.Close()

	// Introspect after revocation — must be inactive.
	intr2, err := http.PostForm(srv.URL+"/introspect", url.Values{
		"token":         {at},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	})
	if err != nil {
		t.Fatalf("introspect after revocation failed: %v", err)
	}
	defer intr2.Body.Close()
	var i2 map[string]interface{}
	json.NewDecoder(intr2.Body).Decode(&i2)
	if active, _ := i2["active"].(bool); active {
		t.Error("expected active=false after revocation")
	}
}

// ---------------------------------------------------------------------------
// Interaction — abort redirects with error
// ---------------------------------------------------------------------------

func TestInteraction_Abort_RedirectsWithAccessDenied(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	client := newTestClient(srv)
	verifier, challenge := generatePKCE()

	// Trigger login interaction.
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=test-client&redirect_uri=%s&scope=openid&state=abort-state&code_challenge=%s&code_challenge_method=S256",
		srv.URL,
		url.QueryEscape("https://example.com/callback"),
		url.QueryEscape(challenge),
	)
	_ = verifier

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	resp.Body.Close()

	finalURL := resp.Request.URL.String()
	if !strings.Contains(finalURL, "/interaction/") {
		t.Skipf("expected interaction redirect, got: %s", finalURL)
	}

	// Extract UID.
	uid := strings.Split(finalURL, "/interaction/")[1]
	if idx := strings.Index(uid, "?"); idx >= 0 {
		uid = uid[:idx]
	}

	// POST /interaction/{uid}/abort.
	abortURL := fmt.Sprintf("%s/interaction/%s/abort", srv.URL, uid)
	abortResp, err := client.PostForm(abortURL, url.Values{})
	if err != nil {
		t.Fatalf("abort POST failed: %v", err)
	}
	defer abortResp.Body.Close()

	// Should end up at the callback with error=access_denied.
	finalURL = abortResp.Request.URL.String()
	if abortResp.StatusCode == http.StatusFound {
		finalURL = abortResp.Header.Get("Location")
	}

	if !strings.Contains(finalURL, "error=access_denied") {
		t.Errorf("expected error=access_denied in redirect after abort, got: %s", finalURL)
	}
}

// ---------------------------------------------------------------------------
// End session
// ---------------------------------------------------------------------------

func TestEndSession_WithPostLogoutRedirect(t *testing.T) {
	_, srv := newTestProvider(t)
	defer srv.Close()

	// Use a non-redirecting client so we can inspect the 302 directly.
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// /logout with a valid registered post_logout_redirect_uri.
	logoutURL := fmt.Sprintf("%s/logout?client_id=test-client&post_logout_redirect_uri=%s&state=logout-state",
		srv.URL, url.QueryEscape("https://example.com/"))

	logoutResp, err := noRedirectClient.Get(logoutURL)
	if err != nil {
		t.Fatalf("logout request failed: %v", err)
	}
	defer logoutResp.Body.Close()

	if logoutResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect for valid post_logout_redirect_uri, got %d", logoutResp.StatusCode)
	}
	loc := logoutResp.Header.Get("Location")
	if !strings.Contains(loc, "https://example.com/") {
		t.Errorf("expected redirect to post_logout_redirect_uri, got %s", loc)
	}
	if !strings.Contains(loc, "state=logout-state") {
		t.Errorf("expected state param in redirect, got %s", loc)
	}
	t.Log("End session with post_logout_redirect_uri passed")
}
