package handlers

import (
"encoding/json"
"net/http"
"strings"
"time"

"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/models"
"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

// NewTokenHandler handles POST /token.
func NewTokenHandler(cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
client := middleware.ClientFromContext(r.Context())
if client == nil {
middleware.WriteOAuthError(w, http.StatusUnauthorized, "invalid_client", "client not authenticated")
return
}

if err := r.ParseForm(); err != nil {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "failed to parse form")
return
}

grantType := r.FormValue("grant_type")

switch grantType {
case "authorization_code":
handleAuthorizationCode(w, r, cfg, ks, adapter, client)
case "refresh_token":
handleRefreshToken(w, r, cfg, ks, adapter, client)
case "urn:ietf:params:oauth:grant-type:device_code":
handleDeviceCode(w, r, cfg, ks, adapter, client)
case "password":
handleROPC(w, r, cfg, ks, adapter, client)
default:
middleware.WriteOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type not supported")
}
}
}

func handleAuthorizationCode(w http.ResponseWriter, r *http.Request, cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, client *config.ClientConfig) {
code := r.FormValue("code")
redirectURI := r.FormValue("redirect_uri")
codeVerifier := r.FormValue("code_verifier")

if code == "" {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "code is required")
return
}

raw, err := adapter.Find(r.Context(), "code:"+code)
if err != nil {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code not found or expired")
return
}
ac, ok := raw.(*models.AuthorizationCode)
if !ok {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
return
}

if ac.Consumed {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code already used")
return
}
if time.Now().Unix() > ac.ExpiresAt {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code expired")
return
}
if ac.ClientID != client.ID {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
return
}
if ac.RedirectURI != redirectURI {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
return
}

// PKCE validation.
if ac.CodeChallenge != "" {
if codeVerifier == "" {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier required")
return
}
method := ac.CodeChallengeMethod
if method == "" {
method = "plain"
}
if !crypto.VerifyPKCE(method, codeVerifier, ac.CodeChallenge) {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
return
}
}

// Mark code consumed.
ac.Consumed = true
adapter.Upsert(r.Context(), "code:"+code, ac, time.Until(time.Unix(ac.ExpiresAt, 0)))

now := time.Now()
at, _, err := issueAccessToken(cfg, ks, adapter, r.Context(), ac.AccountID, client.ID, ac.Scopes, now)
if err != nil {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue access token")
return
}

rt, err := issueRefreshToken(cfg, adapter, r.Context(), ac.AccountID, client.ID, ac.GrantID, ac.Scopes, now)
if err != nil {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue refresh token")
return
}

resp := map[string]interface{}{
"access_token":  at,
"token_type":    "Bearer",
"expires_in":    int(cfg.AccessTokenTTL.Seconds()),
"refresh_token": rt,
"scope":         strings.Join(ac.Scopes, " "),
}

if containsString(ac.Scopes, "openid") {
atHash := crypto.ComputeAtHash(at)
// Load session for auth_time.
authTime := now.Unix()
if rawSess, err := adapter.Find(r.Context(), "session:"+ac.SessionID); err == nil {
if sess, ok := rawSess.(*models.Session); ok {
authTime = sess.LoginTime
}
}
idt, err := issueIDToken(cfg, ks, r.Context(), ac.AccountID, client.ID, ac.Nonce, atHash, authTime, now)
if err == nil {
resp["id_token"] = idt
}
}

w.Header().Set("Content-Type", "application/json")
w.Header().Set("Cache-Control", "no-store")
json.NewEncoder(w).Encode(resp)
}

func handleRefreshToken(w http.ResponseWriter, r *http.Request, cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, client *config.ClientConfig) {
rtID := r.FormValue("refresh_token")
if rtID == "" {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
return
}

raw, err := adapter.Find(r.Context(), "rt:"+rtID)
if err != nil {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token not found or expired")
return
}
rt, ok := raw.(*models.RefreshToken)
if !ok {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
return
}

if rt.Consumed {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token already used")
return
}
if time.Now().Unix() > rt.ExpiresAt {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
return
}
if rt.ClientID != client.ID {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
return
}

// Rotate: mark old consumed.
rt.Consumed = true
adapter.Upsert(r.Context(), "rt:"+rtID, rt, time.Until(time.Unix(rt.ExpiresAt, 0)))

now := time.Now()
at, _, err := issueAccessToken(cfg, ks, adapter, r.Context(), rt.AccountID, client.ID, rt.Scopes, now)
if err != nil {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue access token")
return
}

newRT, err := issueRefreshToken(cfg, adapter, r.Context(), rt.AccountID, client.ID, rt.GrantID, rt.Scopes, now)
if err != nil {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue refresh token")
return
}

resp := map[string]interface{}{
"access_token":  at,
"token_type":    "Bearer",
"expires_in":    int(cfg.AccessTokenTTL.Seconds()),
"refresh_token": newRT,
"scope":         strings.Join(rt.Scopes, " "),
}
w.Header().Set("Content-Type", "application/json")
w.Header().Set("Cache-Control", "no-store")
json.NewEncoder(w).Encode(resp)
}

func handleDeviceCode(w http.ResponseWriter, r *http.Request, cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, client *config.ClientConfig) {
deviceCodeParam := r.FormValue("device_code")
if deviceCodeParam == "" {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "device_code is required")
return
}

raw, err := adapter.Find(r.Context(), "device:"+deviceCodeParam)
if err != nil {
middleware.WriteOAuthError(w, http.StatusBadRequest, "expired_token", "device code expired or not found")
return
}
dc, ok := raw.(*models.DeviceCode)
if !ok {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
return
}

if dc.ClientID != client.ID {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
return
}
if time.Now().Unix() > dc.ExpiresAt {
middleware.WriteOAuthError(w, http.StatusBadRequest, "expired_token", "device code has expired")
return
}
if dc.Denied {
middleware.WriteOAuthError(w, http.StatusBadRequest, "access_denied", "user denied access")
return
}
if !dc.Verified {
middleware.WriteOAuthError(w, http.StatusBadRequest, "authorization_pending", "user has not yet authorized the device")
return
}

now := time.Now()
at, _, err := issueAccessToken(cfg, ks, adapter, r.Context(), dc.AccountID, client.ID, dc.Scopes, now)
if err != nil {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue access token")
return
}

rt, err := issueRefreshToken(cfg, adapter, r.Context(), dc.AccountID, client.ID, dc.GrantID, dc.Scopes, now)
if err != nil {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue refresh token")
return
}

// Mark device code consumed.
adapter.Destroy(r.Context(), "device:"+dc.DeviceCode)

resp := map[string]interface{}{
"access_token":  at,
"token_type":    "Bearer",
"expires_in":    int(cfg.AccessTokenTTL.Seconds()),
"refresh_token": rt,
"scope":         strings.Join(dc.Scopes, " "),
}
w.Header().Set("Content-Type", "application/json")
w.Header().Set("Cache-Control", "no-store")
json.NewEncoder(w).Encode(resp)
}

func handleROPC(w http.ResponseWriter, r *http.Request, cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, client *config.ClientConfig) {
username := r.FormValue("username")
password := r.FormValue("password")
scope := r.FormValue("scope")

if cfg.AuthenticateAccount == nil {
middleware.WriteOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "ROPC not configured")
return
}

account, err := cfg.AuthenticateAccount(r.Context(), username, password)
if err != nil || account == nil {
middleware.WriteOAuthError(w, http.StatusUnauthorized, "invalid_grant", "invalid credentials")
return
}

scopes := strings.Fields(scope)
now := time.Now()

at, _, err := issueAccessToken(cfg, ks, adapter, r.Context(), account.Sub, client.ID, scopes, now)
if err != nil {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue access token")
return
}

resp := map[string]interface{}{
"access_token": at,
"token_type":   "Bearer",
"expires_in":   int(cfg.AccessTokenTTL.Seconds()),
"scope":        scope,
}

if containsString(scopes, "offline_access") {
rt, err := issueRefreshToken(cfg, adapter, r.Context(), account.Sub, client.ID, "", scopes, now)
if err == nil {
resp["refresh_token"] = rt
}
}

if containsString(scopes, "openid") {
idt, err := issueIDToken(cfg, ks, r.Context(), account.Sub, client.ID, "", "", now.Unix(), now)
if err == nil {
resp["id_token"] = idt
}
}

w.Header().Set("Content-Type", "application/json")
w.Header().Set("Cache-Control", "no-store")
json.NewEncoder(w).Encode(resp)
}
