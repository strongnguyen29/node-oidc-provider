package handlers

import (
"context"
"fmt"
"net/http"
"net/url"
"strings"
"time"

"github.com/google/uuid"
"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/models"
"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

// containsString returns true if slice contains s.
func containsString(slice []string, s string) bool {
for _, v := range slice {
if v == s {
return true
}
}
return false
}

// hasAllScopes returns true if all requested scopes are in consented.
func hasAllScopes(consented, requested []string) bool {
m := make(map[string]bool, len(consented))
for _, s := range consented {
m[s] = true
}
for _, s := range requested {
if !m[s] {
return false
}
}
return true
}

// buildAuthorizeURL reconstructs the /authorize URL from stored params.
func buildAuthorizeURL(params map[string]string) string {
q := url.Values{}
for k, v := range params {
if v != "" {
q.Set(k, v)
}
}
return "/authorize?" + q.Encode()
}

// issueAccessToken creates, signs, and stores an access token.
func issueAccessToken(cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, ctx context.Context, accountID, clientID string, scopes []string, now time.Time) (string, string, error) {
jti := uuid.New().String()
claims := crypto.AccessTokenClaims{
Issuer:    cfg.Issuer,
Subject:   accountID,
Audience:  []string{cfg.Issuer},
Scope:     strings.Join(scopes, " "),
JTI:       jti,
IssuedAt:  now,
ExpiresAt: now.Add(cfg.AccessTokenTTL),
ClientID:  clientID,
}
at, err := crypto.IssueAccessToken(ks, claims)
if err != nil {
return "", "", err
}
adapter.Upsert(ctx, "jti:"+jti, jti, cfg.AccessTokenTTL)
return at, jti, nil
}

// issueRefreshToken creates and stores a refresh token.
func issueRefreshToken(cfg *config.Config, adapter store.Adapter, ctx context.Context, accountID, clientID, grantID string, scopes []string, now time.Time) (string, error) {
rtID := uuid.New().String()
rt := &models.RefreshToken{
ID:        rtID,
AccountID: accountID,
ClientID:  clientID,
Scopes:    scopes,
GrantID:   grantID,
CreatedAt: now.Unix(),
ExpiresAt: now.Add(cfg.RefreshTokenTTL).Unix(),
}
if err := adapter.Upsert(ctx, "rt:"+rtID, rt, cfg.RefreshTokenTTL); err != nil {
return "", err
}
return rtID, nil
}

// issueIDToken creates and signs an ID token.
func issueIDToken(cfg *config.Config, ks *crypto.Keystore, ctx context.Context, accountID, clientID, nonce, atHash string, authTime int64, now time.Time) (string, error) {
extra := map[string]interface{}{}
if cfg.FindAccount != nil {
account, err := cfg.FindAccount(ctx, accountID)
if err == nil && account != nil {
for k, v := range account.Claims {
extra[k] = v
}
}
}
idClaims := crypto.IDTokenClaims{
Issuer:    cfg.Issuer,
Subject:   accountID,
Audience:  []string{clientID},
Nonce:     nonce,
AuthTime:  authTime,
AtHash:    atHash,
IssuedAt:  now,
ExpiresAt: now.Add(cfg.AccessTokenTTL),
Extra:     extra,
}
return crypto.IssueIDToken(ks, idClaims)
}

// completeAuthFlow issues tokens/codes and redirects to the redirect_uri.
func completeAuthFlow(
w http.ResponseWriter, r *http.Request,
cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, sm *middleware.SessionMiddleware,
session *models.Session, params map[string]string,
) {
responseType := params["response_type"]
clientID := params["client_id"]
redirectURI := params["redirect_uri"]
scope := params["scope"]
state := params["state"]
nonce := params["nonce"]
codeChallenge := params["code_challenge"]
codeChallengeMethod := params["code_challenge_method"]

scopes := strings.Fields(scope)
now := time.Now()

// Ensure grant and client session exist.
cs := session.Clients[clientID]
grantID := ""
if cs != nil {
grantID = cs.GrantID
}
if grantID == "" {
grantID = uuid.New().String()
grant := &models.Grant{
ID:        grantID,
AccountID: session.AccountID,
ClientID:  clientID,
Scopes:    scopes,
CreatedAt: now.Unix(),
}
adapter.Upsert(r.Context(), "grant:"+grantID, grant, 365*24*time.Hour)
if session.Clients == nil {
session.Clients = make(map[string]*models.ClientSession)
}
if session.Clients[clientID] == nil {
session.Clients[clientID] = &models.ClientSession{}
}
session.Clients[clientID].GrantID = grantID
adapter.Upsert(r.Context(), "session:"+session.ID, session, 24*time.Hour)
}

rtypes := strings.Fields(responseType)
isImplicit := !containsString(rtypes, "code")

var accessTokenStr, idTokenStr, authCode string

if containsString(rtypes, "code") {
code := uuid.New().String()
authCode = code
ac := &models.AuthorizationCode{
Code:                code,
ClientID:            clientID,
RedirectURI:         redirectURI,
Scopes:              scopes,
CodeChallenge:       codeChallenge,
CodeChallengeMethod: codeChallengeMethod,
Nonce:               nonce,
AccountID:           session.AccountID,
SessionID:           session.ID,
GrantID:             grantID,
CreatedAt:           now.Unix(),
ExpiresAt:           now.Add(cfg.AuthCodeTTL).Unix(),
}
adapter.Upsert(r.Context(), "code:"+code, ac, cfg.AuthCodeTTL)
}

if containsString(rtypes, "token") {
at, _, err := issueAccessToken(cfg, ks, adapter, r.Context(), session.AccountID, clientID, scopes, now)
if err != nil {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue access token")
return
}
accessTokenStr = at
}

if containsString(rtypes, "id_token") {
atHash := ""
if accessTokenStr != "" {
atHash = crypto.ComputeAtHash(accessTokenStr)
}
idt, err := issueIDToken(cfg, ks, r.Context(), session.AccountID, clientID, nonce, atHash, session.LoginTime, now)
if err != nil {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue id_token")
return
}
idTokenStr = idt
}

redirectURL, err := url.Parse(redirectURI)
if err != nil {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "invalid redirect_uri")
return
}

if isImplicit {
frag := url.Values{}
if accessTokenStr != "" {
frag.Set("access_token", accessTokenStr)
frag.Set("token_type", "Bearer")
frag.Set("expires_in", fmt.Sprintf("%d", int(cfg.AccessTokenTTL.Seconds())))
}
if idTokenStr != "" {
frag.Set("id_token", idTokenStr)
}
if state != "" {
frag.Set("state", state)
}
redirectURL.Fragment = frag.Encode()
} else {
q := redirectURL.Query()
if authCode != "" {
q.Set("code", authCode)
}
if state != "" {
q.Set("state", state)
}
redirectURL.RawQuery = q.Encode()
}

http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
