package handlers

import (
"encoding/json"
"net/http"
"strings"

"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
)

// NewUserInfoHandler handles GET/POST /userinfo.
func NewUserInfoHandler(cfg *config.Config, ks *crypto.Keystore) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
// Extract Bearer token.
tokenStr := ""
auth := r.Header.Get("Authorization")
if strings.HasPrefix(auth, "Bearer ") {
tokenStr = strings.TrimPrefix(auth, "Bearer ")
}
if tokenStr == "" {
r.ParseForm()
tokenStr = r.FormValue("access_token")
}
if tokenStr == "" {
middleware.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "missing access token")
return
}

claims, err := crypto.ParseAccessToken(ks, tokenStr)
if err != nil {
middleware.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired access token")
return
}

sub, _ := (*claims)["sub"].(string)
scope, _ := (*claims)["scope"].(string)
scopes := strings.Fields(scope)

if cfg.FindAccount == nil {
middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "account lookup not configured")
return
}

account, err := cfg.FindAccount(r.Context(), sub)
if err != nil || account == nil {
middleware.WriteOAuthError(w, http.StatusNotFound, "invalid_token", "account not found")
return
}

result := map[string]interface{}{"sub": sub}

scopeSet := make(map[string]bool)
for _, s := range scopes {
scopeSet[s] = true
}

if scopeSet["profile"] {
for _, k := range []string{"name", "given_name", "family_name", "picture", "locale", "updated_at"} {
if v, ok := account.Claims[k]; ok {
result[k] = v
}
}
}
if scopeSet["email"] {
for _, k := range []string{"email", "email_verified"} {
if v, ok := account.Claims[k]; ok {
result[k] = v
}
}
}

w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(result)
}
}
