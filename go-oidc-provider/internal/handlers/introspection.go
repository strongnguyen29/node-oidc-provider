package handlers

import (
"encoding/json"
"net/http"
"time"

"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/models"
"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

// NewIntrospectionHandler handles POST /introspect.
func NewIntrospectionHandler(cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter) http.HandlerFunc {
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

token := r.FormValue("token")
if token == "" {
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]bool{"active": false})
return
}

w.Header().Set("Content-Type", "application/json")

// Try as JWT access token.
claims, err := crypto.ParseAccessToken(ks, token)
if err == nil {
sub, _ := (*claims)["sub"].(string)
scope, _ := (*claims)["scope"].(string)
clientID, _ := (*claims)["client_id"].(string)
jti, _ := (*claims)["jti"].(string)
var exp, iat int64
switch v := (*claims)["exp"].(type) {
case float64:
exp = int64(v)
}
switch v := (*claims)["iat"].(type) {
case float64:
iat = int64(v)
}
// Check if JTI was revoked.
if jti != "" {
if _, err := adapter.Find(r.Context(), "jti:"+jti); err != nil {
json.NewEncoder(w).Encode(map[string]interface{}{"active": false})
return
}
}
json.NewEncoder(w).Encode(map[string]interface{}{
"active":     true,
"sub":        sub,
"scope":      scope,
"client_id":  clientID,
"exp":        exp,
"iat":        iat,
"iss":        cfg.Issuer,
"jti":        jti,
"token_type": "access_token",
})
return
}

// Try as refresh token.
raw, err := adapter.Find(r.Context(), "rt:"+token)
if err == nil {
if rt, ok := raw.(*models.RefreshToken); ok && !rt.Consumed && time.Now().Unix() <= rt.ExpiresAt {
json.NewEncoder(w).Encode(map[string]interface{}{
"active":    true,
"sub":       rt.AccountID,
"client_id": rt.ClientID,
"exp":       rt.ExpiresAt,
"iat":       rt.CreatedAt,
})
return
}
}

json.NewEncoder(w).Encode(map[string]bool{"active": false})
}
}
