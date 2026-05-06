package handlers

import (
"encoding/json"
"log/slog"
"net/http"
"time"

"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
"github.com/strongnguyen29/go-oidc-provider/internal/logging"
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

log := logging.FromContext(r.Context())

// Try as JWT access token. validateAccessToken bundles signature, issuer
// and JTI-revocation checks so introspection cannot disagree with the
// userinfo endpoint about whether a token is still valid.
if claims, err := validateAccessToken(r.Context(), ks, adapter, cfg, token); err == nil {
sub, _ := claims["sub"].(string)
scope, _ := claims["scope"].(string)
clientID, _ := claims["client_id"].(string)
jti, _ := claims["jti"].(string)
log.LogAttrs(r.Context(), slog.LevelDebug, "introspect_active_access_token",
slog.String("client_id", clientID),
slog.String("sub", sub),
slog.String("jti", logging.RedactToken(jti)),
)
var exp, iat int64
switch v := claims["exp"].(type) {
case float64:
exp = int64(v)
}
switch v := claims["iat"].(type) {
case float64:
iat = int64(v)
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
log.LogAttrs(r.Context(), slog.LevelDebug, "introspect_active_refresh_token",
slog.String("client_id", rt.ClientID),
slog.String("sub", rt.AccountID),
)
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

log.LogAttrs(r.Context(), slog.LevelDebug, "introspect_inactive",
slog.String("client_id", client.ID),
)
json.NewEncoder(w).Encode(map[string]bool{"active": false})
}
}
