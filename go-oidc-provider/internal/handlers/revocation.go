package handlers

import (
"log/slog"
"net/http"

"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
"github.com/strongnguyen29/go-oidc-provider/internal/logging"
"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

// NewRevocationHandler handles POST /revoke.
func NewRevocationHandler(cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
client := middleware.ClientFromContext(r.Context())
if client == nil {
middleware.WriteOAuthError(w, http.StatusUnauthorized, "invalid_client", "client not authenticated")
return
}

if err := r.ParseForm(); err != nil {
w.WriteHeader(http.StatusOK)
return
}

token := r.FormValue("token")
if token == "" {
w.WriteHeader(http.StatusOK)
return
}

log := logging.FromContext(r.Context())

// Try as JWT (access token) — extract jti and remove from store.
claims, err := crypto.ParseAccessToken(ks, token)
if err == nil {
if jti, ok := (*claims)["jti"].(string); ok && jti != "" {
adapter.Destroy(r.Context(), "jti:"+jti)
log.LogAttrs(r.Context(), slog.LevelInfo, "token_revoked",
slog.String("client_id", client.ID),
slog.String("kind", "access_token"),
slog.String("jti", logging.RedactToken(jti)),
)
}
w.WriteHeader(http.StatusOK)
return
}

// Try as refresh token.
adapter.Destroy(r.Context(), "rt:"+token)
log.LogAttrs(r.Context(), slog.LevelInfo, "token_revoked",
slog.String("client_id", client.ID),
slog.String("kind", "refresh_token"),
slog.String("rt_id", logging.RedactToken(token)),
)

w.WriteHeader(http.StatusOK)
}
}
