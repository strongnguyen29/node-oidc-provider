package handlers

import (
"net/http"

"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
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

// Try as JWT (access token) — extract jti and remove from store.
claims, err := crypto.ParseAccessToken(ks, token)
if err == nil {
if jti, ok := (*claims)["jti"].(string); ok && jti != "" {
adapter.Destroy(r.Context(), "jti:"+jti)
}
w.WriteHeader(http.StatusOK)
return
}

// Try as refresh token.
adapter.Destroy(r.Context(), "rt:"+token)

w.WriteHeader(http.StatusOK)
}
}
