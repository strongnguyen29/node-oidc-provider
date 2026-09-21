package middleware

import (
"context"
"encoding/base64"
"net/http"
"strings"

"github.com/strongnguyen29/go-oidc-provider/internal/config"
)

type clientContextKey string

// ClientContextKey is the context key for the authenticated client.
const ClientContextKey clientContextKey = "client"

// ClientAuthMiddleware extracts and validates client credentials.
func ClientAuthMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
return func(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
client := extractClient(r, cfg)
if client == nil {
WriteOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
return
}
ctx := context.WithValue(r.Context(), ClientContextKey, client)
next.ServeHTTP(w, r.WithContext(ctx))
})
}
}

func extractClient(r *http.Request, cfg *config.Config) *config.ClientConfig {
var clientID, clientSecret string

if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Basic ") {
decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
if err == nil {
parts := strings.SplitN(string(decoded), ":", 2)
if len(parts) == 2 {
clientID = parts[0]
clientSecret = parts[1]
}
}
}

if clientID == "" {
if err := r.ParseForm(); err == nil {
clientID = r.FormValue("client_id")
clientSecret = r.FormValue("client_secret")
}
}

if clientID == "" {
return nil
}

client := cfg.FindClient(clientID)
if client == nil {
return nil
}

if client.TokenEndpointAuthMethod == "none" {
return client
}

if client.Secret != clientSecret {
return nil
}

return client
}

// ClientFromContext retrieves the authenticated client from context.
func ClientFromContext(ctx context.Context) *config.ClientConfig {
c, _ := ctx.Value(ClientContextKey).(*config.ClientConfig)
return c
}
