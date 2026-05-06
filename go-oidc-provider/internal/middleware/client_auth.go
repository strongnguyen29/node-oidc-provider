package middleware

import (
"context"
"crypto/subtle"
"encoding/base64"
"log/slog"
"net/http"
"strings"

"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/logging"
)

type clientContextKey string

// ClientContextKey is the context key for the authenticated client.
const ClientContextKey clientContextKey = "client"

// ClientAuthMiddleware extracts and validates client credentials.
func ClientAuthMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
return func(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
attemptedID, method := observeClientCreds(r)
client := extractClient(r, cfg)
log := logging.FromContext(r.Context())
if client == nil {
log.LogAttrs(r.Context(), slog.LevelWarn, "client_auth_failed",
slog.String("client_id", attemptedID),
slog.String("auth_method", method),
)
WriteOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
return
}
log.LogAttrs(r.Context(), slog.LevelDebug, "client_auth_ok",
slog.String("client_id", client.ID),
slog.String("auth_method", method),
)
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

// Constant-time compare prevents leaking the registered secret via timing
// side channels (the byte-by-byte cost of `==` would correlate with the
// length of the matching prefix). Empty inputs are rejected outright so
// misconfigured clients with an empty Secret cannot authenticate.
if client.Secret == "" || clientSecret == "" {
return nil
}
if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
return nil
}

return client
}

// observeClientCreds returns the client_id the request *attempted* to use and
// the auth method (basic/form/none). Used purely for logging: we want to
// record which credential a failed authentication tried to present without
// logging the secret itself. Returns "" / "none" when no credentials were
// supplied at all.
func observeClientCreds(r *http.Request) (string, string) {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				return parts[0], "basic"
			}
		}
		return "", "basic"
	}
	// r.ParseForm is idempotent; calling it here means the downstream
	// extractClient call sees the same parsed form.
	if err := r.ParseForm(); err == nil {
		if id := r.PostFormValue("client_id"); id != "" {
			return id, "form"
		}
	}
	return "", "none"
}

// ClientFromContext retrieves the authenticated client from context.
func ClientFromContext(ctx context.Context) *config.ClientConfig {
c, _ := ctx.Value(ClientContextKey).(*config.ClientConfig)
return c
}
