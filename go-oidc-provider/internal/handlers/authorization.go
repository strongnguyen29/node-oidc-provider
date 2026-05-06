package handlers

import (
"log/slog"
"net/http"
"strings"

"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
"github.com/strongnguyen29/go-oidc-provider/internal/logging"
"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/models"
"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

// NewAuthorizationHandler handles GET /authorize.
func NewAuthorizationHandler(cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, sm *middleware.SessionMiddleware) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
q := r.URL.Query()
responseType := q.Get("response_type")
clientID := q.Get("client_id")
redirectURI := q.Get("redirect_uri")
scope := q.Get("scope")
state := q.Get("state")
nonce := q.Get("nonce")
codeChallenge := q.Get("code_challenge")
codeChallengeMethod := q.Get("code_challenge_method")
prompt := q.Get("prompt")

log := logging.FromContext(r.Context())
log.LogAttrs(r.Context(), slog.LevelDebug, "authorize_request",
slog.String("client_id", clientID),
slog.String("response_type", responseType),
slog.String("redirect_uri", redirectURI),
slog.String("scope", scope),
slog.String("prompt", prompt),
slog.Bool("pkce", codeChallenge != ""),
)

// Validate client.
client := cfg.FindClient(clientID)
if client == nil {
log.LogAttrs(r.Context(), slog.LevelWarn, "authorize_unknown_client",
slog.String("client_id", clientID))
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
return
}

// Validate redirect_uri.
if !containsString(client.RedirectURIs, redirectURI) {
log.LogAttrs(r.Context(), slog.LevelWarn, "authorize_redirect_uri_not_registered",
slog.String("client_id", clientID),
slog.String("redirect_uri", redirectURI),
)
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri not registered")
return
}

// Validate response_type.
if responseType == "" {
middleware.RedirectOAuthError(w, r, redirectURI, client.RedirectURIs, "invalid_request", "response_type is required", state)
return
}
// RFC 6749 §3.1.1 / OIDC §3.1.2.4 — reject response_types not registered
// for the client. Empty ResponseTypes is treated as permissive for
// backward compatibility (a startup warning surfaces this misconfig).
if len(client.ResponseTypes) > 0 && !responseTypeAllowed(responseType, client.ResponseTypes) {
middleware.RedirectOAuthError(w, r, redirectURI, client.RedirectURIs, "unauthorized_client", "response_type not allowed for this client", state)
return
}

// PKCE enforcement.
if cfg.PKCERequired && strings.Contains(responseType, "code") && codeChallenge == "" {
log.LogAttrs(r.Context(), slog.LevelWarn, "authorize_pkce_missing",
slog.String("client_id", clientID),
slog.String("response_type", responseType),
)
middleware.RedirectOAuthError(w, r, redirectURI, client.RedirectURIs, "invalid_request", "code_challenge required", state)
return
}

// Collect params for interaction storage.
params := map[string]string{
"response_type": responseType,
"client_id":     clientID,
"redirect_uri":  redirectURI,
"scope":         scope,
"state":         state,
"nonce":         nonce,
"prompt":        prompt,
}
if codeChallenge != "" {
params["code_challenge"] = codeChallenge
if codeChallengeMethod == "" {
codeChallengeMethod = "plain"
}
params["code_challenge_method"] = codeChallengeMethod
}

// Load session.
sessionID := sm.GetSessionID(r)
var session *models.Session
if sessionID != "" {
if raw, err := adapter.Find(r.Context(), "session:"+sessionID); err == nil {
if s, ok := raw.(*models.Session); ok {
session = s
}
}
}

dispatchNext(w, r, cfg, ks, adapter, sm, client, session, params)
}
}
