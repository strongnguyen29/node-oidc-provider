package handlers

import (
"net/http"
"strings"
"time"

"github.com/google/uuid"
"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
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

// Validate client.
client := cfg.FindClient(clientID)
if client == nil {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
return
}

// Validate redirect_uri.
if !containsString(client.RedirectURIs, redirectURI) {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri not registered")
return
}

// Validate response_type.
if responseType == "" {
middleware.RedirectOAuthError(w, r, redirectURI, client.RedirectURIs, "invalid_request", "response_type is required", state)
return
}

// PKCE enforcement.
if cfg.PKCERequired && strings.Contains(responseType, "code") && codeChallenge == "" {
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

// Determine if interaction is needed.
interactionPrompt := ""

if session == nil || prompt == "login" {
interactionPrompt = "login"
} else if prompt == "select_account" {
interactionPrompt = "select_account"
} else {
cs := session.Clients[clientID]
requestedScopes := strings.Fields(scope)
if cs == nil || prompt == "consent" || !hasAllScopes(cs.Consented, requestedScopes) {
interactionPrompt = "consent"
}
}

if interactionPrompt != "" {
uid := uuid.New().String()
interaction := &models.Interaction{
UID:       uid,
Prompt:    interactionPrompt,
ClientID:  clientID,
Params:    params,
CreatedAt: time.Now().Unix(),
ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
}
if session != nil {
interaction.AccountID = session.AccountID
interaction.SessionID = session.ID
}
adapter.Upsert(r.Context(), "interaction:"+uid, interaction, 10*time.Minute)
http.Redirect(w, r, "/interaction/"+uid, http.StatusFound)
return
}

completeAuthFlow(w, r, cfg, ks, adapter, sm, session, params)
}
}
