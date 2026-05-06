package handlers

import (
"html/template"
"net/http"
"net/url"

"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/store"
"github.com/strongnguyen29/go-oidc-provider/internal/views"

gojwt "github.com/golang-jwt/jwt/v5"
)

var logoutConfirmTmpl = template.Must(template.New("error").ParseFS(views.FS, "error.html"))

// NewEndSessionHandler handles GET /logout.
func NewEndSessionHandler(cfg *config.Config, adapter store.Adapter, sm *middleware.SessionMiddleware, ks *crypto.Keystore) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
q := r.URL.Query()
idTokenHint := q.Get("id_token_hint")
postLogoutRedirectURI := q.Get("post_logout_redirect_uri")
state := q.Get("state")
clientID := q.Get("client_id")

// Parse id_token_hint with signature verification (allowing expired tokens) to get client_id.
if idTokenHint != "" && clientID == "" {
pubKey := ks.PublicKey()
token, err := gojwt.Parse(
idTokenHint,
func(t *gojwt.Token) (interface{}, error) { return pubKey, nil },
gojwt.WithoutClaimsValidation(),
)
if err == nil && token != nil {
if claims, ok := token.Claims.(gojwt.MapClaims); ok {
if aud, ok := claims["aud"]; ok {
switch v := aud.(type) {
case string:
clientID = v
case []interface{}:
if len(v) > 0 {
clientID, _ = v[0].(string)
}
}
}
}
}
}

// Destroy session.
sessionID := sm.GetSessionID(r)
if sessionID != "" {
adapter.Destroy(r.Context(), "session:"+sessionID)
sm.ClearSession(w)
}

// Validate post_logout_redirect_uri against the registered list and redirect using
// the registered value (not the raw user-supplied string) to prevent open redirect.
if postLogoutRedirectURI != "" && clientID != "" {
client := cfg.FindClient(clientID)
if client != nil {
for _, registeredURI := range client.PostLogoutRedirectURIs {
if registeredURI == postLogoutRedirectURI {
// Use the trusted registered URI, not the user-supplied value.
redirectTarget := registeredURI
if state != "" {
redirectTarget += "?state=" + url.QueryEscape(state)
}
http.Redirect(w, r, redirectTarget, http.StatusFound)
return
}
}
}
}

// Render confirmation page.
w.Header().Set("Content-Type", "text/html")
logoutConfirmTmpl.ExecuteTemplate(w, "error.html", map[string]string{
"Title":       "Signed Out",
"Description": "You have been successfully signed out.",
})
}
}
