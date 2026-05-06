package middleware

import (
"encoding/json"
"net/http"
"net/url"
)

// WriteOAuthError writes a JSON OAuth error response.
func WriteOAuthError(w http.ResponseWriter, statusCode int, errCode, description string) {
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(statusCode)
json.NewEncoder(w).Encode(map[string]string{
"error":             errCode,
"error_description": description,
})
}

// RedirectOAuthError redirects to a validated redirect URI with OAuth error params.
// registeredRedirectURIs must be the list of URIs registered for the client; the
// actual redirect target is sourced from that list (not the raw user-provided value)
// to prevent open-redirect attacks.
func RedirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI string, registeredRedirectURIs []string, errCode, description, state string) {
// Use the value from the trusted registered list, not directly from user input.
trustedURI := ""
for _, reg := range registeredRedirectURIs {
if reg == redirectURI {
trustedURI = reg
break
}
}
if trustedURI == "" {
WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri not permitted")
return
}
u, err := url.Parse(trustedURI)
if err != nil {
WriteOAuthError(w, http.StatusInternalServerError, "server_error", "invalid redirect_uri")
return
}
q := u.Query()
q.Set("error", errCode)
if description != "" {
q.Set("error_description", description)
}
if state != "" {
q.Set("state", state)
}
u.RawQuery = q.Encode()
http.Redirect(w, r, u.String(), http.StatusFound)
}
