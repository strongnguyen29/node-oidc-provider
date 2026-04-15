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

// RedirectOAuthError redirects to redirectURI with OAuth error params.
func RedirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, errCode, description, state string) {
u, err := url.Parse(redirectURI)
if err != nil {
WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid redirect_uri")
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
