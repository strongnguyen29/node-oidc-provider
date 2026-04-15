package middleware

import (
"net/http"

"github.com/gorilla/securecookie"
)

const sessionCookieName = "_session"

// SessionData holds the data stored in the session cookie (just the session ID).
type SessionData struct {
SessionID string `json:"session_id"`
}

// SessionMiddleware handles encrypted session cookies.
type SessionMiddleware struct {
sc *securecookie.SecureCookie
}

// NewSessionMiddleware creates a new SessionMiddleware with the given secret.
func NewSessionMiddleware(secret []byte) *SessionMiddleware {
return &SessionMiddleware{
sc: securecookie.New(secret, nil),
}
}

// GetSessionID extracts and decodes the session ID from the request cookie.
func (sm *SessionMiddleware) GetSessionID(r *http.Request) string {
cookie, err := r.Cookie(sessionCookieName)
if err != nil {
return ""
}
var data SessionData
if err := sm.sc.Decode(sessionCookieName, cookie.Value, &data); err != nil {
return ""
}
return data.SessionID
}

// SaveSessionID encodes the session ID and sets it as a cookie.
func (sm *SessionMiddleware) SaveSessionID(w http.ResponseWriter, sessionID string) error {
data := SessionData{SessionID: sessionID}
encoded, err := sm.sc.Encode(sessionCookieName, data)
if err != nil {
return err
}
http.SetCookie(w, &http.Cookie{
Name:     sessionCookieName,
Value:    encoded,
Path:     "/",
HttpOnly: true,
SameSite: http.SameSiteLaxMode,
})
return nil
}

// ClearSession removes the session cookie.
func (sm *SessionMiddleware) ClearSession(w http.ResponseWriter) {
http.SetCookie(w, &http.Cookie{
Name:     sessionCookieName,
Value:    "",
Path:     "/",
MaxAge:   -1,
HttpOnly: true,
})
}
