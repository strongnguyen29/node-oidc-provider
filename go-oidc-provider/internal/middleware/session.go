package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"

	"github.com/gorilla/securecookie"
)

const sessionCookieName = "_session"

// SessionData holds the data stored in the session cookie (just the session ID).
type SessionData struct {
	SessionID string `json:"session_id"`
}

// SessionMiddleware handles encrypted session cookies and CSRF tokens.
type SessionMiddleware struct {
	sc         *securecookie.SecureCookie
	secure     bool // whether to set the Secure flag on cookies (true for HTTPS issuers)
	csrfSecret []byte
}

// NewSessionMiddleware creates a new SessionMiddleware with the given secret.
// secure should be true when the provider issuer uses HTTPS.
func NewSessionMiddleware(secret []byte, secure bool) *SessionMiddleware {
	csrfDigest := sha256.Sum256(append(append([]byte{}, secret...), []byte("csrf")...))
	return &SessionMiddleware{
		sc:         securecookie.New(secret, nil),
		secure:     secure,
		csrfSecret: csrfDigest[:],
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
		Secure:   sm.secure,
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
		Secure:   sm.secure,
	})
}

// CSRFToken derives a deterministic HMAC-SHA256 token bound to a stable
// identifier (typically the interaction uid or device user_code). The token
// is safe to embed into HTML forms because the identifier is short-lived
// and the HMAC key never leaves the server.
func (sm *SessionMiddleware) CSRFToken(id string) string {
	mac := hmac.New(sha256.New, sm.csrfSecret)
	mac.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ValidateCSRF compares a submitted token against the expected value for id
// in constant time. Returns true on a match.
func (sm *SessionMiddleware) ValidateCSRF(id, token string) bool {
	if id == "" || token == "" {
		return false
	}
	expected := sm.CSRFToken(id)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
}
