package handlers

import (
"html/template"
"net/http"
"strings"
"time"

"github.com/go-chi/chi/v5"
"github.com/google/uuid"
"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/models"
"github.com/strongnguyen29/go-oidc-provider/internal/store"
"github.com/strongnguyen29/go-oidc-provider/internal/views"
)

var (
loginTmpl         = template.Must(template.New("login").ParseFS(views.FS, "login.html"))
consentTmpl       = template.Must(template.New("consent").ParseFS(views.FS, "consent.html"))
selectAccountTmpl = template.Must(template.New("select_account").ParseFS(views.FS, "select_account.html"))
errorTmpl         = template.Must(template.New("error").ParseFS(views.FS, "error.html"))
)

// NewInteractionGetHandler handles GET /interaction/{uid}.
func NewInteractionGetHandler(cfg *config.Config, adapter store.Adapter) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
uid := chi.URLParam(r, "uid")
raw, err := adapter.Find(r.Context(), "interaction:"+uid)
if err != nil {
errorTmpl.ExecuteTemplate(w, "error.html", map[string]string{
"Title":       "Interaction Not Found",
"Description": "This interaction has expired or does not exist.",
})
return
}
interaction, ok := raw.(*models.Interaction)
if !ok {
w.WriteHeader(http.StatusInternalServerError)
return
}

w.Header().Set("Content-Type", "text/html")
switch interaction.Prompt {
case "login":
loginTmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
"UID": uid,
})
case "consent":
scopes := strings.Fields(interaction.Params["scope"])
consentTmpl.ExecuteTemplate(w, "consent.html", map[string]interface{}{
"UID":      uid,
"ClientID": interaction.ClientID,
"Scopes":   scopes,
})
case "select_account":
selectAccountTmpl.ExecuteTemplate(w, "select_account.html", map[string]interface{}{
"UID":       uid,
"AccountID": interaction.AccountID,
})
default:
errorTmpl.ExecuteTemplate(w, "error.html", map[string]string{
"Title":       "Unknown Prompt",
"Description": "Unknown interaction type.",
})
}
}
}

// NewInteractionLoginHandler handles POST /interaction/{uid}/login.
func NewInteractionLoginHandler(cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, sm *middleware.SessionMiddleware) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
uid := chi.URLParam(r, "uid")
raw, err := adapter.Find(r.Context(), "interaction:"+uid)
if err != nil {
w.WriteHeader(http.StatusNotFound)
return
}
interaction, ok := raw.(*models.Interaction)
if !ok {
w.WriteHeader(http.StatusInternalServerError)
return
}

if err := r.ParseForm(); err != nil {
w.WriteHeader(http.StatusBadRequest)
return
}

// Handle select_account: use existing session.
if r.FormValue("use_existing") == "1" && interaction.SessionID != "" {
rawSess, err := adapter.Find(r.Context(), "session:"+interaction.SessionID)
if err == nil {
if sess, ok := rawSess.(*models.Session); ok {
sm.SaveSessionID(w, sess.ID)
http.Redirect(w, r, buildAuthorizeURL(interaction.Params), http.StatusFound)
return
}
}
}

login := r.FormValue("login")
password := r.FormValue("password")

if cfg.AuthenticateAccount == nil {
renderLoginError(w, uid, "Authentication not configured")
return
}

account, err := cfg.AuthenticateAccount(r.Context(), login, password)
if err != nil || account == nil {
renderLoginError(w, uid, "Invalid username or password")
return
}

// Create or update session.
sessionID := sm.GetSessionID(r)
var session *models.Session
if sessionID != "" {
if rawSess, err := adapter.Find(r.Context(), "session:"+sessionID); err == nil {
session, _ = rawSess.(*models.Session)
}
}
if session == nil {
session = &models.Session{
ID:        uuid.New().String(),
Clients:   make(map[string]*models.ClientSession),
LoginTime: time.Now().Unix(),
}
}
session.AccountID = account.Sub
adapter.Upsert(r.Context(), "session:"+session.ID, session, 24*time.Hour)
sm.SaveSessionID(w, session.ID)

// Check if this is a device flow login.
if deviceUserCode := interaction.Params["device_user_code"]; deviceUserCode != "" {
deviceCodeID := interaction.Params["device_code_id"]
if rawDC, err := adapter.Find(r.Context(), "device:"+deviceCodeID); err == nil {
if dc, ok := rawDC.(*models.DeviceCode); ok {
dc.Verified = true
dc.AccountID = account.Sub
adapter.Upsert(r.Context(), "device:"+dc.DeviceCode, dc, cfg.DeviceCodeTTL)
}
}
w.Header().Set("Content-Type", "text/html")
w.Write([]byte(`<!DOCTYPE html><html><body><h2>Device authorized!</h2><p>You may close this window and return to your device.</p></body></html>`))
return
}

// Update interaction and redirect back to authorize.
interaction.AccountID = account.Sub
interaction.SessionID = session.ID
if interaction.Result == nil {
interaction.Result = &models.InteractionResult{}
}
interaction.Result.Login = &models.LoginResult{AccountID: account.Sub}
adapter.Upsert(r.Context(), "interaction:"+uid, interaction, 10*time.Minute)

http.Redirect(w, r, buildAuthorizeURL(interaction.Params), http.StatusFound)
}
}

// NewInteractionConfirmHandler handles POST /interaction/{uid}/confirm.
func NewInteractionConfirmHandler(cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter, sm *middleware.SessionMiddleware) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
uid := chi.URLParam(r, "uid")
raw, err := adapter.Find(r.Context(), "interaction:"+uid)
if err != nil {
w.WriteHeader(http.StatusNotFound)
return
}
interaction, ok := raw.(*models.Interaction)
if !ok {
w.WriteHeader(http.StatusInternalServerError)
return
}

if err := r.ParseForm(); err != nil {
w.WriteHeader(http.StatusBadRequest)
return
}

grantedScopes := r.Form["granted_scopes"]

// Load session and update consent.
sessionID := interaction.SessionID
if sessionID == "" {
sessionID = sm.GetSessionID(r)
}

if sessionID != "" {
if rawSess, err := adapter.Find(r.Context(), "session:"+sessionID); err == nil {
if sess, ok := rawSess.(*models.Session); ok {
if sess.Clients == nil {
sess.Clients = make(map[string]*models.ClientSession)
}
cs := sess.Clients[interaction.ClientID]
if cs == nil {
cs = &models.ClientSession{}
sess.Clients[interaction.ClientID] = cs
}
cs.Consented = grantedScopes
adapter.Upsert(r.Context(), "session:"+sess.ID, sess, 24*time.Hour)
}
}
}

// Update interaction result.
if interaction.Result == nil {
interaction.Result = &models.InteractionResult{}
}
interaction.Result.Consent = &models.ConsentResult{
GrantedScopes: grantedScopes,
}
adapter.Upsert(r.Context(), "interaction:"+uid, interaction, 10*time.Minute)

http.Redirect(w, r, buildAuthorizeURL(interaction.Params), http.StatusFound)
}
}

// NewInteractionAbortHandler handles POST /interaction/{uid}/abort.
func NewInteractionAbortHandler(cfg *config.Config, adapter store.Adapter) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
uid := chi.URLParam(r, "uid")
raw, err := adapter.Find(r.Context(), "interaction:"+uid)
if err != nil {
w.WriteHeader(http.StatusNotFound)
return
}
interaction, ok := raw.(*models.Interaction)
if !ok {
w.WriteHeader(http.StatusInternalServerError)
return
}
redirectURI := interaction.Params["redirect_uri"]
state := interaction.Params["state"]
adapter.Destroy(r.Context(), "interaction:"+uid)
var registeredURIs []string
		if interactionClient := cfg.FindClient(interaction.ClientID); interactionClient != nil {
			registeredURIs = interactionClient.RedirectURIs
		}
		middleware.RedirectOAuthError(w, r, redirectURI, registeredURIs, "access_denied", "user denied access", state)
}
}

func renderLoginError(w http.ResponseWriter, uid, errMsg string) {
w.Header().Set("Content-Type", "text/html")
loginTmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
"UID":   uid,
"Error": errMsg,
})
}
