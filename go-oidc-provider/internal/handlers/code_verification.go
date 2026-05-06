package handlers

import (
"html/template"
"net/http"
"time"

"github.com/google/uuid"
"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/models"
"github.com/strongnguyen29/go-oidc-provider/internal/store"
"github.com/strongnguyen29/go-oidc-provider/internal/views"
)

var deviceTmpl = template.Must(template.New("device").ParseFS(views.FS, "device.html"))

// NewDeviceGetHandler handles GET /device.
func NewDeviceGetHandler(cfg *config.Config, adapter store.Adapter) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
userCode := r.URL.Query().Get("user_code")
w.Header().Set("Content-Type", "text/html")
deviceTmpl.ExecuteTemplate(w, "device.html", map[string]interface{}{
"UserCode": userCode,
})
}
}

// NewDevicePostHandler handles POST /device.
func NewDevicePostHandler(cfg *config.Config, adapter store.Adapter, sm *middleware.SessionMiddleware) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
if err := r.ParseForm(); err != nil {
w.WriteHeader(http.StatusBadRequest)
return
}

userCode := r.FormValue("user_code")
if userCode == "" {
w.Header().Set("Content-Type", "text/html")
deviceTmpl.ExecuteTemplate(w, "device.html", map[string]interface{}{
"Error": "Please enter a user code.",
})
return
}

// Find device code by user code.
rawDCID, err := adapter.Find(r.Context(), "usercode:"+userCode)
if err != nil {
w.Header().Set("Content-Type", "text/html")
deviceTmpl.ExecuteTemplate(w, "device.html", map[string]interface{}{
"Error":    "Invalid or expired code. Please try again.",
"UserCode": userCode,
})
return
}
deviceCodeID, ok := rawDCID.(string)
if !ok {
w.WriteHeader(http.StatusInternalServerError)
return
}

rawDC, err := adapter.Find(r.Context(), "device:"+deviceCodeID)
if err != nil {
w.Header().Set("Content-Type", "text/html")
deviceTmpl.ExecuteTemplate(w, "device.html", map[string]interface{}{
"Error":    "Code expired. Please restart the authorization on your device.",
"UserCode": userCode,
})
return
}
dc, ok := rawDC.(*models.DeviceCode)
if !ok {
w.WriteHeader(http.StatusInternalServerError)
return
}

// Check session.
sessionID := sm.GetSessionID(r)
var session *models.Session
if sessionID != "" {
if rawSess, err := adapter.Find(r.Context(), "session:"+sessionID); err == nil {
session, _ = rawSess.(*models.Session)
}
}

if session == nil {
// Redirect to login interaction with device info in params.
uid := uuid.New().String()
interaction := &models.Interaction{
UID:      uid,
Prompt:   "login",
ClientID: dc.ClientID,
Params: map[string]string{
"device_user_code": userCode,
"device_code_id":   dc.DeviceCode,
},
CreatedAt: time.Now().Unix(),
ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
}
adapter.Upsert(r.Context(), "interaction:"+uid, interaction, 10*time.Minute)
http.Redirect(w, r, "/interaction/"+uid, http.StatusFound)
return
}

// Session exists: mark device verified.
dc.Verified = true
dc.AccountID = session.AccountID
adapter.Upsert(r.Context(), "device:"+dc.DeviceCode, dc, cfg.DeviceCodeTTL)

w.Header().Set("Content-Type", "text/html")
deviceTmpl.ExecuteTemplate(w, "device.html", map[string]interface{}{
"Success": true,
})
}
}
