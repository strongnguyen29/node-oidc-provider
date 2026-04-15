package handlers

import (
"encoding/json"
"crypto/rand"
	"math/big"
"net/http"
"strings"
"time"

"github.com/google/uuid"
"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/models"
"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

const userCodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func generateUserCode() string {
b := make([]byte, 8)
for i := range b {
n, err := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeChars))))
		if err != nil {
			panic("crypto/rand failure: " + err.Error())
		}
		b[i] = userCodeChars[n.Int64()]
}
return string(b[:4]) + "-" + string(b[4:])
}

// NewDeviceAuthorizationHandler handles POST /device/authorization.
func NewDeviceAuthorizationHandler(cfg *config.Config, adapter store.Adapter) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
client := middleware.ClientFromContext(r.Context())
if client == nil {
middleware.WriteOAuthError(w, http.StatusUnauthorized, "invalid_client", "client not authenticated")
return
}

if err := r.ParseForm(); err != nil {
middleware.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "failed to parse form")
return
}

scope := r.FormValue("scope")
scopes := strings.Fields(scope)

deviceCode := uuid.New().String()
userCode := generateUserCode()
now := time.Now()

dc := &models.DeviceCode{
DeviceCode: deviceCode,
UserCode:   userCode,
ClientID:   client.ID,
Scopes:     scopes,
CreatedAt:  now.Unix(),
ExpiresAt:  now.Add(cfg.DeviceCodeTTL).Unix(),
}

adapter.Upsert(r.Context(), "device:"+deviceCode, dc, cfg.DeviceCodeTTL)
adapter.Upsert(r.Context(), "usercode:"+userCode, deviceCode, cfg.DeviceCodeTTL)

verificationURI := cfg.Issuer + "/device"
resp := map[string]interface{}{
"device_code":              deviceCode,
"user_code":                userCode,
"verification_uri":         verificationURI,
"verification_uri_complete": verificationURI + "?user_code=" + userCode,
"expires_in":               int(cfg.DeviceCodeTTL.Seconds()),
"interval":                 cfg.DeviceInterval,
}

w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(resp)
}
}
