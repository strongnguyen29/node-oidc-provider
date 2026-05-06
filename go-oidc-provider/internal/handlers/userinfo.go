package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/strongnguyen29/go-oidc-provider/internal/config"
	"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
	"github.com/strongnguyen29/go-oidc-provider/internal/logging"
	"github.com/strongnguyen29/go-oidc-provider/internal/middleware"
	"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

// NewUserInfoHandler handles GET/POST /userinfo. It enforces RFC 6750: a
// failure response carries an RFC 6750 §3 WWW-Authenticate Bearer challenge
// so callers can react to invalid/expired tokens correctly.
func NewUserInfoHandler(cfg *config.Config, ks *crypto.Keystore, adapter store.Adapter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeChallenge := func(status int, code, desc string) {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q, error=%q, error_description=%q`, cfg.Issuer, code, desc))
			middleware.WriteOAuthError(w, status, code, desc)
		}

		// Extract Bearer token.
		tokenStr := ""
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			tokenStr = strings.TrimPrefix(auth, "Bearer ")
		}
		if tokenStr == "" {
			r.ParseForm()
			tokenStr = r.FormValue("access_token")
		}
		if tokenStr == "" {
			writeChallenge(http.StatusUnauthorized, "invalid_token", "missing access token")
			return
		}

		log := logging.FromContext(r.Context())
		claims, err := validateAccessToken(r.Context(), ks, adapter, cfg, tokenStr)
		if err != nil {
			log.LogAttrs(r.Context(), slog.LevelWarn, "userinfo_invalid_token",
				slog.String("err", err.Error()),
			)
			writeChallenge(http.StatusUnauthorized, "invalid_token", "invalid or revoked access token")
			return
		}

		sub, _ := claims["sub"].(string)
		scope, _ := claims["scope"].(string)
		scopes := strings.Fields(scope)

		if cfg.FindAccount == nil {
			middleware.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "account lookup not configured")
			return
		}

		account, err := cfg.FindAccount(r.Context(), sub)
		if err != nil || account == nil {
			log.LogAttrs(r.Context(), slog.LevelWarn, "userinfo_account_not_found",
				slog.String("sub", sub),
				slog.Bool("lookup_error", err != nil),
			)
			writeChallenge(http.StatusUnauthorized, "invalid_token", "account not found")
			return
		}

		log.LogAttrs(r.Context(), slog.LevelDebug, "userinfo_ok",
			slog.String("sub", sub),
			slog.Any("scopes", scopes),
		)

		result := map[string]interface{}{"sub": sub}

		scopeSet := make(map[string]bool)
		for _, s := range scopes {
			scopeSet[s] = true
		}

		if scopeSet["profile"] {
			for _, k := range []string{"name", "given_name", "family_name", "picture", "locale", "updated_at"} {
				if v, ok := account.Claims[k]; ok {
					result[k] = v
				}
			}
		}
		if scopeSet["email"] {
			for _, k := range []string{"email", "email_verified"} {
				if v, ok := account.Claims[k]; ok {
					result[k] = v
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
