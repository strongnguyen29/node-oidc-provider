package handlers

import (
"encoding/json"
"net/http"

"github.com/strongnguyen29/go-oidc-provider/internal/config"
)

// NewDiscoveryHandler returns the OIDC discovery document handler.
func NewDiscoveryHandler(cfg *config.Config) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
doc := map[string]interface{}{
"issuer":                                cfg.Issuer,
"authorization_endpoint":                cfg.Issuer + "/authorize",
"token_endpoint":                        cfg.Issuer + "/token",
"userinfo_endpoint":                     cfg.Issuer + "/userinfo",
"jwks_uri":                              cfg.Issuer + "/jwks",
"device_authorization_endpoint":         cfg.Issuer + "/device/authorization",
"introspection_endpoint":                cfg.Issuer + "/introspect",
"revocation_endpoint":                   cfg.Issuer + "/revoke",
"end_session_endpoint":                  cfg.Issuer + "/logout",
"response_types_supported":              []string{"code", "token", "id_token", "code token", "code id_token", "id_token token", "code id_token token"},
"grant_types_supported":                 cfg.GrantTypes,
"scopes_supported":                      cfg.Scopes,
"subject_types_supported":               []string{"public"},
"id_token_signing_alg_values_supported": []string{"RS256"},
"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "none"},
"claims_supported":                      []string{"sub", "iss", "aud", "iat", "exp", "nonce", "auth_time", "name", "email", "picture"},
"code_challenge_methods_supported":      []string{"S256", "plain"},
}
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(doc)
}
}
