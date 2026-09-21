package handlers

import (
"encoding/json"
"net/http"

"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
)

// NewJWKSHandler returns the JWKS endpoint handler.
func NewJWKSHandler(ks *crypto.Keystore) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(ks.PublicJWKS())
}
}
