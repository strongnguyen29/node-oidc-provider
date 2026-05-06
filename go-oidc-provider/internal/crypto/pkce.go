package crypto

import (
"crypto/sha256"
"encoding/base64"
)

// VerifyPKCE checks the PKCE code_verifier against the stored code_challenge.
func VerifyPKCE(method, verifier, challenge string) bool {
switch method {
case "S256":
h := sha256.Sum256([]byte(verifier))
computed := base64.RawURLEncoding.EncodeToString(h[:])
return computed == challenge
case "plain":
return verifier == challenge
default:
return false
}
}
