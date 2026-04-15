package crypto

import (
"crypto/sha256"
"encoding/base64"
"fmt"
"time"

gojwt "github.com/golang-jwt/jwt/v5"
"github.com/google/uuid"
)

// AccessTokenClaims holds the claims for an access token.
type AccessTokenClaims struct {
Issuer    string
Subject   string
Audience  []string
Scope     string
JTI       string
IssuedAt  time.Time
ExpiresAt time.Time
ClientID  string
}

// IDTokenClaims holds the claims for an ID token.
type IDTokenClaims struct {
Issuer    string
Subject   string
Audience  []string
Nonce     string
AuthTime  int64
AtHash    string
IssuedAt  time.Time
ExpiresAt time.Time
Extra     map[string]interface{}
}

// IssueAccessToken signs and returns a JWT access token.
func IssueAccessToken(ks *Keystore, claims AccessTokenClaims) (string, error) {
priv, kid := ks.SigningKey()
if claims.JTI == "" {
claims.JTI = uuid.New().String()
}
mapClaims := gojwt.MapClaims{
"iss":       claims.Issuer,
"sub":       claims.Subject,
"aud":       claims.Audience,
"scope":     claims.Scope,
"jti":       claims.JTI,
"iat":       claims.IssuedAt.Unix(),
"exp":       claims.ExpiresAt.Unix(),
"client_id": claims.ClientID,
}
token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, mapClaims)
token.Header["kid"] = kid
return token.SignedString(priv)
}

// IssueIDToken signs and returns a JWT ID token.
func IssueIDToken(ks *Keystore, claims IDTokenClaims) (string, error) {
priv, kid := ks.SigningKey()
mapClaims := gojwt.MapClaims{
"iss":       claims.Issuer,
"sub":       claims.Subject,
"aud":       claims.Audience,
"iat":       claims.IssuedAt.Unix(),
"exp":       claims.ExpiresAt.Unix(),
"auth_time": claims.AuthTime,
}
if claims.Nonce != "" {
mapClaims["nonce"] = claims.Nonce
}
if claims.AtHash != "" {
mapClaims["at_hash"] = claims.AtHash
}
for k, v := range claims.Extra {
mapClaims[k] = v
}
token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, mapClaims)
token.Header["kid"] = kid
return token.SignedString(priv)
}

// ParseAccessToken validates and parses a JWT access token.
func ParseAccessToken(ks *Keystore, tokenString string) (*gojwt.MapClaims, error) {
priv, _ := ks.SigningKey()
token, err := gojwt.Parse(tokenString, func(t *gojwt.Token) (interface{}, error) {
if _, ok := t.Method.(*gojwt.SigningMethodRSA); !ok {
return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
}
return &priv.PublicKey, nil
})
if err != nil {
return nil, err
}
if claims, ok := token.Claims.(gojwt.MapClaims); ok && token.Valid {
return &claims, nil
}
return nil, fmt.Errorf("invalid token")
}

// ComputeAtHash computes the at_hash claim value from an access token string.
func ComputeAtHash(accessToken string) string {
h := sha256.Sum256([]byte(accessToken))
half := h[:len(h)/2]
return base64.RawURLEncoding.EncodeToString(half)
}
