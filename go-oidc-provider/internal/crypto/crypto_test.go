package crypto_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
)

// computeS256 replicates the S256 challenge computation so tests can build
// expected values without depending on internals.
func computeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func newKS(t *testing.T) *crypto.Keystore {
	t.Helper()
	ks, err := crypto.NewKeystore()
	if err != nil {
		t.Fatalf("NewKeystore: %v", err)
	}
	return ks
}

// ---------------------------------------------------------------------------
// Keystore
// ---------------------------------------------------------------------------

func TestKeystore_NewKeystore(t *testing.T) {
	ks, err := crypto.NewKeystore()
	if err != nil {
		t.Fatalf("NewKeystore: %v", err)
	}
	if ks == nil {
		t.Fatal("expected non-nil keystore")
	}
}

func TestKeystore_SigningKey_StableAcrossCalls(t *testing.T) {
	ks := newKS(t)
	k1, id1 := ks.SigningKey()
	k2, id2 := ks.SigningKey()
	if k1 != k2 {
		t.Error("SigningKey must return the same private key every call")
	}
	if id1 != id2 {
		t.Error("SigningKey must return the same kid every call")
	}
	if k1 == nil {
		t.Error("private key must be non-nil")
	}
	if id1 == "" {
		t.Error("kid must be non-empty")
	}
}

func TestKeystore_TwoKeystores_DifferentKIDs(t *testing.T) {
	ks1, ks2 := newKS(t), newKS(t)
	_, kid1 := ks1.SigningKey()
	_, kid2 := ks2.SigningKey()
	if kid1 == kid2 {
		t.Error("two independently generated keystores should have different kids")
	}
}

func TestKeystore_PublicJWKS(t *testing.T) {
	ks := newKS(t)
	_, kid := ks.SigningKey()
	jwks := ks.PublicJWKS()

	if len(jwks.Keys) == 0 {
		t.Fatal("JWKS must contain at least one key")
	}
	k := jwks.Keys[0]
	if k.KeyID != kid {
		t.Errorf("expected kid=%s, got %s", kid, k.KeyID)
	}
	if k.Algorithm != "RS256" {
		t.Errorf("expected alg=RS256, got %s", k.Algorithm)
	}
	if k.Use != "sig" {
		t.Errorf("expected use=sig, got %s", k.Use)
	}
}

func TestKeystore_PublicKey_MatchesSigningKey(t *testing.T) {
	ks := newKS(t)
	priv, _ := ks.SigningKey()
	pub := ks.PublicKey()
	if pub == nil {
		t.Fatal("PublicKey must not be nil")
	}
	if pub != &priv.PublicKey {
		t.Error("PublicKey must be the address of priv.PublicKey")
	}
}

// ---------------------------------------------------------------------------
// Access token — issue + parse
// ---------------------------------------------------------------------------

func makeATClaims(issuer string) crypto.AccessTokenClaims {
	now := time.Now()
	return crypto.AccessTokenClaims{
		Issuer:    issuer,
		Subject:   "user-42",
		Audience:  []string{issuer},
		Scope:     "openid profile",
		JTI:       "jti-abc",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		ClientID:  "client-1",
	}
}

func TestIssueAccessToken_ReturnsNonEmpty(t *testing.T) {
	ks := newKS(t)
	tok, err := crypto.IssueAccessToken(ks, makeATClaims("https://iss.example.com"))
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token string")
	}
}

func TestParseAccessToken_RoundTrip(t *testing.T) {
	ks := newKS(t)
	claims := makeATClaims("https://iss.example.com")

	tok, err := crypto.IssueAccessToken(ks, claims)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	parsed, err := crypto.ParseAccessToken(ks, tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}

	check := func(field, want string) {
		t.Helper()
		got, _ := (*parsed)[field].(string)
		if got != want {
			t.Errorf("claim %s: expected %q, got %q", field, want, got)
		}
	}
	check("sub", claims.Subject)
	check("scope", claims.Scope)
	check("jti", claims.JTI)
	check("client_id", claims.ClientID)
	check("iss", claims.Issuer)
}

func TestIssueAccessToken_AutoGeneratesJTI(t *testing.T) {
	ks := newKS(t)
	claims := makeATClaims("https://iss.example.com")
	claims.JTI = "" // ask issuer to generate

	tok, _ := crypto.IssueAccessToken(ks, claims)
	parsed, err := crypto.ParseAccessToken(ks, tok)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	jti, _ := (*parsed)["jti"].(string)
	if jti == "" {
		t.Error("auto-generated JTI must be non-empty")
	}
}

func TestParseAccessToken_InvalidString(t *testing.T) {
	ks := newKS(t)
	_, err := crypto.ParseAccessToken(ks, "not.a.valid.jwt")
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestParseAccessToken_WrongKeystore(t *testing.T) {
	ks1 := newKS(t)
	ks2 := newKS(t) // different key pair

	tok, _ := crypto.IssueAccessToken(ks1, makeATClaims("https://iss.example.com"))
	_, err := crypto.ParseAccessToken(ks2, tok)
	if err == nil {
		t.Fatal("expected error when parsing token signed by different key")
	}
}

func TestParseAccessToken_ExpiredToken(t *testing.T) {
	ks := newKS(t)
	priv, kid := ks.SigningKey()

	mapClaims := gojwt.MapClaims{
		"iss":       "https://iss.example.com",
		"sub":       "user-1",
		"aud":       []string{"https://iss.example.com"},
		"scope":     "openid",
		"jti":       "jti-old",
		"iat":       time.Now().Add(-2 * time.Hour).Unix(),
		"exp":       time.Now().Add(-time.Hour).Unix(), // already expired
		"client_id": "client-1",
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = kid
	tokenStr, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	_, err = crypto.ParseAccessToken(ks, tokenStr)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestParseAccessToken_HMACToken_Rejected(t *testing.T) {
	// A token signed with HMAC should be rejected (ParseAccessToken expects RSA).
	mapClaims := gojwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, mapClaims)
	tokenStr, err := tok.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("sign HMAC token: %v", err)
	}

	ks := newKS(t)
	_, err = crypto.ParseAccessToken(ks, tokenStr)
	if err == nil {
		t.Fatal("expected error for HMAC-signed token")
	}
}

// ---------------------------------------------------------------------------
// ID token
// ---------------------------------------------------------------------------

func TestIssueIDToken_ReturnsNonEmpty(t *testing.T) {
	ks := newKS(t)
	now := time.Now()
	claims := crypto.IDTokenClaims{
		Issuer:    "https://iss.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		Nonce:     "nonce-1",
		AuthTime:  now.Unix(),
		AtHash:    "at-hash-val",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		Extra:     map[string]interface{}{"email": "u@example.com"},
	}
	tok, err := crypto.IssueIDToken(ks, claims)
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty ID token")
	}
}

func TestIssueIDToken_ExtraClaimsIncluded(t *testing.T) {
	ks := newKS(t)
	now := time.Now()
	claims := crypto.IDTokenClaims{
		Issuer:    "https://iss.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		Extra:     map[string]interface{}{"name": "Alice", "email": "alice@example.com"},
	}
	tok, _ := crypto.IssueIDToken(ks, claims)

	priv, _ := ks.SigningKey()
	parsed, err := gojwt.Parse(tok, func(t *gojwt.Token) (interface{}, error) {
		return &priv.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse ID token: %v", err)
	}
	mc := parsed.Claims.(gojwt.MapClaims)
	if mc["name"] != "Alice" {
		t.Errorf("expected name=Alice, got %v", mc["name"])
	}
	if mc["email"] != "alice@example.com" {
		t.Errorf("expected email=alice@example.com, got %v", mc["email"])
	}
}

func TestIssueIDToken_EmptyNonceOmitted(t *testing.T) {
	ks := newKS(t)
	now := time.Now()
	claims := crypto.IDTokenClaims{
		Issuer:    "https://iss.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		Nonce:     "",
	}
	tok, _ := crypto.IssueIDToken(ks, claims)

	priv, _ := ks.SigningKey()
	parsed, _ := gojwt.Parse(tok, func(t *gojwt.Token) (interface{}, error) {
		return &priv.PublicKey, nil
	})
	mc := parsed.Claims.(gojwt.MapClaims)
	if _, ok := mc["nonce"]; ok {
		t.Error("nonce must be absent when empty")
	}
}

func TestIssueIDToken_NonceIncludedWhenSet(t *testing.T) {
	ks := newKS(t)
	now := time.Now()
	claims := crypto.IDTokenClaims{
		Issuer:    "https://iss.example.com",
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		Nonce:     "my-nonce",
	}
	tok, _ := crypto.IssueIDToken(ks, claims)

	priv, _ := ks.SigningKey()
	parsed, _ := gojwt.Parse(tok, func(t *gojwt.Token) (interface{}, error) {
		return &priv.PublicKey, nil
	})
	mc := parsed.Claims.(gojwt.MapClaims)
	if mc["nonce"] != "my-nonce" {
		t.Errorf("expected nonce=my-nonce, got %v", mc["nonce"])
	}
}

// ---------------------------------------------------------------------------
// ComputeAtHash
// ---------------------------------------------------------------------------

func TestComputeAtHash_Deterministic(t *testing.T) {
	h1 := crypto.ComputeAtHash("some-access-token")
	h2 := crypto.ComputeAtHash("some-access-token")
	if h1 == "" {
		t.Fatal("at_hash must not be empty")
	}
	if h1 != h2 {
		t.Error("at_hash must be deterministic for the same input")
	}
}

func TestComputeAtHash_DifferentInputsDifferentOutput(t *testing.T) {
	if crypto.ComputeAtHash("token-a") == crypto.ComputeAtHash("token-b") {
		t.Error("different tokens must produce different at_hash values")
	}
}

func TestComputeAtHash_IsHalfSha256Base64URL(t *testing.T) {
	token := "hello"
	h := sha256.Sum256([]byte(token))
	expected := base64.RawURLEncoding.EncodeToString(h[:len(h)/2])
	got := crypto.ComputeAtHash(token)
	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

func TestVerifyPKCE_S256_Valid(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeS256(verifier)
	if !crypto.VerifyPKCE("S256", verifier, challenge) {
		t.Error("S256 verification must succeed for matching pair")
	}
}

func TestVerifyPKCE_S256_WrongVerifier(t *testing.T) {
	challenge := computeS256("correct-verifier")
	if crypto.VerifyPKCE("S256", "wrong-verifier", challenge) {
		t.Error("S256 must fail for wrong verifier")
	}
}

func TestVerifyPKCE_Plain_Valid(t *testing.T) {
	if !crypto.VerifyPKCE("plain", "my-secret-code", "my-secret-code") {
		t.Error("plain must succeed when verifier == challenge")
	}
}

func TestVerifyPKCE_Plain_Invalid(t *testing.T) {
	if crypto.VerifyPKCE("plain", "verifier-a", "verifier-b") {
		t.Error("plain must fail when verifier != challenge")
	}
}

func TestVerifyPKCE_UnknownMethod(t *testing.T) {
	if crypto.VerifyPKCE("sha512", "v", "v") {
		t.Error("unknown method must return false")
	}
}

func TestVerifyPKCE_CaseSensitive(t *testing.T) {
	// S256 and s256 are different strings; only "S256" is recognized.
	verifier := "test-verifier"
	challenge := computeS256(verifier)
	if crypto.VerifyPKCE("s256", verifier, challenge) {
		t.Error("PKCE method matching must be case-sensitive")
	}
}
