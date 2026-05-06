package crypto_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
)

func genRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

func encodePKCS1(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	})
}

func encodePKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// TestPersistedKeyStableKid asserts the same RSA key always produces the same
// kid (RFC 7638 thumbprint) so tokens issued before a restart still match the
// JWKS exposed afterwards.
func TestPersistedKeyStableKid(t *testing.T) {
	priv := genRSA(t)
	ks1, err := crypto.NewKeystoreFromKeys([]*rsa.PrivateKey{priv})
	if err != nil {
		t.Fatalf("NewKeystoreFromKeys: %v", err)
	}
	ks2, err := crypto.NewKeystoreFromKeys([]*rsa.PrivateKey{priv})
	if err != nil {
		t.Fatalf("NewKeystoreFromKeys: %v", err)
	}
	_, kid1 := ks1.SigningKey()
	_, kid2 := ks2.SigningKey()
	if kid1 != kid2 {
		t.Errorf("expected stable kid for same key, got %q vs %q", kid1, kid2)
	}
	if kid1 == "" {
		t.Error("kid must be non-empty")
	}
}

// TestVerifyOldTokenAfterRotation issues a token under the original key, then
// rotates the keystore (new primary, old key kept) and verifies the original
// token still parses successfully.
func TestVerifyOldTokenAfterRotation(t *testing.T) {
	oldKey := genRSA(t)
	ks, err := crypto.NewKeystoreFromKeys([]*rsa.PrivateKey{oldKey})
	if err != nil {
		t.Fatalf("NewKeystoreFromKeys: %v", err)
	}
	tok, err := crypto.IssueAccessToken(ks, crypto.AccessTokenClaims{
		Issuer:    "https://iss.example.com",
		Subject:   "u1",
		Audience:  []string{"client-1"},
		Scope:     "openid",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		ClientID:  "client-1",
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	newKey := genRSA(t)
	rotated, err := crypto.NewKeystoreFromKeys([]*rsa.PrivateKey{newKey, oldKey})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := crypto.ParseAccessToken(rotated, tok); err != nil {
		t.Fatalf("expected old token to verify after rotation, got %v", err)
	}
}

// TestJWKSContainsAllKeys asserts every registered key is published in the
// JWKS so external verifiers can validate tokens issued under any of them.
func TestJWKSContainsAllKeys(t *testing.T) {
	k1, k2 := genRSA(t), genRSA(t)
	ks, err := crypto.NewKeystoreFromKeys([]*rsa.PrivateKey{k1, k2})
	if err != nil {
		t.Fatalf("NewKeystoreFromKeys: %v", err)
	}
	jwks := ks.PublicJWKS()
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 JWK entries, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].KeyID == jwks.Keys[1].KeyID {
		t.Error("each JWK must have a distinct kid")
	}
	for i, jwk := range jwks.Keys {
		if jwk.Algorithm != "RS256" {
			t.Errorf("key %d: expected alg=RS256, got %s", i, jwk.Algorithm)
		}
		if jwk.Use != "sig" {
			t.Errorf("key %d: expected use=sig, got %s", i, jwk.Use)
		}
	}
}

func TestNewKeystoreFromKeys_RejectsEmpty(t *testing.T) {
	if _, err := crypto.NewKeystoreFromKeys(nil); err == nil {
		t.Error("expected error for empty key list")
	}
}

func TestNewKeystoreFromKeys_RejectsDuplicate(t *testing.T) {
	k := genRSA(t)
	if _, err := crypto.NewKeystoreFromKeys([]*rsa.PrivateKey{k, k}); err == nil {
		t.Error("expected error for duplicate keys")
	}
}

func TestKeyByID_LookupAndMiss(t *testing.T) {
	k1, k2 := genRSA(t), genRSA(t)
	ks, _ := crypto.NewKeystoreFromKeys([]*rsa.PrivateKey{k1, k2})
	_, kid1 := ks.SigningKey()
	if pub := ks.KeyByID(kid1); pub == nil || pub.N.Cmp(k1.N) != 0 {
		t.Error("KeyByID(primary kid) must return primary public key")
	}
	if pub := ks.KeyByID("does-not-exist"); pub != nil {
		t.Error("KeyByID(unknown) must return nil")
	}
}

func TestLoadRSAPrivateKeysFromPEM_PKCS1AndPKCS8(t *testing.T) {
	k1 := genRSA(t)
	k2 := genRSA(t)
	keys, err := crypto.LoadRSAPrivateKeysFromPEM([][]byte{
		encodePKCS1(t, k1),
		encodePKCS8(t, k2),
	})
	if err != nil {
		t.Fatalf("LoadRSAPrivateKeysFromPEM: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[0].N.Cmp(k1.N) != 0 {
		t.Error("first parsed key must equal PKCS#1 input")
	}
	if keys[1].N.Cmp(k2.N) != 0 {
		t.Error("second parsed key must equal PKCS#8 input")
	}
}

func TestLoadRSAPrivateKeysFromPEM_RejectsBadPEM(t *testing.T) {
	if _, err := crypto.LoadRSAPrivateKeysFromPEM([][]byte{[]byte("not pem")}); err == nil {
		t.Error("expected error for malformed PEM")
	}
}

func TestLoadRSAPrivateKeysFromFiles(t *testing.T) {
	dir := t.TempDir()
	k := genRSA(t)
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, encodePKCS1(t, k), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	keys, err := crypto.LoadRSAPrivateKeysFromFiles([]string{path})
	if err != nil {
		t.Fatalf("LoadRSAPrivateKeysFromFiles: %v", err)
	}
	if len(keys) != 1 || keys[0].N.Cmp(k.N) != 0 {
		t.Error("loaded key must match written key")
	}
}

func TestLoadRSAPrivateKeysFromFiles_MissingFile(t *testing.T) {
	if _, err := crypto.LoadRSAPrivateKeysFromFiles([]string{"/no/such/file.pem"}); err == nil {
		t.Error("expected error for missing file")
	}
}
