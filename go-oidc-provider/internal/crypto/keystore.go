package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"

	"github.com/go-jose/go-jose/v4"
)

// signingKey wraps an RSA private key with its derived JWK thumbprint kid.
type signingKey struct {
	priv *rsa.PrivateKey
	kid  string
}

// Keystore holds one or more RSA signing keys. keys[0] is always the active
// signing key; older keys remain available for token verification so that
// rotation does not invalidate previously issued tokens.
type Keystore struct {
	keys []signingKey
}

// NewKeystore generates a new ephemeral RSA-2048 keystore. Tokens signed with
// an ephemeral keystore become invalid when the process restarts; production
// deployments must use NewKeystoreFromKeys with persisted PEM material.
func NewKeystore() (*Keystore, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	kid, err := computeKID(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("derive kid: %w", err)
	}
	slog.Warn("ephemeral_signing_key",
		slog.String("kid", kid),
		slog.String("hint", "issued tokens will be invalidated on restart; configure SigningKeysPEM/SigningKeyFiles for persistence"),
	)
	return &Keystore{keys: []signingKey{{priv: priv, kid: kid}}}, nil
}

// NewKeystoreFromKeys constructs a keystore from one or more pre-generated RSA
// private keys. The first key is treated as the primary signing key. All keys
// are exposed via PublicJWKS so verifiers can validate tokens issued by older
// signing keys during a rotation window.
func NewKeystoreFromKeys(keys []*rsa.PrivateKey) (*Keystore, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one signing key is required")
	}
	out := make([]signingKey, 0, len(keys))
	seen := map[string]struct{}{}
	for i, priv := range keys {
		if priv == nil {
			return nil, fmt.Errorf("signing key #%d is nil", i)
		}
		kid, err := computeKID(&priv.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("derive kid for key #%d: %w", i, err)
		}
		if _, dup := seen[kid]; dup {
			return nil, fmt.Errorf("duplicate signing key (kid=%s)", kid)
		}
		seen[kid] = struct{}{}
		out = append(out, signingKey{priv: priv, kid: kid})
	}
	return &Keystore{keys: out}, nil
}

// LoadRSAPrivateKeysFromPEM parses a list of PEM-encoded blocks (each block may
// contain a PKCS#1 or PKCS#8 RSA private key) and returns the decoded keys in
// input order. Blocks that are not RSA private keys are rejected.
func LoadRSAPrivateKeysFromPEM(blobs [][]byte) ([]*rsa.PrivateKey, error) {
	out := make([]*rsa.PrivateKey, 0, len(blobs))
	for i, blob := range blobs {
		key, err := parseRSAPrivateKeyPEM(blob)
		if err != nil {
			return nil, fmt.Errorf("parse PEM #%d: %w", i, err)
		}
		out = append(out, key)
	}
	return out, nil
}

// LoadRSAPrivateKeysFromFiles reads each file as PEM data and decodes the keys.
func LoadRSAPrivateKeysFromFiles(paths []string) ([]*rsa.PrivateKey, error) {
	out := make([]*rsa.PrivateKey, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		key, err := parseRSAPrivateKeyPEM(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		out = append(out, key)
	}
	return out, nil
}

// SigningKey returns the primary private key and its key ID. The first
// configured key is always the active signer.
func (k *Keystore) SigningKey() (*rsa.PrivateKey, string) {
	primary := k.keys[0]
	return primary.priv, primary.kid
}

// KeyByID returns the public key whose JWK thumbprint matches kid, or nil if
// no such key is present.
func (k *Keystore) KeyByID(kid string) *rsa.PublicKey {
	for i := range k.keys {
		if k.keys[i].kid == kid {
			return &k.keys[i].priv.PublicKey
		}
	}
	return nil
}

// PublicKey returns the primary RSA public key. Provided for legacy callers
// that do not consult the kid header; verification of multi-key tokens should
// use KeyByID instead.
func (k *Keystore) PublicKey() *rsa.PublicKey {
	return &k.keys[0].priv.PublicKey
}

// PublicKeys returns all RSA public keys in registration order. Useful when a
// JWT lacks a kid header and the verifier needs to try every candidate.
func (k *Keystore) PublicKeys() []*rsa.PublicKey {
	out := make([]*rsa.PublicKey, len(k.keys))
	for i := range k.keys {
		out[i] = &k.keys[i].priv.PublicKey
	}
	return out
}

// PublicJWKS returns the JWKS exposing every signing key so JWT verifiers can
// validate tokens issued under previous signers during rotation.
func (k *Keystore) PublicJWKS() jose.JSONWebKeySet {
	jwks := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(k.keys))}
	for i := range k.keys {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:       &k.keys[i].priv.PublicKey,
			KeyID:     k.keys[i].kid,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		})
	}
	return jwks
}

// computeKID derives a deterministic key ID from an RSA public key using the
// RFC 7638 JWK thumbprint (base64url(SHA-256(canonical JSON))).
func computeKID(pub *rsa.PublicKey) (string, error) {
	thumb := struct {
		E   string `json:"e"`
		Kty string `json:"kty"`
		N   string `json:"n"`
	}{
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
	}
	canonical, err := json.Marshal(thumb)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// parseRSAPrivateKeyPEM decodes the first PEM block from data and returns the
// underlying RSA private key. PKCS#1 and PKCS#8 encodings are both accepted.
func parseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}
