package crypto

import (
"crypto/rand"
"crypto/rsa"

"github.com/go-jose/go-jose/v4"
"github.com/google/uuid"
)

// Keystore holds the signing key material.
type Keystore struct {
privateKey *rsa.PrivateKey
kid        string
}

// NewKeystore generates a new RSA-2048 key pair.
func NewKeystore() (*Keystore, error) {
priv, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
return nil, err
}
return &Keystore{
privateKey: priv,
kid:        uuid.New().String(),
}, nil
}

// SigningKey returns the private key and its key ID.
func (k *Keystore) SigningKey() (*rsa.PrivateKey, string) {
return k.privateKey, k.kid
}

// PublicJWKS returns the public JSON Web Key Set.
func (k *Keystore) PublicJWKS() jose.JSONWebKeySet {
return jose.JSONWebKeySet{
Keys: []jose.JSONWebKey{
{
Key:       &k.privateKey.PublicKey,
KeyID:     k.kid,
Algorithm: string(jose.RS256),
Use:       "sig",
},
},
}
}

// PublicKey returns the RSA public key for token verification.
func (k *Keystore) PublicKey() *rsa.PublicKey {
return &k.privateKey.PublicKey
}
