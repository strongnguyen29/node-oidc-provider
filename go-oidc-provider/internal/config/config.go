package config

import (
"context"
"time"
)

// Config holds all provider configuration.
type Config struct {
Issuer              string
AccessTokenTTL      time.Duration
AuthCodeTTL         time.Duration
RefreshTokenTTL     time.Duration
DeviceCodeTTL       time.Duration
DeviceInterval      int
Scopes              []string
GrantTypes          []string
PKCERequired        bool
CookieSecret        []byte
// SigningKeysPEM holds RSA private signing keys as PEM-encoded byte blobs.
// The first entry is the active signer; remaining entries are kept available
// for verifying tokens issued under a previous key during rotation.
SigningKeysPEM [][]byte
// SigningKeyFiles is a list of paths to PEM-encoded RSA private keys, applied
// after SigningKeysPEM. The combined ordering determines the primary signer.
SigningKeyFiles     []string
Clients             []ClientConfig
FindAccount         func(ctx context.Context, sub string) (*Account, error)
AuthenticateAccount func(ctx context.Context, login, password string) (*Account, error)

// LogLevel controls verbosity of structured log output emitted by the
// provider's request middleware and handlers. One of "debug", "info",
// "warn", "error" (case-insensitive). Empty defaults to "info" via
// Defaults(). Setting "debug" additionally enables per-request store-op
// tracing — useful for troubleshooting session/interaction lookups but
// noisy in production.
LogLevel string
}

// ClientConfig represents a registered OAuth2 client.
type ClientConfig struct {
ID                      string
Secret                  string
RedirectURIs            []string
PostLogoutRedirectURIs  []string
GrantTypes              []string
ResponseTypes           []string
Scopes                  []string
TokenEndpointAuthMethod string
// IsFirstParty marks the client as belonging to the same trust boundary as
// the authorization server (e.g. the operator's own apps). When true the
// consent screen is ALWAYS skipped — including when the request carries
// `prompt=consent` — and the requested scopes are auto-granted on every
// authorization. Use only for clients the operator fully trusts, since
// this opts the user out of any consent UI for that client.
IsFirstParty bool
}

// Account represents an end-user account.
type Account struct {
Sub    string
Claims map[string]interface{}
}

// FindClient returns the client configuration for the given client ID.
func (c *Config) FindClient(id string) *ClientConfig {
for i := range c.Clients {
if c.Clients[i].ID == id {
return &c.Clients[i]
}
}
return nil
}

// Defaults sets sensible default values on the config.
func (c *Config) Defaults() {
if c.AccessTokenTTL == 0 {
c.AccessTokenTTL = time.Hour
}
if c.AuthCodeTTL == 0 {
c.AuthCodeTTL = 10 * time.Minute
}
if c.RefreshTokenTTL == 0 {
c.RefreshTokenTTL = 14 * 24 * time.Hour
}
if c.DeviceCodeTTL == 0 {
c.DeviceCodeTTL = 5 * time.Minute
}
if c.DeviceInterval == 0 {
c.DeviceInterval = 5
}
if c.LogLevel == "" {
c.LogLevel = "info"
}
if len(c.Scopes) == 0 {
c.Scopes = []string{"openid", "profile", "email", "offline_access"}
}
if len(c.GrantTypes) == 0 {
c.GrantTypes = []string{
"authorization_code",
"refresh_token",
"urn:ietf:params:oauth:grant-type:device_code",
"password",
"implicit",
}
}
}
