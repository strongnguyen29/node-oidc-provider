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
Clients             []ClientConfig
FindAccount         func(ctx context.Context, sub string) (*Account, error)
AuthenticateAccount func(ctx context.Context, login, password string) (*Account, error)
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
