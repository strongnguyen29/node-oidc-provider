package main

import (
"context"
"log"
"net/http"

"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/pkg/provider"
)

func main() {
cfg := &config.Config{
Issuer: "http://localhost:9000",
Clients: []config.ClientConfig{
{
ID:            "test-client",
Secret:        "test-secret",
RedirectURIs:  []string{"http://localhost:3000/callback"},
PostLogoutRedirectURIs: []string{"http://localhost:3000"},
GrantTypes:    []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
ResponseTypes: []string{"code"},
Scopes:        []string{"openid", "profile", "email", "offline_access"},
TokenEndpointAuthMethod: "client_secret_basic",
},
{
ID:            "device-client",
Secret:        "device-secret",
RedirectURIs:  []string{},
GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:device_code"},
ResponseTypes: []string{},
Scopes:        []string{"openid", "profile"},
TokenEndpointAuthMethod: "client_secret_basic",
},
},
FindAccount: func(ctx context.Context, sub string) (*config.Account, error) {
return &config.Account{
Sub: sub,
Claims: map[string]interface{}{
"name":  "Test User",
"email": sub + "@example.com",
},
}, nil
},
AuthenticateAccount: func(ctx context.Context, login, password string) (*config.Account, error) {
if password != "password" {
return nil, nil
}
return &config.Account{
Sub: login,
Claims: map[string]interface{}{
"name":  login,
"email": login + "@example.com",
},
}, nil
},
}

p, err := provider.New(cfg, nil)
if err != nil {
log.Fatalf("failed to create provider: %v", err)
}

log.Printf("OIDC Provider listening on :9000")
log.Printf("Discovery: http://localhost:9000/.well-known/openid-configuration")
if err := http.ListenAndServe(":9000", p.Handler()); err != nil {
log.Fatalf("server error: %v", err)
}
}
