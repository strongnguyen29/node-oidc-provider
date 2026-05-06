package provider

import (
"crypto/rand"
"fmt"
"net/http"
"strings"

"github.com/go-chi/chi/v5"
"github.com/go-chi/chi/v5/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
"github.com/strongnguyen29/go-oidc-provider/internal/handlers"
mw "github.com/strongnguyen29/go-oidc-provider/internal/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

// Provider is the main OIDC/OAuth2 provider.
type Provider struct {
config   *config.Config
keystore *crypto.Keystore
store    store.Adapter
router   chi.Router
}

// New creates a new Provider. If adapter is nil, an in-memory store is used.
func New(cfg *config.Config, adapter store.Adapter) (*Provider, error) {
cfg.Defaults()

if adapter == nil {
adapter = store.NewMemoryStore()
}

if len(cfg.CookieSecret) == 0 {
secret := make([]byte, 32)
if _, err := rand.Read(secret); err != nil {
return nil, fmt.Errorf("failed to generate cookie secret: %w", err)
}
cfg.CookieSecret = secret
}

ks, err := crypto.NewKeystore()
if err != nil {
return nil, fmt.Errorf("failed to create keystore: %w", err)
}

p := &Provider{
config:   cfg,
keystore: ks,
store:    adapter,
}

p.router = p.buildRouter()
return p, nil
}

func (p *Provider) buildRouter() chi.Router {
r := chi.NewRouter()
r.Use(middleware.Recoverer)

secure := strings.HasPrefix(p.config.Issuer, "https://")
	sm := mw.NewSessionMiddleware(p.config.CookieSecret, secure)
clientAuth := mw.ClientAuthMiddleware(p.config)

r.Get("/.well-known/openid-configuration", handlers.NewDiscoveryHandler(p.config))
r.Get("/jwks", handlers.NewJWKSHandler(p.keystore))
r.Get("/authorize", handlers.NewAuthorizationHandler(p.config, p.keystore, p.store, sm))

r.With(clientAuth).Post("/token", handlers.NewTokenHandler(p.config, p.keystore, p.store))
r.Get("/userinfo", handlers.NewUserInfoHandler(p.config, p.keystore))
r.Post("/userinfo", handlers.NewUserInfoHandler(p.config, p.keystore))
r.With(clientAuth).Post("/introspect", handlers.NewIntrospectionHandler(p.config, p.keystore, p.store))
r.With(clientAuth).Post("/revoke", handlers.NewRevocationHandler(p.config, p.keystore, p.store))
r.Get("/logout", handlers.NewEndSessionHandler(p.config, p.store, sm, p.keystore))

r.Get("/interaction/{uid}", handlers.NewInteractionGetHandler(p.config, p.store))
r.Post("/interaction/{uid}/login", handlers.NewInteractionLoginHandler(p.config, p.keystore, p.store, sm))
r.Post("/interaction/{uid}/confirm", handlers.NewInteractionConfirmHandler(p.config, p.keystore, p.store, sm))
r.Post("/interaction/{uid}/abort", handlers.NewInteractionAbortHandler(p.config, p.store))

r.With(clientAuth).Post("/device/authorization", handlers.NewDeviceAuthorizationHandler(p.config, p.store))
r.Get("/device", handlers.NewDeviceGetHandler(p.config, p.store))
r.Post("/device", handlers.NewDevicePostHandler(p.config, p.store, sm))

return r
}

// Handler returns the HTTP handler for the provider.
func (p *Provider) Handler() http.Handler {
return p.router
}
