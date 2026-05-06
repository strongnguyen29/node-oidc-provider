package provider

import (
"crypto/rand"
"fmt"
"log/slog"
"net/http"
"strings"

"github.com/go-chi/chi/v5"
"github.com/go-chi/chi/v5/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/config"
"github.com/strongnguyen29/go-oidc-provider/internal/crypto"
"github.com/strongnguyen29/go-oidc-provider/internal/handlers"
"github.com/strongnguyen29/go-oidc-provider/internal/logging"
mw "github.com/strongnguyen29/go-oidc-provider/internal/middleware"
"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

// Provider is the main OIDC/OAuth2 provider.
type Provider struct {
config   *config.Config
keystore *crypto.Keystore
store    store.Adapter
logger   *slog.Logger
router   chi.Router
}

// New creates a new Provider. If adapter is nil, an in-memory store is used.
func New(cfg *config.Config, adapter store.Adapter) (*Provider, error) {
cfg.Defaults()

if adapter == nil {
adapter = store.NewMemoryStore()
}

logger := logging.New(cfg.LogLevel)
// At debug level we wrap the adapter so each Find/Upsert/Consume/Destroy
// shows up in the log stream alongside the request that triggered it. The
// wrapper preserves the optional AppendString fast path used by grant
// family bookkeeping.
if logging.LevelFromString(cfg.LogLevel) <= slog.LevelDebug {
adapter = store.NewLoggingAdapter(adapter, logger)
}

if len(cfg.CookieSecret) == 0 {
secret := make([]byte, 32)
if _, err := rand.Read(secret); err != nil {
return nil, fmt.Errorf("failed to generate cookie secret: %w", err)
}
cfg.CookieSecret = secret
}

ks, err := buildKeystore(cfg)
if err != nil {
return nil, fmt.Errorf("failed to create keystore: %w", err)
}

p := &Provider{
config:   cfg,
keystore: ks,
store:    adapter,
logger:   logger,
}

logger.Info("provider_started",
slog.String("issuer", cfg.Issuer),
slog.String("log_level", cfg.LogLevel),
slog.Int("clients", len(cfg.Clients)),
slog.Int("signing_keys", len(cfg.SigningKeysPEM)+len(cfg.SigningKeyFiles)),
)

p.router = p.buildRouter()
return p, nil
}

func (p *Provider) buildRouter() chi.Router {
r := chi.NewRouter()
// RequestLogger runs first so every downstream handler — including
// chi.Recoverer's panic response — is observable through the access log
// and has a request-scoped logger available on the context.
r.Use(mw.RequestLogger(p.logger))
r.Use(middleware.Recoverer)

secure := strings.HasPrefix(p.config.Issuer, "https://")
	sm := mw.NewSessionMiddleware(p.config.CookieSecret, secure)
clientAuth := mw.ClientAuthMiddleware(p.config)

r.Get("/.well-known/openid-configuration", handlers.NewDiscoveryHandler(p.config))
r.Get("/jwks", handlers.NewJWKSHandler(p.keystore))
r.Get("/authorize", handlers.NewAuthorizationHandler(p.config, p.keystore, p.store, sm))

r.With(clientAuth).Post("/token", handlers.NewTokenHandler(p.config, p.keystore, p.store))
r.Get("/userinfo", handlers.NewUserInfoHandler(p.config, p.keystore, p.store))
r.Post("/userinfo", handlers.NewUserInfoHandler(p.config, p.keystore, p.store))
r.With(clientAuth).Post("/introspect", handlers.NewIntrospectionHandler(p.config, p.keystore, p.store))
r.With(clientAuth).Post("/revoke", handlers.NewRevocationHandler(p.config, p.keystore, p.store))
r.Get("/logout", handlers.NewEndSessionHandler(p.config, p.store, sm, p.keystore))

r.Get("/interaction/{uid}", handlers.NewInteractionGetHandler(p.config, p.store, sm))
r.Post("/interaction/{uid}/login", handlers.NewInteractionLoginHandler(p.config, p.keystore, p.store, sm))
r.Post("/interaction/{uid}/confirm", handlers.NewInteractionConfirmHandler(p.config, p.keystore, p.store, sm))
r.Post("/interaction/{uid}/abort", handlers.NewInteractionAbortHandler(p.config, p.store, sm))

r.With(clientAuth).Post("/device/authorization", handlers.NewDeviceAuthorizationHandler(p.config, p.store))
r.Get("/device", handlers.NewDeviceGetHandler(p.config, p.store, sm))
r.Post("/device", handlers.NewDevicePostHandler(p.config, p.store, sm))

return r
}

// Handler returns the HTTP handler for the provider.
func (p *Provider) Handler() http.Handler {
return p.router
}

// buildKeystore constructs the signing keystore. PEM blobs (cfg.SigningKeysPEM)
// take precedence and are then extended with any keys loaded from disk
// (cfg.SigningKeyFiles). When both are empty an ephemeral key is generated and
// the keystore logs a warning at startup so operators do not silently ship a
// non-persistent provider into production.
func buildKeystore(cfg *config.Config) (*crypto.Keystore, error) {
	keys, err := crypto.LoadRSAPrivateKeysFromPEM(cfg.SigningKeysPEM)
	if err != nil {
		return nil, fmt.Errorf("load SigningKeysPEM: %w", err)
	}
	fileKeys, err := crypto.LoadRSAPrivateKeysFromFiles(cfg.SigningKeyFiles)
	if err != nil {
		return nil, fmt.Errorf("load SigningKeyFiles: %w", err)
	}
	keys = append(keys, fileKeys...)
	if len(keys) == 0 {
		return crypto.NewKeystore()
	}
	return crypto.NewKeystoreFromKeys(keys)
}
