// Package main là sample server minh hoạ cách sử dụng go-oidc-provider
// (Go port của thư viện node-oidc-provider) với Redis (standalone, single
// node) làm storage adapter thay cho in-memory store mặc định.
//
// Module này nằm ngoài cây source go-oidc-provider/ và liên kết tới library
// qua `replace` directive trong go.mod.
//
// Chạy:
//
//	# 1) Khởi động Redis (xem docker-compose.yml kế bên):
//	docker compose up -d
//
//	# 2) Khởi động OIDC server (cwd = example-go/):
//	go run .
//
//	# 3) Kiểm tra discovery:
//	curl http://localhost:9000/.well-known/openid-configuration
//
// Mọi tham số (Redis address, client credentials, TTL...) đều được hardcode
// bên dưới và có comment hướng dẫn nơi cần đổi khi đem sang môi trường thật.
package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/strongnguyen29/go-oidc-provider/pkg/config"
	"github.com/strongnguyen29/go-oidc-provider/pkg/provider"
	"github.com/strongnguyen29/go-oidc-provider/pkg/store"
)

func main() {
	// -----------------------------------------------------------------------
	// Redis adapter — standalone (1 node).
	//
	// Khi triển khai thật, đổi:
	//   - Addrs: thay localhost bằng host Redis của bạn.
	//   - Password: đặt mật khẩu nếu Redis bật AUTH.
	//   - DB: chọn DB index khác 0 nếu cần tách dữ liệu.
	// Để dùng Redis Cluster, truyền nhiều địa chỉ vào Addrs — UniversalClient
	// tự động phát hiện cluster topology.
	// -----------------------------------------------------------------------
	adapter, err := store.NewRedisClusterAdapter(store.RedisClusterOptions{
		Addrs:        []string{"localhost:6379"},
		Password:     "",
		DB:           0,
		PoolSize:     10,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	})
	if err != nil {
		log.Fatalf("redis adapter: %v", err)
	}
	defer adapter.Close()

	// -----------------------------------------------------------------------
	// OIDC Provider configuration.
	//
	// Issuer phải là URL công khai của provider. Khi đặt sau reverse proxy
	// HTTPS, dùng "https://..." để cookie session tự bật cờ Secure.
	// -----------------------------------------------------------------------
	cfg := &config.Config{
		LogLevel: "debug",
		Issuer: "http://localhost:9000",
		Clients: []config.ClientConfig{
			{
				// Web client (confidential, dùng authorization_code + PKCE).
				// IsFirstParty=true: skip consent UI cho ứng dụng nội bộ.
				// Đặt false (mặc định) cho third-party để vẫn hiện consent.
				ID:                      "test-client",
				Secret:                  "test-secret",
				RedirectURIs:            []string{"http://localhost:3000/callback"},
				PostLogoutRedirectURIs:  []string{"http://localhost:3000"},
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ResponseTypes:           []string{"code"},
				Scopes:                  []string{"openid", "profile", "email", "offline_access"},
				TokenEndpointAuthMethod: "client_secret_basic",
				IsFirstParty:            true,
			},
			{
				// Device client (RFC 8628 — TV / CLI / IoT).
				ID:                      "device-client",
				Secret:                  "device-secret",
				RedirectURIs:            []string{},
				GrantTypes:              []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
				ResponseTypes:           []string{},
				Scopes:                  []string{"openid", "profile"},
				TokenEndpointAuthMethod: "client_secret_basic",
			},
		},

		// Tra cứu account theo subject (thường là user ID trong DB của bạn).
		FindAccount: func(ctx context.Context, sub string) (*config.Account, error) {
			return &config.Account{
				Sub: sub,
				Claims: map[string]interface{}{
					"name":  "Test User",
					"email": sub + "@example.com",
				},
			}, nil
		},

		// Xác thực username/password (login form & ROPC). Trả nil,nil khi sai.
		// Trong production: thay bằng bcrypt/argon2 lookup vào DB người dùng.
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

	p, err := provider.New(cfg, adapter)
	if err != nil {
		log.Fatalf("provider: %v", err)
	}

	addr := ":9000"
	log.Printf("OIDC Provider (Redis store) listening on %s", addr)
	log.Printf("Discovery: http://localhost%s/.well-known/openid-configuration", addr)
	if err := http.ListenAndServe(addr, p.Handler()); err != nil {
		log.Fatalf("server: %v", err)
	}
}
