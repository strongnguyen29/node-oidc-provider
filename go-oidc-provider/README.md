# go-oidc-provider

Thư viện Go triển khai **OAuth 2.0 Authorization Server** và **OpenID Connect Core 1.0 Provider** hoàn chỉnh.

---

## Tính năng

| Tính năng | Hỗ trợ |
|---|---|
| Authorization Code + PKCE | ✅ |
| Implicit Flow | ✅ |
| Device Authorization Grant (RFC 8628) | ✅ |
| Resource Owner Password Credentials | ✅ |
| Refresh Token (xoay vòng) | ✅ |
| OIDC Discovery (RFC 8414) | ✅ |
| JWKS endpoint | ✅ |
| UserInfo endpoint | ✅ |
| Token Introspection (RFC 7662) | ✅ |
| Token Revocation (RFC 7009) | ✅ |
| RP-Initiated Logout 1.0 | ✅ |
| JWT Access Token (RS256) | ✅ |
| ID Token với `nonce`, `at_hash`, `auth_time` | ✅ |
| In-memory store tích hợp sẵn | ✅ |
| Custom storage adapter | ✅ |
| HTML interaction UI (login / consent) | ✅ |

---

## Cài đặt nhanh

```bash
go get github.com/strongnguyen29/go-oidc-provider
```

### Khởi động server tối giản

```go
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
                ID:            "my-app",
                Secret:        "my-secret",
                RedirectURIs:  []string{"http://localhost:3000/callback"},
                GrantTypes:    []string{"authorization_code", "refresh_token"},
                ResponseTypes: []string{"code"},
                Scopes:        []string{"openid", "profile", "email", "offline_access"},
                TokenEndpointAuthMethod: "client_secret_basic",
            },
        },
        FindAccount: func(ctx context.Context, sub string) (*config.Account, error) {
            return &config.Account{
                Sub:    sub,
                Claims: map[string]interface{}{"name": sub, "email": sub + "@example.com"},
            }, nil
        },
        AuthenticateAccount: func(ctx context.Context, login, password string) (*config.Account, error) {
            if password != "secret" {
                return nil, nil // trả về nil để báo xác thực thất bại
            }
            return &config.Account{Sub: login}, nil
        },
    }

    p, err := provider.New(cfg, nil) // nil → dùng in-memory store
    if err != nil {
        log.Fatal(err)
    }

    log.Println("OIDC Provider: http://localhost:9000")
    http.ListenAndServe(":9000", p.Handler())
}
```

Chạy server:

```bash
go run ./cmd/server
```

Kiểm tra discovery document:

```bash
curl http://localhost:9000/.well-known/openid-configuration | jq
```

---

## Tài liệu

| Tài liệu | Mô tả |
|---|---|
| [Hướng dẫn tích hợp](docs/integration.md) | Tích hợp từng bước, ví dụ đầy đủ |
| [Tham chiếu cấu hình](docs/configuration.md) | Tất cả tuỳ chọn `Config`, `ClientConfig` |
| [Luồng OAuth2/OIDC](docs/flows.md) | Sơ đồ và ví dụ HTTP từng grant type |
| [Tham chiếu endpoint](docs/endpoints.md) | Request/response mẫu cho mỗi endpoint |

---

## Chạy ví dụ kèm theo

```bash
cd go-oidc-provider
go run ./cmd/server/main.go
```

Server khởi động trên `:9000` với client `test-client` / `test-secret` và in-memory store.

---

## Chạy test

```bash
cd go-oidc-provider
go test ./...
```

---

## Yêu cầu

- Go 1.21+
- Không cần database (in-memory store tích hợp sẵn)

---

## Giới hạn phạm vi

Thư viện không triển khai:

- Dynamic Client Registration
- PAR (Pushed Authorization Requests)
- CIBA / Backchannel Authentication
- mTLS / DPoP token binding
- JAR (JWT-Secured Authorization Requests)
- `private_key_jwt` client authentication
- Opaque access tokens (access token luôn là JWT)
