# Hướng dẫn tích hợp

Tài liệu này hướng dẫn từng bước tích hợp `go-oidc-provider` vào ứng dụng Go của bạn.

---

## Mục lục

1. [Cài đặt](#1-cài-đặt)
2. [Khởi tạo Provider](#2-khởi-tạo-provider)
3. [Tích hợp với HTTP server](#3-tích-hợp-với-http-server)
4. [Tích hợp xác thực người dùng](#4-tích-hợp-xác-thực-người-dùng)
5. [Cấu hình client](#5-cấu-hình-client)
6. [Tùy chỉnh storage adapter](#6-tùy-chỉnh-storage-adapter)
7. [Tích hợp với framework (Gin, Echo)](#7-tích-hợp-với-framework-gin-echo)
8. [Bảo vệ API với access token](#8-bảo-vệ-api-với-access-token)
9. [Ví dụ đầy đủ: Web App tích hợp OIDC](#9-ví-dụ-đầy-đủ-web-app-tích-hợp-oidc)
10. [Triển khai production](#10-triển-khai-production)
11. [Xử lý lỗi thường gặp](#11-xử-lý-lỗi-thường-gặp)

---

## 1. Cài đặt

```bash
go get github.com/strongnguyen29/go-oidc-provider
```

Thêm vào `go.mod`:

```bash
go mod tidy
```

---

## 2. Khởi tạo Provider

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
        Issuer: "https://auth.example.com",

        Clients: []config.ClientConfig{
            {
                ID:            "my-web-app",
                Secret:        "super-secret",
                RedirectURIs:  []string{"https://app.example.com/callback"},
                PostLogoutRedirectURIs: []string{"https://app.example.com/"},
                GrantTypes:    []string{"authorization_code", "refresh_token"},
                ResponseTypes: []string{"code"},
                Scopes:        []string{"openid", "profile", "email", "offline_access"},
                TokenEndpointAuthMethod: "client_secret_basic",
            },
        },

        // Hàm tra cứu thông tin user theo sub
        FindAccount: func(ctx context.Context, sub string) (*config.Account, error) {
            user := myDB.FindUserByID(ctx, sub)
            return &config.Account{
                Sub: user.ID,
                Claims: map[string]interface{}{
                    "name":  user.FullName,
                    "email": user.Email,
                },
            }, nil
        },

        // Hàm xác thực username/password (dùng cho login form và ROPC)
        AuthenticateAccount: func(ctx context.Context, login, password string) (*config.Account, error) {
            user, err := myDB.AuthenticateUser(ctx, login, password)
            if err != nil || user == nil {
                return nil, nil // nil nghĩa là xác thực thất bại
            }
            return &config.Account{Sub: user.ID}, nil
        },
    }

    // Tạo provider với in-memory store (phù hợp cho development)
    p, err := provider.New(cfg, nil)
    if err != nil {
        log.Fatal(err)
    }

    http.ListenAndServe(":9000", p.Handler())
}
```

---

## 3. Tích hợp với HTTP server

`provider.Handler()` trả về `http.Handler` tiêu chuẩn. Bạn có thể gắn vào bất kỳ HTTP server nào.

### net/http thuần

```go
mux := http.NewServeMux()

// OIDC Provider xử lý tất cả route của mình
mux.Handle("/", oidcProvider.Handler())

// Các route của ứng dụng
mux.HandleFunc("/api/data", myAPIHandler)

http.ListenAndServe(":8080", mux)
```

### Với TLS (production)

```go
srv := &http.Server{
    Addr:    ":443",
    Handler: oidcProvider.Handler(),
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
    },
}
srv.ListenAndServeTLS("cert.pem", "key.pem")
```

### Đặt sau reverse proxy (Nginx, Caddy)

Khi đặt sau reverse proxy, đảm bảo:

1. `Issuer` trong config khớp với URL công khai (`https://auth.example.com`)
2. Proxy truyền header `X-Forwarded-For` và `X-Forwarded-Proto`
3. Cookie `_session` hoạt động trên HTTPS — provider tự động bật `Secure` flag khi `Issuer` bắt đầu bằng `https://`

Nginx config mẫu:

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;

    location / {
        proxy_pass http://localhost:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 4. Tích hợp xác thực người dùng

Provider cung cấp UI login mặc định (form HTML). Bạn chỉ cần implement hai hàm callback:

### `FindAccount` — Lấy thông tin user theo subject

```go
FindAccount: func(ctx context.Context, sub string) (*config.Account, error) {
    // sub là user ID được lưu trong token
    var user User
    if err := db.WithContext(ctx).First(&user, "id = ?", sub).Error; err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            return nil, fmt.Errorf("user not found: %s", sub)
        }
        return nil, err
    }
    return &config.Account{
        Sub: user.ID,
        Claims: map[string]interface{}{
            "name":            user.DisplayName,
            "given_name":      user.FirstName,
            "family_name":     user.LastName,
            "email":           user.Email,
            "email_verified":  user.EmailVerified,
            "picture":         user.AvatarURL,
            "locale":          user.Locale,
            "updated_at":      user.UpdatedAt.Unix(),
        },
    }, nil
},
```

### `AuthenticateAccount` — Xác thực username/password

```go
AuthenticateAccount: func(ctx context.Context, login, password string) (*config.Account, error) {
    // login có thể là email hoặc username
    var user User
    if err := db.WithContext(ctx).
        Where("email = ? OR username = ?", login, login).
        First(&user).Error; err != nil {
        return nil, nil // user không tồn tại → trả nil
    }

    // Kiểm tra password hash (bcrypt, argon2, ...)
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
        return nil, nil // sai password → trả nil
    }

    return &config.Account{Sub: user.ID}, nil
},
```

**Quy tắc:**
- Trả về `nil, nil` khi xác thực thất bại (sai password, user không tồn tại)
- Trả về `nil, error` chỉ khi có lỗi hệ thống (database down, ...)
- Không bao giờ tiết lộ lý do thất bại cụ thể trong response HTTP

---

## 5. Cấu hình client

### Web App (confidential client)

```go
config.ClientConfig{
    ID:     "web-app",
    Secret: "client-secret",   // giữ bí mật ở server
    RedirectURIs: []string{
        "https://app.example.com/callback",
        "https://app.example.com/silent-callback",
    },
    PostLogoutRedirectURIs: []string{
        "https://app.example.com/",
        "https://app.example.com/logged-out",
    },
    GrantTypes:    []string{"authorization_code", "refresh_token"},
    ResponseTypes: []string{"code"},
    Scopes:        []string{"openid", "profile", "email", "offline_access"},
    TokenEndpointAuthMethod: "client_secret_basic",
}
```

### SPA / Mobile App (public client, không có secret)

```go
config.ClientConfig{
    ID:           "spa-app",
    Secret:       "",           // public client không có secret
    RedirectURIs: []string{"https://spa.example.com/callback"},
    GrantTypes:   []string{"authorization_code"},
    ResponseTypes: []string{"code"},
    Scopes:       []string{"openid", "profile"},
    TokenEndpointAuthMethod: "none",
}
```

Public client **bắt buộc** dùng PKCE:

```go
cfg.PKCERequired = true
```

### Device (TV, CLI)

```go
config.ClientConfig{
    ID:           "tv-app",
    Secret:       "tv-secret",
    RedirectURIs: []string{},   // không cần redirect URI
    GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
    ResponseTypes: []string{},
    Scopes:       []string{"openid", "profile"},
    TokenEndpointAuthMethod: "client_secret_basic",
}
```

---

## 6. Tùy chỉnh storage adapter

In-memory store mặc định không bền vững — dữ liệu mất sau khi restart.  
Với production, implement interface `store.Adapter` cho Redis, PostgreSQL, v.v.

### Interface

```go
type Adapter interface {
    // Lưu hoặc cập nhật dữ liệu với TTL
    Upsert(ctx context.Context, id string, payload interface{}, expiresIn time.Duration) error

    // Tìm theo ID, trả về lỗi nếu không tồn tại hoặc đã hết hạn
    Find(ctx context.Context, id string) (interface{}, error)

    // Đánh dấu token là đã dùng (consumed) — không xóa khỏi store
    Consume(ctx context.Context, id string) error

    // Xóa vĩnh viễn khỏi store
    Destroy(ctx context.Context, id string) error
}
```

### Ví dụ: Redis adapter

```go
package redisstore

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/redis/go-redis/v9"
)

type RedisAdapter struct {
    client *redis.Client
}

func New(addr string) *RedisAdapter {
    return &RedisAdapter{
        client: redis.NewClient(&redis.Options{Addr: addr}),
    }
}

type entry struct {
    Payload  json.RawMessage `json:"payload"`
    Type     string          `json:"type"`
    Consumed bool            `json:"consumed"`
}

func (a *RedisAdapter) Upsert(ctx context.Context, id string, payload interface{}, ttl time.Duration) error {
    data, err := json.Marshal(payload)
    if err != nil {
        return err
    }
    e := entry{Payload: data, Type: fmt.Sprintf("%T", payload)}
    raw, err := json.Marshal(e)
    if err != nil {
        return err
    }
    return a.client.Set(ctx, id, raw, ttl).Err()
}

func (a *RedisAdapter) Find(ctx context.Context, id string) (interface{}, error) {
    raw, err := a.client.Get(ctx, id).Bytes()
    if err == redis.Nil {
        return nil, fmt.Errorf("not found: %s", id)
    }
    if err != nil {
        return nil, err
    }
    var e entry
    if err := json.Unmarshal(raw, &e); err != nil {
        return nil, err
    }
    // Deserialize theo type (cần type registry)
    return deserialize(e.Type, e.Payload)
}

func (a *RedisAdapter) Consume(ctx context.Context, id string) error {
    raw, err := a.client.Get(ctx, id).Bytes()
    if err != nil {
        return err
    }
    var e entry
    json.Unmarshal(raw, &e)
    e.Consumed = true
    updated, _ := json.Marshal(e)
    ttl := a.client.TTL(ctx, id).Val()
    return a.client.Set(ctx, id, updated, ttl).Err()
}

func (a *RedisAdapter) Destroy(ctx context.Context, id string) error {
    return a.client.Del(ctx, id).Err()
}
```

Đăng ký adapter:

```go
adapter := redisstore.New("localhost:6379")
p, err := provider.New(cfg, adapter)
```

### Type registry cho deserialization

Provider lưu các struct khác nhau vào store (Session, AuthorizationCode, RefreshToken, ...).  
Khi implement custom adapter, cần giải quyết việc deserialization:

```go
import "github.com/strongnguyen29/go-oidc-provider/internal/models"

func deserialize(typeName string, data json.RawMessage) (interface{}, error) {
    switch typeName {
    case "*models.Session":
        var v models.Session
        json.Unmarshal(data, &v)
        return &v, nil
    case "*models.AuthorizationCode":
        var v models.AuthorizationCode
        json.Unmarshal(data, &v)
        return &v, nil
    case "*models.RefreshToken":
        var v models.RefreshToken
        json.Unmarshal(data, &v)
        return &v, nil
    case "*models.DeviceCode":
        var v models.DeviceCode
        json.Unmarshal(data, &v)
        return &v, nil
    case "*models.Grant":
        var v models.Grant
        json.Unmarshal(data, &v)
        return &v, nil
    case "*models.Interaction":
        var v models.Interaction
        json.Unmarshal(data, &v)
        return &v, nil
    default:
        var v interface{}
        json.Unmarshal(data, &v)
        return v, nil
    }
}
```

---

## 7. Tích hợp với framework (Gin, Echo)

### Gin

```go
import "github.com/gin-gonic/gin"

r := gin.Default()

// Mount OIDC provider trên sub-path
oidcHandler := oidcProvider.Handler()
r.Any("/auth/*path", func(c *gin.Context) {
    // Rewrite path: /auth/authorize → /authorize
    c.Request.URL.Path = c.Param("path")
    oidcHandler.ServeHTTP(c.Writer, c.Request)
})

r.Run(":8080")
```

Hoặc dùng `http.StripPrefix`:

```go
r.Any("/auth/*path", gin.WrapH(
    http.StripPrefix("/auth", oidcProvider.Handler()),
))
```

### Echo

```go
import "github.com/labstack/echo/v4"

e := echo.New()
e.Any("/auth/*", echo.WrapHandler(
    http.StripPrefix("/auth", oidcProvider.Handler()),
))
e.Start(":8080")
```

---

## 8. Bảo vệ API với access token

Resource Server cần xác minh JWT access token từ client.

### Middleware xác minh JWT

```go
package middleware

import (
    "crypto/rsa"
    "encoding/json"
    "fmt"
    "net/http"

    "github.com/golang-jwt/jwt/v5"
)

type JWTMiddleware struct {
    publicKey *rsa.PublicKey
    issuer    string
}

func NewJWTMiddleware(jwksURL, issuer string) (*JWTMiddleware, error) {
    key, err := fetchPublicKeyFromJWKS(jwksURL)
    if err != nil {
        return nil, err
    }
    return &JWTMiddleware{publicKey: key, issuer: issuer}, nil
}

func (m *JWTMiddleware) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tokenString := extractBearerToken(r)
        if tokenString == "" {
            http.Error(w, `{"error":"missing_token"}`, http.StatusUnauthorized)
            return
        }

        token, err := jwt.Parse(tokenString,
            func(t *jwt.Token) (interface{}, error) {
                if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
                    return nil, fmt.Errorf("unexpected alg: %v", t.Header["alg"])
                }
                return m.publicKey, nil
            },
            jwt.WithIssuer(m.issuer),
            jwt.WithExpirationRequired(),
        )
        if err != nil || !token.Valid {
            http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
            return
        }

        // Gắn claims vào context
        ctx := context.WithValue(r.Context(), "claims", token.Claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func extractBearerToken(r *http.Request) string {
    auth := r.Header.Get("Authorization")
    if strings.HasPrefix(auth, "Bearer ") {
        return strings.TrimPrefix(auth, "Bearer ")
    }
    return ""
}
```

### Kiểm tra scope

```go
func requireScope(scope string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims := r.Context().Value("claims").(jwt.MapClaims)
        scopes := strings.Fields(claims["scope"].(string))
        for _, s := range scopes {
            if s == scope {
                next.ServeHTTP(w, r)
                return
            }
        }
        http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
    })
}

// Sử dụng:
mux.Handle("/api/profile", jwtMiddleware.Middleware(
    requireScope("profile", profileHandler),
))
```

---

## 9. Ví dụ đầy đủ: Web App tích hợp OIDC

Ví dụ một web app Go sử dụng OIDC để đăng nhập người dùng.

```go
package main

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "log"
    "net/http"
    "net/url"

    "github.com/strongnguyen29/go-oidc-provider/internal/config"
    "github.com/strongnguyen29/go-oidc-provider/pkg/provider"
)

const (
    providerURL  = "http://localhost:9000"
    clientID     = "web-app"
    clientSecret = "web-secret"
    redirectURI  = "http://localhost:8080/callback"
)

func main() {
    // === Authorization Server (chạy cùng process, hoặc tách ra) ===
    cfg := &config.Config{
        Issuer: providerURL,
        Clients: []config.ClientConfig{{
            ID: clientID, Secret: clientSecret,
            RedirectURIs:  []string{redirectURI},
            GrantTypes:    []string{"authorization_code", "refresh_token"},
            ResponseTypes: []string{"code"},
            Scopes:        []string{"openid", "profile", "email"},
            TokenEndpointAuthMethod: "client_secret_basic",
        }},
        FindAccount: func(ctx context.Context, sub string) (*config.Account, error) {
            return &config.Account{Sub: sub, Claims: map[string]interface{}{
                "name": "User " + sub, "email": sub + "@example.com",
            }}, nil
        },
        AuthenticateAccount: func(ctx context.Context, login, pw string) (*config.Account, error) {
            if pw != "password" {
                return nil, nil
            }
            return &config.Account{Sub: login}, nil
        },
    }
    p, _ := provider.New(cfg, nil)
    go http.ListenAndServe(":9000", p.Handler())

    // === Client Application ===
    mux := http.NewServeMux()
    mux.HandleFunc("/", homeHandler)
    mux.HandleFunc("/login", loginHandler)
    mux.HandleFunc("/callback", callbackHandler)
    mux.HandleFunc("/profile", profileHandler)

    log.Println("App: http://localhost:8080")
    http.ListenAndServe(":8080", mux)
}

// store đơn giản (production nên dùng Redis/DB)
var stateStore = map[string]string{}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    // Tạo PKCE
    verifierBytes := make([]byte, 32)
    rand.Read(verifierBytes)
    verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
    h := sha256.Sum256([]byte(verifier))
    challenge := base64.RawURLEncoding.EncodeToString(h[:])

    // Tạo state
    stateBytes := make([]byte, 16)
    rand.Read(stateBytes)
    state := base64.RawURLEncoding.EncodeToString(stateBytes)

    // Lưu verifier (trong production: server-side session)
    stateStore[state] = verifier

    // Redirect đến authorization server
    params := url.Values{
        "response_type":         {"code"},
        "client_id":             {clientID},
        "redirect_uri":          {redirectURI},
        "scope":                 {"openid profile email"},
        "state":                 {state},
        "code_challenge":        {challenge},
        "code_challenge_method": {"S256"},
    }
    http.Redirect(w, r, providerURL+"/authorize?"+params.Encode(), http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
    state := r.URL.Query().Get("state")
    code := r.URL.Query().Get("code")

    verifier, ok := stateStore[state]
    if !ok {
        http.Error(w, "invalid state", http.StatusBadRequest)
        return
    }
    delete(stateStore, state)

    // Đổi code lấy tokens
    req, _ := http.NewRequest("POST", providerURL+"/token", strings.NewReader(url.Values{
        "grant_type":    {"authorization_code"},
        "code":          {code},
        "redirect_uri":  {redirectURI},
        "code_verifier": {verifier},
    }.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.SetBasicAuth(clientID, clientSecret)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        http.Error(w, "token exchange failed", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    var tokens map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&tokens)

    // Lưu access token vào session (demo đơn giản)
    http.SetCookie(w, &http.Cookie{
        Name:     "access_token",
        Value:    tokens["access_token"].(string),
        Path:     "/",
        HttpOnly: true,
    })
    http.Redirect(w, r, "/profile", http.StatusFound)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("access_token")
    if err != nil {
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }

    req, _ := http.NewRequest("GET", providerURL+"/userinfo", nil)
    req.Header.Set("Authorization", "Bearer "+cookie.Value)
    resp, err := http.DefaultClient.Do(req)
    if err != nil || resp.StatusCode != http.StatusOK {
        http.Error(w, "failed to get profile", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    var profile map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&profile)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(profile)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, `<a href="/login">Đăng nhập</a> | <a href="/profile">Trang cá nhân</a>`)
}
```

---

## 10. Triển khai production

### Checklist production

- [ ] **Issuer URL dùng HTTPS**: `Issuer: "https://auth.example.com"` — provider tự bật `Secure` cookie
- [ ] **CookieSecret cố định**: Đặt `CookieSecret` bằng 32 byte ngẫu nhiên được lưu bền vững (không để trống)
- [ ] **Persistent storage**: Implement Redis/PostgreSQL adapter thay vì in-memory
- [ ] **Signing key bền vững**: RSA key hiện được tái tạo mỗi lần restart — cần lưu vào KMS/Vault
- [ ] **PKCE bắt buộc**: Bật `PKCERequired: true` cho tất cả authorization_code clients
- [ ] **Token TTL phù hợp**: AccessToken ngắn (15-30 phút), RefreshToken dài hạn
- [ ] **Rate limiting**: Đặt rate limiter trước `/token` và `/authorize`
- [ ] **Logging**: Ghi log login attempt, token issuance với IP và user agent
- [ ] **CORS**: Nếu SPA gọi trực tiếp các endpoint, cấu hình CORS header phù hợp
- [ ] **Health check**: Thêm `/health` endpoint cho load balancer

### Biến môi trường (gợi ý)

```go
cfg := &config.Config{
    Issuer:       os.Getenv("OIDC_ISSUER"),      // "https://auth.example.com"
    CookieSecret: mustDecodeHex(os.Getenv("COOKIE_SECRET")), // 32-byte hex
    // ...
}
```

### Docker

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /oidc-server ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /oidc-server /oidc-server
EXPOSE 9000
ENTRYPOINT ["/oidc-server"]
```

---

## 11. Xử lý lỗi thường gặp

### `redirect_uri not registered`

**Nguyên nhân:** `redirect_uri` trong authorization request không khớp với danh sách đăng ký.  
**Giải pháp:** Đảm bảo `RedirectURIs` trong `ClientConfig` khớp **chính xác** (kể cả trailing slash).

```go
// ❌ Sai
RedirectURIs: []string{"https://app.example.com/callback/"}

// ✅ Đúng (phải khớp chính xác với redirect_uri trong request)
RedirectURIs: []string{"https://app.example.com/callback"}
```

### `PKCE verification failed`

**Nguyên nhân:** `code_verifier` không khớp với `code_challenge` trong authorization request.  
**Giải pháp:** Đảm bảo lưu đúng `verifier` trong session của client và gửi lại ở bước token exchange.

```go
// code_challenge = BASE64URL(SHA256(verifier))
h := sha256.Sum256([]byte(verifier))
challenge := base64.RawURLEncoding.EncodeToString(h[:])
// Không dùng base64.StdEncoding — phải là RawURLEncoding
```

### Session cookie không hoạt động

**Nguyên nhân:** Cross-origin request hoặc `SameSite=Lax` chặn cookie.  
**Giải pháp:**
- Provider và client app phải cùng domain (hoặc subdomain)
- Dùng HTTPS để tránh bị chặn cookie `Secure`

### `authorization_pending` mãi không hết

**Nguyên nhân:** User chưa hoàn thành xác minh device code.  
**Giải pháp:** Kiểm tra luồng: người dùng phải truy cập `/device`, nhập user code, và đăng nhập thành công.

### Token hết hạn sau khi restart server

**Nguyên nhân:** In-memory store mất dữ liệu sau restart.  
**Giải pháp:** Implement persistent adapter (Redis, PostgreSQL).

### `invalid_client` khi gọi /token

**Nguyên nhân:** Client credentials sai hoặc không đúng format Basic Auth.  
**Giải pháp:**

```bash
# Đúng format: base64(client_id:client_secret)
echo -n "web-app:web-secret" | base64
# → d2ViLWFwcDp3ZWItc2VjcmV0

curl -X POST https://auth.example.com/token \
  -H "Authorization: Basic d2ViLWFwcDp3ZWItc2VjcmV0" \
  -d "grant_type=authorization_code&code=..."
```
