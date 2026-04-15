# Các luồng OAuth2/OIDC

---

## 1. Authorization Code Flow + PKCE (khuyến nghị)

Luồng phổ biến nhất, phù hợp với web app, SPA, mobile app.

### Sơ đồ

```
Client                    Browser/User              Provider
  |                            |                       |
  |--- 1. Redirect /authorize -->                      |
  |         (code_challenge)   |                       |
  |                            |--- GET /authorize --->|
  |                            |                       |
  |                            |<-- redirect /interaction/{uid} login
  |                            |                       |
  |                            |--- POST /interaction/{uid}/login
  |                            |    (username, password)           |
  |                            |                       |
  |                            |<-- redirect /interaction/{uid} consent (nếu cần)
  |                            |                       |
  |                            |--- POST /interaction/{uid}/confirm
  |                            |    (granted_scopes)   |
  |                            |                       |
  |                            |<-- redirect /authorize (lần 2, tự động)
  |                            |                       |
  |                            |<-- redirect callback?code=...&state=...
  |                            |                       |
  |<-- 2. Nhận code từ callback|                       |
  |                            |                       |
  |--- 3. POST /token (code + code_verifier) --------->|
  |                            |                       |
  |<-- 4. access_token + id_token + refresh_token -----|
```

### Bước 1 — Tạo PKCE và redirect đến /authorize

```go
import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "net/url"
)

// Tạo code verifier (43-128 ký tự, random)
verifierBytes := make([]byte, 32)
rand.Read(verifierBytes)
verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

// Tạo code challenge = BASE64URL(SHA256(verifier))
h := sha256.Sum256([]byte(verifier))
challenge := base64.RawURLEncoding.EncodeToString(h[:])

// Tạo state ngẫu nhiên
stateBytes := make([]byte, 16)
rand.Read(stateBytes)
state := base64.RawURLEncoding.EncodeToString(stateBytes)

// Lưu verifier và state vào session của client (cookie, server-side session, ...)
session.Set("pkce_verifier", verifier)
session.Set("oauth_state", state)

// Tạo authorization URL
params := url.Values{
    "response_type":         {"code"},
    "client_id":             {"web-app"},
    "redirect_uri":          {"https://app.example.com/callback"},
    "scope":                 {"openid profile email offline_access"},
    "state":                 {state},
    "code_challenge":        {challenge},
    "code_challenge_method": {"S256"},
}
authURL := "https://auth.example.com/authorize?" + params.Encode()

http.Redirect(w, r, authURL, http.StatusFound)
```

### Bước 2 — Xử lý callback

```go
func handleCallback(w http.ResponseWriter, r *http.Request) {
    // Kiểm tra state chống CSRF
    state := r.URL.Query().Get("state")
    if state != session.Get("oauth_state") {
        http.Error(w, "invalid state", http.StatusBadRequest)
        return
    }

    code := r.URL.Query().Get("code")
    if errCode := r.URL.Query().Get("error"); errCode != "" {
        http.Error(w, errCode+": "+r.URL.Query().Get("error_description"), http.StatusBadRequest)
        return
    }

    // Đổi code lấy tokens
    verifier := session.Get("pkce_verifier")
    tokens, err := exchangeCode(code, verifier)
    // ...
}
```

### Bước 3 — Đổi code lấy tokens

```go
func exchangeCode(code, verifier string) (*TokenResponse, error) {
    resp, err := http.PostForm("https://auth.example.com/token", url.Values{
        "grant_type":    {"authorization_code"},
        "code":          {code},
        "redirect_uri":  {"https://app.example.com/callback"},
        "code_verifier": {verifier},
    })
    // Authorization header dùng cho client_secret_basic:
    // req.Header.Set("Authorization", "Basic "+base64(client_id+":"+client_secret))
}
```

---

## 2. Refresh Token Flow

Dùng để lấy access token mới khi access token cũ hết hạn.

### Luồng

```
Client                               Provider
  |                                     |
  |--- POST /token (refresh_token) ---->|
  |                                     |
  |<-- access_token + refresh_token ----|
  |    (refresh token cũ bị thu hồi)    |
```

### Ví dụ

```go
resp, err := http.PostForm("https://auth.example.com/token", url.Values{
    "grant_type":    {"refresh_token"},
    "refresh_token": {savedRefreshToken},
})
// Authorization: Basic base64(client_id:client_secret)
```

**Lưu ý quan trọng:** Refresh token được **xoay vòng** — mỗi lần dùng sẽ nhận về token mới, token cũ bị vô hiệu ngay. Cần lưu refresh token mới sau mỗi lần refresh.

---

## 3. Device Authorization Flow (RFC 8628)

Dùng cho thiết bị không có trình duyệt (TV, CLI, IoT).

### Sơ đồ

```
Device App             User's Browser           Provider
  |                         |                     |
  |-- 1. POST /device/authorization -------------->|
  |<-- device_code, user_code, verification_uri --|
  |                         |                     |
  |-- 2. Hiện user_code cho người dùng            |
  |                         |                     |
  |                         |-- GET /device?user_code=WDJB-MJHT ->
  |                         |                     |
  |                         |<-- trang login ------|
  |                         |-- POST login ------->|
  |                         |<-- "Device authorized!" --|
  |                         |                     |
  |-- 3. Poll POST /token (mỗi 5 giây) ---------->|
  |<-- authorization_pending (chờ) ↩              |
  |                         |                     |
  |-- Poll lại... ---------------------------------------->|
  |<-- access_token + refresh_token --------------|
```

### Bước 1 — Yêu cầu device code

```go
resp, err := http.PostForm("https://auth.example.com/device/authorization", url.Values{
    "scope": {"openid profile"},
})
// Authorization: Basic base64(client_id:client_secret)

var data struct {
    DeviceCode              string `json:"device_code"`
    UserCode                string `json:"user_code"`
    VerificationURI         string `json:"verification_uri"`
    VerificationURIComplete string `json:"verification_uri_complete"`
    ExpiresIn               int    `json:"expires_in"`
    Interval                int    `json:"interval"`
}
json.NewDecoder(resp.Body).Decode(&data)

fmt.Printf("Vui lòng truy cập: %s\nNhập mã: %s\n",
    data.VerificationURI, data.UserCode)
```

### Bước 2 — Poll token endpoint

```go
ticker := time.NewTicker(time.Duration(data.Interval) * time.Second)
for range ticker.C {
    resp, _ := http.PostForm("https://auth.example.com/token", url.Values{
        "grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
        "device_code": {data.DeviceCode},
    })
    
    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    
    switch result["error"] {
    case nil:
        // Thành công!
        accessToken := result["access_token"].(string)
        ticker.Stop()
        return accessToken
    case "authorization_pending":
        // Tiếp tục chờ
    case "slow_down":
        // Tăng interval thêm 5 giây
    default:
        // Lỗi nghiêm trọng: expired_token, access_denied
        return "", fmt.Errorf("%v", result["error"])
    }
}
```

---

## 4. Implicit Flow

Dùng khi client không thể giữ secret (SPA thuần không có backend).  
**Không khuyến nghị** — nên dùng Authorization Code + PKCE thay thế.

### Ví dụ URL

```
GET /authorize?response_type=id_token token
    &client_id=spa-client
    &redirect_uri=https://app.example.com/callback
    &scope=openid profile
    &nonce=n-0S6_WzA2Mj
    &state=af0ifjsldkj
```

**Response** (fragment):

```
https://app.example.com/callback#
    access_token=eyJ...
    &token_type=Bearer
    &expires_in=3600
    &id_token=eyJ...
    &state=af0ifjsldkj
```

---

## 5. Resource Owner Password Credentials (ROPC)

Dùng khi client là trusted first-party app (ví dụ: mobile app của chính công ty).  
**Không khuyến nghị** cho third-party clients.

```go
resp, err := http.PostForm("https://auth.example.com/token", url.Values{
    "grant_type": {"password"},
    "username":   {"alice@example.com"},
    "password":   {"my-secret-password"},
    "scope":      {"openid profile offline_access"},
})
// Authorization: Basic base64(client_id:client_secret)
```

Cần implement `AuthenticateAccount` trong `config.Config`.

---

## 6. RP-Initiated Logout

Đăng xuất người dùng từ Authorization Server sau khi đăng xuất khỏi client app.

```go
// Tạo logout URL
params := url.Values{
    "id_token_hint":            {savedIDToken},
    "post_logout_redirect_uri": {"https://app.example.com/"},
    "state":                    {"logout-state-xyz"},
}
logoutURL := "https://auth.example.com/logout?" + params.Encode()
http.Redirect(w, r, logoutURL, http.StatusFound)
```

**Lưu ý:** `post_logout_redirect_uri` phải được đăng ký trước trong `ClientConfig.PostLogoutRedirectURIs`.

---

## 7. Xác minh Access Token tại Resource Server

Resource Server nhận access token JWT và cần xác minh chữ ký.

### Lấy JWKS và cache

```go
import (
    "github.com/golang-jwt/jwt/v5"
    "github.com/golang-jwt/jwt/v5/jwk"
)

// Cache JWKS (nên refresh định kỳ hoặc khi gặp kid mới)
jwksURL := "https://auth.example.com/jwks"

// Parse và xác minh token
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    kid := token.Header["kid"].(string)
    return getPublicKeyFromJWKS(jwksURL, kid)
})

if err != nil || !token.Valid {
    http.Error(w, "invalid token", http.StatusUnauthorized)
    return
}

claims := token.Claims.(jwt.MapClaims)
sub := claims["sub"].(string)
scope := claims["scope"].(string)
```

### Cấu trúc JWT access token

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": ["https://auth.example.com"],
  "iat": 1716918000,
  "exp": 1716921600,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "scope": "openid profile email",
  "client_id": "web-app"
}
```

---

## 8. Introspection tại Resource Server

Thay vì xác minh JWT locally, Resource Server có thể gọi introspection endpoint.  
Phù hợp khi cần hỗ trợ revocation real-time.

```go
resp, err := http.PostForm("https://auth.example.com/introspect", url.Values{
    "token": {accessToken},
})
// Authorization: Basic base64(rs_client_id:rs_client_secret)

var result map[string]interface{}
json.NewDecoder(resp.Body).Decode(&result)

if active, ok := result["active"].(bool); !ok || !active {
    http.Error(w, "token inactive", http.StatusUnauthorized)
    return
}
sub := result["sub"].(string)
```

---

## Tóm tắt chọn luồng phù hợp

| Loại ứng dụng | Luồng khuyến nghị |
|---|---|
| Web app có backend (server-side) | Authorization Code + PKCE |
| SPA (React, Vue) với backend | Authorization Code + PKCE |
| Mobile app | Authorization Code + PKCE |
| CLI / TV / IoT | Device Authorization Flow |
| First-party mobile app | ROPC (nếu thực sự cần thiết) |
| Machine-to-machine | Client Credentials *(chưa triển khai)* |
