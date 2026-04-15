# Tham chiếu cấu hình

Tất cả cấu hình được truyền qua struct `config.Config` khi khởi tạo Provider.

---

## `config.Config`

```go
type Config struct {
    // Issuer là URL gốc của Authorization Server (bắt buộc).
    // Ví dụ: "https://auth.example.com"
    // Không được có dấu "/" ở cuối.
    Issuer string

    // AccessTokenTTL là thời gian sống của access token JWT.
    // Mặc định: 1 giờ.
    AccessTokenTTL time.Duration

    // AuthCodeTTL là thời gian sống của authorization code.
    // Mặc định: 10 phút.
    AuthCodeTTL time.Duration

    // RefreshTokenTTL là thời gian sống của refresh token.
    // Mặc định: 14 ngày.
    RefreshTokenTTL time.Duration

    // DeviceCodeTTL là thời gian sống của device code.
    // Mặc định: 5 phút.
    DeviceCodeTTL time.Duration

    // DeviceInterval là khoảng thời gian (giây) tối thiểu giữa các lần poll
    // token endpoint trong Device Flow.
    // Mặc định: 5 giây.
    DeviceInterval int

    // Scopes là danh sách scope được provider hỗ trợ.
    // Mặc định: ["openid", "profile", "email", "offline_access"]
    Scopes []string

    // GrantTypes là danh sách grant type được phép.
    // Mặc định: ["authorization_code", "refresh_token",
    //             "urn:ietf:params:oauth:grant-type:device_code", "password", "implicit"]
    GrantTypes []string

    // PKCERequired = true bắt buộc code_challenge với authorization_code grant.
    // Mặc định: false.
    PKCERequired bool

    // CookieSecret là khóa 32-byte dùng để mã hóa session cookie.
    // Nếu để trống, provider tự sinh ngẫu nhiên khi khởi động.
    CookieSecret []byte

    // Clients là danh sách client đăng ký tĩnh.
    Clients []ClientConfig

    // FindAccount tra cứu thông tin tài khoản theo subject (sub).
    // Được gọi khi cần lấy claims cho UserInfo và ID Token.
    FindAccount func(ctx context.Context, sub string) (*Account, error)

    // AuthenticateAccount xác thực tài khoản bằng username/password.
    // Dùng cho Resource Owner Password Credentials grant.
    // Trả về nil, nil nếu thông tin đăng nhập không đúng.
    AuthenticateAccount func(ctx context.Context, login, password string) (*Account, error)
}
```

### Giá trị mặc định

Gọi `cfg.Defaults()` (hoặc `provider.New` tự gọi) để áp dụng mặc định:

| Trường | Mặc định |
|---|---|
| `AccessTokenTTL` | `1h` |
| `AuthCodeTTL` | `10m` |
| `RefreshTokenTTL` | `336h` (14 ngày) |
| `DeviceCodeTTL` | `5m` |
| `DeviceInterval` | `5` |
| `Scopes` | `["openid","profile","email","offline_access"]` |
| `GrantTypes` | `["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code","password","implicit"]` |

---

## `config.ClientConfig`

```go
type ClientConfig struct {
    // ID là client_id duy nhất (bắt buộc).
    ID string

    // Secret là client_secret dùng cho client_secret_basic auth.
    // Để trống nếu TokenEndpointAuthMethod = "none".
    Secret string

    // RedirectURIs là danh sách URI được phép sau khi authorization.
    // Bắt buộc với authorization_code và implicit flow.
    RedirectURIs []string

    // PostLogoutRedirectURIs là danh sách URI được phép sau khi logout.
    PostLogoutRedirectURIs []string

    // GrantTypes là các grant type client được phép sử dụng.
    // Ví dụ: ["authorization_code", "refresh_token"]
    GrantTypes []string

    // ResponseTypes là các response_type client được phép yêu cầu.
    // Ví dụ: ["code"], ["token"], ["id_token"]
    ResponseTypes []string

    // Scopes là danh sách scope client được phép yêu cầu.
    Scopes []string

    // TokenEndpointAuthMethod xác định cách client xác thực tại /token.
    // Giá trị hỗ trợ: "client_secret_basic" | "none"
    // Mặc định: "client_secret_basic"
    TokenEndpointAuthMethod string
}
```

---

## `config.Account`

```go
type Account struct {
    // Sub là subject identifier duy nhất cho người dùng.
    // Được dùng làm giá trị "sub" trong token và UserInfo.
    Sub string

    // Claims là các claim bổ sung trả về trong ID Token và UserInfo.
    // Ví dụ: {"name": "Nguyễn Văn A", "email": "a@example.com", "picture": "..."}
    Claims map[string]interface{}
}
```

---

## Ví dụ cấu hình đầy đủ

```go
cfg := &config.Config{
    Issuer:          "https://auth.example.com",
    AccessTokenTTL:  30 * time.Minute,
    RefreshTokenTTL: 7 * 24 * time.Hour,
    PKCERequired:    true,
    CookieSecret:    []byte("32-byte-secret-key-here-abcdefgh"),

    Scopes:     []string{"openid", "profile", "email", "offline_access"},
    GrantTypes: []string{"authorization_code", "refresh_token"},

    Clients: []config.ClientConfig{
        {
            ID:           "web-app",
            Secret:       "web-secret",
            RedirectURIs: []string{
                "https://app.example.com/callback",
                "https://app.example.com/silent-renew",
            },
            PostLogoutRedirectURIs: []string{"https://app.example.com/"},
            GrantTypes:   []string{"authorization_code", "refresh_token"},
            ResponseTypes: []string{"code"},
            Scopes:       []string{"openid", "profile", "email", "offline_access"},
            TokenEndpointAuthMethod: "client_secret_basic",
        },
        {
            ID:           "spa-client",
            Secret:       "",               // public client, không có secret
            RedirectURIs: []string{"http://localhost:5173/callback"},
            GrantTypes:   []string{"authorization_code"},
            ResponseTypes: []string{"code"},
            Scopes:       []string{"openid", "profile"},
            TokenEndpointAuthMethod: "none",
        },
    },

    FindAccount: func(ctx context.Context, sub string) (*config.Account, error) {
        // Tra cứu user từ database theo sub
        user, err := db.FindUserByID(ctx, sub)
        if err != nil {
            return nil, err
        }
        return &config.Account{
            Sub: user.ID,
            Claims: map[string]interface{}{
                "name":    user.FullName,
                "email":   user.Email,
                "picture": user.AvatarURL,
            },
        }, nil
    },

    AuthenticateAccount: func(ctx context.Context, login, password string) (*config.Account, error) {
        user, err := db.AuthenticateUser(ctx, login, password)
        if err != nil || user == nil {
            return nil, nil
        }
        return &config.Account{Sub: user.ID}, nil
    },
}
```
