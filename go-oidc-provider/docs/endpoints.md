# Tham chiếu Endpoint

Provider mount tất cả route trên một `http.Handler` duy nhất.  
Đường dẫn gốc là Issuer URL (ví dụ `https://auth.example.com`).

---

## OIDC Discovery

### `GET /.well-known/openid-configuration`

Trả về metadata của Authorization Server theo chuẩn [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) và [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html).

**Response** `200 application/json`:

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  "jwks_uri": "https://auth.example.com/jwks",
  "device_authorization_endpoint": "https://auth.example.com/device/authorization",
  "introspection_endpoint": "https://auth.example.com/introspect",
  "revocation_endpoint": "https://auth.example.com/revoke",
  "end_session_endpoint": "https://auth.example.com/logout",
  "response_types_supported": ["code", "token", "id_token", "code token", "code id_token"],
  "grant_types_supported": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "password"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
  "claims_supported": ["sub", "iss", "aud", "iat", "exp", "nonce", "auth_time", "name", "email", "picture"],
  "code_challenge_methods_supported": ["S256", "plain"]
}
```

---

## JWKS

### `GET /jwks`

Trả về tập public key theo định dạng [JSON Web Key Set (RFC 7517)](https://datatracker.ietf.org/doc/html/rfc7517).  
Client/Resource Server dùng endpoint này để xác minh chữ ký JWT.

**Response** `200 application/json`:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "550e8400-e29b-41d4-a716-446655440000",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps...",
      "e": "AQAB"
    }
  ]
}
```

**Lưu ý:** Key được sinh ngẫu nhiên mỗi khi provider khởi động.  
Với production, hãy lưu key vào persistent storage để tránh token vô hiệu sau restart.

---

## Authorization Endpoint

### `GET /authorize`

Khởi đầu luồng authorization.

**Query parameters:**

| Tham số | Bắt buộc | Mô tả |
|---|---|---|
| `response_type` | ✅ | `code`, `token`, `id_token`, hoặc kết hợp |
| `client_id` | ✅ | Client identifier đã đăng ký |
| `redirect_uri` | ✅ | URI callback đã đăng ký cho client |
| `scope` | ✅ | Space-separated scopes (phải có `openid` cho OIDC) |
| `state` | Khuyến nghị | Giá trị ngẫu nhiên chống CSRF |
| `nonce` | OIDC | Giá trị ngẫu nhiên chống replay (bắt buộc với implicit flow) |
| `code_challenge` | PKCE | Base64url(SHA256(verifier)) |
| `code_challenge_method` | PKCE | `S256` (khuyến nghị) hoặc `plain` |
| `prompt` | Tuỳ chọn | `login` \| `consent` \| `select_account` |

**Kết quả** (sau khi người dùng xác thực):
- `response_type=code`: redirect đến `redirect_uri?code=...&state=...`
- `response_type=token`: redirect đến `redirect_uri#access_token=...`
- `response_type=id_token`: redirect đến `redirect_uri#id_token=...`

**Ví dụ:**

```
GET /authorize?response_type=code
    &client_id=web-app
    &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
    &scope=openid%20profile%20email
    &state=xyzABC123
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256
```

**Lỗi** (redirect về `redirect_uri?error=...`):

| `error` | Tình huống |
|---|---|
| `invalid_request` | Thiếu tham số bắt buộc |
| `invalid_client` | `client_id` không tồn tại |
| `invalid_redirect_uri` | `redirect_uri` chưa đăng ký |
| `access_denied` | Người dùng từ chối |

---

## Token Endpoint

### `POST /token`

Đổi authorization code, device code, password, hoặc refresh token để lấy access token.

**Authentication**: `Authorization: Basic base64(client_id:client_secret)`  
*(hoặc `client_id` / `client_secret` trong request body nếu `TokenEndpointAuthMethod = "none"`)*

---

#### Grant: `authorization_code`

**Request body** (`application/x-www-form-urlencoded`):

```
grant_type=authorization_code
&code=AUTH_CODE
&redirect_uri=https://app.example.com/callback
&code_verifier=PKCE_VERIFIER   (bắt buộc nếu authorization request có code_challenge)
```

**Response** `200 application/json`:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "d1e8a93f-...",
  "id_token": "eyJhbGciOiJSUzI1NiJ9...",
  "scope": "openid profile email"
}
```

---

#### Grant: `refresh_token`

**Request body:**

```
grant_type=refresh_token
&refresh_token=d1e8a93f-...
```

**Response** `200 application/json`: *(giống authorization_code, không có `id_token`)*

**Lưu ý:** Refresh token được xoay vòng — token cũ bị vô hiệu, token mới được trả về.

---

#### Grant: `urn:ietf:params:oauth:grant-type:device_code`

**Request body:**

```
grant_type=urn:ietf:params:oauth:grant-type:device_code
&device_code=DEVICE_CODE
```

**Response khi chờ** `400 application/json`:

```json
{"error": "authorization_pending"}
```

**Response khi thành công** `200 application/json`: *(giống authorization_code)*

---

#### Grant: `password` (ROPC)

**Request body:**

```
grant_type=password
&username=alice
&password=secret
&scope=openid profile
```

**Response** `200 application/json`: *(giống authorization_code)*

---

**Lỗi token endpoint:**

| `error` | HTTP | Tình huống |
|---|---|---|
| `invalid_client` | 401 | Sai client credentials |
| `invalid_grant` | 400 | Code sai, hết hạn, hoặc đã dùng |
| `invalid_request` | 400 | Thiếu tham số bắt buộc |
| `unsupported_grant_type` | 400 | grant_type không được hỗ trợ |
| `authorization_pending` | 400 | Device chưa được user xác nhận |
| `expired_token` | 400 | Device code đã hết hạn |
| `access_denied` | 400 | User từ chối device |

---

## UserInfo Endpoint

### `GET /userinfo` hoặc `POST /userinfo`

Trả về claims của người dùng sở hữu access token.

**Authentication**: `Authorization: Bearer ACCESS_TOKEN`

**Response** `200 application/json`:

```json
{
  "sub": "user-123",
  "name": "Nguyễn Văn A",
  "email": "a@example.com",
  "picture": "https://cdn.example.com/avatars/user-123.jpg"
}
```

**Lỗi:**

| `error` | HTTP | Tình huống |
|---|---|---|
| `invalid_token` | 401 | Token không hợp lệ hoặc hết hạn |

---

## Device Authorization Endpoint

### `POST /device/authorization`

Khởi tạo Device Authorization Grant. Client gửi request, nhận `device_code` và `user_code`.

**Authentication**: `Authorization: Basic base64(client_id:client_secret)`

**Request body:**

```
scope=openid profile
```

**Response** `200 application/json`:

```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://auth.example.com/device",
  "verification_uri_complete": "https://auth.example.com/device?user_code=WDJB-MJHT",
  "expires_in": 300,
  "interval": 5
}
```

---

## Device Code Verification

### `GET /device`

Hiển thị form để người dùng nhập `user_code` trên trình duyệt.

### `POST /device`

**Request body:**

```
user_code=WDJB-MJHT
```

Nếu người dùng chưa đăng nhập, redirect đến trang login interaction.  
Sau khi xác nhận, device code được đánh dấu là verified.

---

## Introspection Endpoint

### `POST /introspect`

Kiểm tra trạng thái của một token ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)).

**Authentication**: `Authorization: Basic base64(client_id:client_secret)`

**Request body:**

```
token=eyJhbGciOiJSUzI1NiJ9...
token_type_hint=access_token   (tuỳ chọn)
```

**Response `active=true`** `200 application/json`:

```json
{
  "active": true,
  "sub": "user-123",
  "client_id": "web-app",
  "scope": "openid profile",
  "iss": "https://auth.example.com",
  "exp": 1716921600,
  "iat": 1716918000,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "token_type": "access_token"
}
```

**Response `active=false`** `200 application/json`:

```json
{"active": false}
```

---

## Revocation Endpoint

### `POST /revoke`

Thu hồi access token hoặc refresh token ([RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)).

**Authentication**: `Authorization: Basic base64(client_id:client_secret)`

**Request body:**

```
token=TOKEN_VALUE
token_type_hint=refresh_token   (tuỳ chọn: "access_token" | "refresh_token")
```

**Response** `200 OK` (luôn trả về 200 theo RFC 7009, dù token không tồn tại)

---

## End Session (RP-Initiated Logout)

### `GET /logout`

Kết thúc session người dùng ([OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-logout-1_0.html)).

**Query parameters:**

| Tham số | Mô tả |
|---|---|
| `id_token_hint` | ID Token trước đó để xác định client và user |
| `post_logout_redirect_uri` | URI redirect sau logout (phải đã đăng ký trong `PostLogoutRedirectURIs`) |
| `state` | Giá trị truyền qua cho `post_logout_redirect_uri` |
| `client_id` | Client identifier (dùng nếu không có `id_token_hint`) |

**Kết quả:**
- Nếu `post_logout_redirect_uri` hợp lệ: redirect đến URI đó với `?state=...`
- Ngược lại: hiển thị trang xác nhận đã đăng xuất

---

## Interaction Endpoints

Các endpoint này phục vụ giao diện người dùng (login/consent).

### `GET /interaction/{uid}`

Hiển thị trang tương tác dựa vào `prompt` (`login`, `consent`, `select_account`).

### `POST /interaction/{uid}/login`

Xử lý đăng nhập.

**Request body (form):**

```
login=alice
password=secret
```

**Kết quả:** Redirect về `/authorize` với params gốc; session cookie được ghi.

### `POST /interaction/{uid}/confirm`

Xử lý đồng ý cấp quyền (consent).

**Request body (form):**

```
granted_scopes=openid&granted_scopes=profile&granted_scopes=email
```

**Kết quả:** Redirect về `/authorize`; consent được lưu vào session.

### `POST /interaction/{uid}/abort`

Người dùng từ chối (cancel).

**Kết quả:** Redirect về `redirect_uri?error=access_denied`.

---

## Định dạng lỗi

**JSON error** (dùng cho token, introspect, revoke, userinfo):

```json
{
  "error": "invalid_grant",
  "error_description": "authorization code expired"
}
```

**Redirect error** (dùng cho authorization endpoint):

```
https://app.example.com/callback?error=access_denied&error_description=user+denied+access&state=xyzABC123
```
