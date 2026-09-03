# Nâng app từ `@strongnguyen/oidc-provider` 7.16.x lên 9.11.6

Tài liệu này dành cho **app tích hợp**, không phải cho người phát triển thư viện. Nó
chỉ nói những gì phía app phải đổi.

Thiết kế và quá trình thi công phía thư viện nằm ở
[`superpowers/specs/2026-08-27-v9-migration-design.md`](superpowers/specs/2026-08-27-v9-migration-design.md)
và [`superpowers/plans/2026-08-28-v9-migration.md`](superpowers/plans/2026-08-28-v9-migration.md).

Phiên bản đích: **9.11.6**, trên nền upstream `panva/node-oidc-provider@9.11.5`.
Nhánh: `vlive/oidc-provider-v9`.

---

## 0. Năm việc làm app gãy ngay lần chạy đầu

Đọc mục này trước. Bốn cái đầu là do upstream, cái thứ năm là do fork.

1. **Package thành ESM-only.** `require()` không còn dùng được.
2. **Cần Node 22+.** v9 bỏ hỗ trợ Node 18 và 20.
3. **Mọi route đều kết thúc request.** Middleware Koa đặt *sau* provider sẽ **không
   chạy nữa**. Provider cũng không còn handler 404 catch-all.
4. **`POST /auth` và `POST /session/end` bị tắt mặc định.**
5. **Cookie `_SID` không còn trong thư viện.** App phải tự đặt, nếu không tính năng
   chia sẻ session theo root-domain im lặng ngừng hoạt động — không lỗi, không log.

---

## 1. Điều kiện tiên quyết

```bash
node --version   # phải >= 22
```

`package.json` của thư viện không khai `engines`, nhưng `lib/index.js` in cảnh báo
`Unsupported runtime. Use Node.js v22.x LTS, or a later LTS release.` khi chạy trên
runtime cũ hơn hoặc không phải Node LTS.

App phải là ESM: `"type": "module"` trong `package.json`, hoặc dùng đuôi `.mjs`.

---

## 2. Đổi cách import

```diff
- const Provider = require('@strongnguyen/oidc-provider');
- const { errors, interactionPolicy } = require('@strongnguyen/oidc-provider');
+ import Provider, { errors, interactionPolicy } from '@strongnguyen/oidc-provider';
```

Các export có sẵn:

| Export | Dạng |
|---|---|
| `Provider` | default **và** named — dùng cái nào cũng được |
| `errors` | named |
| `interactionPolicy` | named |
| `ExternalSigningKey` | named (mới ở v9, cho khóa ký trong KMS/HSM) |

---

## 3. Đổi cách gắn provider vào app

### 3.1 `provider.app` đã deprecate

`Provider` giờ **chính là** Koa app (`class Provider extends Koa`).

```diff
- provider.app.use(myMiddleware);
+ provider.use(myMiddleware);
```

Đây **không** phải hai cách viết của cùng một việc:

- `provider.use(fn)` được override để chèn middleware vào **trước** router, nên nó luôn
  ở vị trí *upstream* của mọi route. Đây là cái bạn muốn.
- `provider.use` khác `Koa.prototype.use`: gọi thẳng `provider.app.use(fn)` sẽ append
  vào cuối stack, tức chạy **sau** toàn bộ middleware nội bộ. Với những việc như đặt
  `ctx.req.deviceId`, làm vậy là quá muộn và patch sẽ không thấy gì.

### 3.2 Middleware "downstream" không còn chạy

v9 khiến mọi route kết thúc request. Nếu app đang dựa vào một middleware đặt sau
provider để log, đo, hay chỉnh response, **nó sẽ ngừng chạy**. Chuyển logic đó thành
middleware `provider.use()` dạng bọc:

```js
provider.use(async (ctx, next) => {
  const started = Date.now();
  try {
    await next();
  } finally {
    log(ctx.method, ctx.path, ctx.status, Date.now() - started);
  }
});
```

### 3.3 Không còn 404 catch-all

Trước đây provider trả 404 cho path không khớp route nào. Giờ nó gọi `next()`. Nếu app
mount provider vào một router lớn hơn thì đây thường là điều bạn muốn; nếu provider
đứng một mình, app phải tự thêm handler 404.

### 3.4 `ctx.oidc` chỉ tồn tại trong route của provider

Với request không khớp route nào, `ctx.oidc` là `undefined`. Mọi middleware
`provider.use()` phải guard `ctx.oidc?`.

---

## 4. Việc bắt buộc: đưa cookie `_SID` vào app

Ở v7 thư viện tự đặt cookie `_SID` (id tài khoản, chia sẻ theo root-domain) trong
session handler. Ở v9 phần đó **không được port**, vì cơ chế `ssHandler`
(same-site legacy fallback) mà nó dựa vào đã bị upstream xóa hẳn.

Thêm đoạn này vào app:

```js
provider.use(async (ctx, next) => {
  try {
    await next();
  } finally {
    const session = ctx.oidc?.session;
    if (session) {
      const opts = {
        httpOnly: false,
        overwrite: true,
        signed: false,
        sameSite: 'lax',
        secure: true,
        domain: '.example.vn',      // đổi thành root domain thật
      };
      if (!session.transient && session.exp) {
        opts.expires = new Date(session.exp * 1000);
      }
      ctx.cookies.set('_SID', session.destroyed ? '0' : (session.accountId || '0'), opts);
    }
  }
});
```

Bốn điều bắt buộc, không phải để cho gọn:

1. **`try/finally`.** Bản v7 nằm trong `finally` của session handler nên vẫn đặt cookie
   khi route ném lỗi. Bỏ `finally` là đổi hành vi.
2. **Guard `ctx.oidc?`** — request không khớp route nào thì `ctx.oidc` undefined.
3. **Guard `if (session)`** — route như `/token` không chạy session middleware.
4. **Chỉ đọc, không ghi vào `session`.** `ctx.oidc.session` là Proxy bẫy `set`; mọi phép
   ghi bật `touched` và kéo theo một lần persist ngoài ý muốn.

Một điểm được cải thiện: bản v7 phải chắp `; expires=...` vào chuỗi set-cookie bằng
regex. Từ ngoài ta biết `session.exp` nên truyền `expires` trực tiếp.

> **Bắt buộc có test.** Nếu upstream đổi hành vi splice của `provider.use()` hoặc đổi
> chỗ gắn `ctx.oidc`, cookie này sẽ **âm thầm** ngừng được đặt — không lỗi, không log,
> chỉ là session chia sẻ root-domain hết hoạt động. Viết một test trong repo app khẳng
> định `Set-Cookie: _SID=...` có mặt ở response của `/auth` và bị đặt `0` sau
> `/session/end`. Đây là cái giá đã chấp nhận khi đưa `_SID` ra khỏi thư viện.

---

## 5. Việc bắt buộc: khai lại hai config vốn hardcode

Ở v7 hai hành vi này nằm cứng trong code thư viện. Ở v9 chúng thành config, **mặc định
bằng hành vi upstream** — nghĩa là nếu không khai, app sẽ mất hành vi cũ.

```js
const provider = new Provider(issuer, {
  // v7 hardcode: userinfo nhận cả scope api_profile_get.
  // Không khai -> chỉ nhận openid, và mọi access token api_profile_get bị 403.
  userinfoRequiredScopes: ['openid', 'api_profile_get'],

  features: {
    introspection: {
      enabled: true,
      // v7 hardcode: token_type_hint sai thì trả inactive, không tra loại khác.
      // Không khai -> quay về hành vi RFC 7662, tra tiếp các loại còn lại.
      strictTokenTypeHint: true,
    },
  },
});
```

### Lưu ý về `userinfoRequiredScopes`

Qua được cửa scope **không** có nghĩa là nhận được claims. Claims vẫn bị lọc theo OIDC
scope, nên access token chỉ mang `api_profile_get` (không có `openid`) sẽ được
**chấp nhận với HTTP 200 nhưng body rỗng `{}`**, kể cả `sub` cũng không có.

Đây đúng là hành vi v7 đang chạy production, không phải hồi quy — nhưng nếu app đang
mong `/me` trả profile cho token `api_profile_get`, thì nó chưa từng làm vậy. Cần
`openid` trong scope để có claims.

### Ba ô hành vi introspection đổi so với v7

Ngay cả khi bật `strictTokenTypeHint: true`, ba trường hợp cho kết quả khác v7:

| Token | `token_type_hint` | v7 | v9 |
|---|---|---|---|
| ClientCredentials | `access_token` | `active: false` | **`active: true`** |
| AccessToken | `client_credentials` | `active: false` | **`active: true`** |
| ClientCredentials | `client_credentials` | `active: true` | `active: true` |

Lý do: v9 gộp AccessToken và ClientCredentials vào **cùng một nhóm** cho hint
`access_token`, vì theo RFC 7662 cả hai đều *là* access token; chế độ strict chỉ chặn
fallback ra ngoài nhóm, không chia nhỏ trong nhóm. Và `client_credentials` không còn là
hint hợp lệ nên rơi vào nhánh mặc định tra cả ba loại.

11 trường hợp còn lại giữ nguyên. v9 thêm nhận dạng URN
(`urn:ietf:params:oauth:token-type:access_token` và `...:refresh_token`).

---

## 6. Hai endpoint device flow đã bị xóa

```
POST /device/code-check
POST /device/code-verification
```

Cùng với config `features.deviceFlow.approvalScopeValidate`. Chúng **không được port**
sang v9. App nào đang gọi chúng sẽ gãy.

Bối cảnh nên biết: bản v7 đăng ký ba route trùng tên `code_verification`, mà router lưu
tên theo kiểu ghi-sau-thắng, nên `urlFor('code_verification')` trả
`/device/code-verification` thay vì `/device`. Hậu quả là **`verification_uri` gửi cho
thiết bị trỏ vào một endpoint POST-only đòi Bearer token**, thay vì trang nhập user
code. Đây là bug đã ship trong 7.16.6; bỏ patch khiến nó tự hết.

Nếu vẫn cần luồng phê duyệt device code bằng access token, nó phải được thiết kế lại —
đừng tái lập patch cũ.

---

## 7. Config đổi tên và bị xóa

| v7 | v9 |
|---|---|
| `tokenEndpointAuthMethods` | `clientAuthMethods` |
| `enabledJWA.tokenEndpointAuthSigningAlgValues` | `enabledJWA.clientAuthSigningAlgValues` |
| `revocationEndpointAuthMethods` | bỏ — dùng `clientAuthMethods` |
| `httpOptions` | `fetch` — chữ ký và giá trị trả về theo API `fetch()` |
| `features.requestObjects.request` | `features.requestObjects.enabled` |
| `features.requestObjects.requestUri` | bỏ — JAR by reference không còn hỗ trợ |
| `features.requestObjects.mode` | bỏ |
| `pkce.methods` | bỏ |

Client metadata bị xóa: `introspection_endpoint_auth_method`,
`introspection_endpoint_auth_signing_alg`, `revocation_endpoint_auth_method`,
`revocation_endpoint_auth_signing_alg`. Dùng `token_endpoint_auth_method` /
`token_endpoint_auth_signing_alg` cho cả ba endpoint.

API bị xóa: getter `provider.Account`. Thêm mới: `Provider.ctx` (static getter trả ctx
của request đang xử lý).

Định dạng token **PASETO bị xóa** (từ v8). Nếu app đang dùng, phải chuyển sang `jwt`
hoặc `opaque`.

Thuật toán bị xóa: `Ed448`, `X448`, `secp256k1`/`ES256K`, JWS `none`, JWE `RSA1_5`,
JWE PBKDF2. Profile `FAPI 1.0 ID2` bị xóa.

---

## 8. Giá trị mặc định đổi — kiểm lại từng dòng config của app

Những cái này **không** báo lỗi, chúng chỉ đổi hành vi.

| Config | v7 | v9 | Ảnh hưởng |
|---|---|---|---|
| `clockTolerance` | `0` | `15` | Nới 15s cho lệch đồng hồ |
| `ttl.AuthorizationCode` | 10 phút | **60 giây** | Client chậm đổi code sẽ gãy |
| `cookies.long.sameSite` | `none` | **`lax`** | Luồng cross-site gãy |
| `enableHttpPostMethods` | (POST luôn bật) | **`false`** | `POST /auth`, `POST /session/end` trả lỗi |
| `features.pushedAuthorizationRequests.enabled` | `false` | **`true`** | PAR bật sẵn |
| `features.dPoP.enabled` | `false` | **`true`** | DPoP bật sẵn |
| `acceptQueryParamAccessTokens` | `true` | **`false`** | Bearer qua query string bị chặn |
| `allowOmittingSingleRegisteredRedirectUri` | `false` | `true` | |
| `pkce.required` | luôn bắt buộc | chỉ với client `clientAuthMethod === 'none'` và FAPI | Nới lỏng |
| `features.registrationManagement.rotateRegistrationAccessToken` | `false` | `true` | Token quản lý bị rotate |
| `features.fapi.profile` | có mặc định | **bắt buộc khai** khi bật FAPI | |

Nếu app đang bật `enableHttpPostMethods: true`, nó **buộc** `cookies.long.sameSite`
phải là `'none'` — thư viện kiểm điều này.

---

## 9. Đổi trong nội dung token và HTTP response

- **`at_hash` không còn** trong id_token của grant `authorization_code`, `device_code`,
  `refresh_token`. CIBA ping/poll cũng bỏ `at_hash`,
  `urn:openid:params:jwt:claim:rt_hash`, `urn:openid:params:jwt:claim:auth_req_id`.
- **`s_hash`** chỉ còn trong grant implicit khi request là FAPI 1.0 Final.
- JWT phát hành **không còn `"typ": "JWT"`**.
- **Truy cập resource không kèm access token giờ trả 401**, trước là 400.
- **Userinfo với Bearer token mà kèm cả DPoP giờ bị từ chối.** Userinfo cũng trả cả hai
  challenge `dpop` và `bearer` khi DPoP đang bật.
- **`kid` của JWK phải là duy nhất** — không hai khóa nào được trùng `kid`. Kiểm lại
  keystore của app.
- Mọi identifier sinh ngẫu nhiên tăng từ ~126 bit lên ~256 bit entropy. Nếu adapter của
  app có giới hạn độ dài cột, kiểm lại schema.
- `revokeGrantPolicy` giờ **cũng** được gọi khi thu hồi access token dạng opaque (giá
  trị trả về mặc định vẫn là `false` cho trường hợp này).

---

## 10. Grant type tuỳ biến

`provider.registerGrantType(name, handler, params, dupes)` giữ nguyên chữ ký, và
`grantTypeParamsDefault` vẫn hoạt động như cũ.

Một điểm dễ mắc, đúng ở cả v7 và v9 nhưng thường chỉ lộ ra khi refactor:

> `client_schema` validate `client.grant_types` theo tập grant type **đã đăng ký**. Nên
> client chỉ được khai một grant type ngoài chuẩn **sau khi** `registerGrantType` đã
> được gọi cho nó. Đăng ký muộn thì request đầu tiên trả
> `400 invalid_client_metadata`.

Gọi mọi `registerGrantType` ngay sau khi khởi tạo Provider, trước khi nhận request.

### Client khai `response_types` chứa `id_token`/`token`

v7 (có patch của fork) từ chối client nếu `grant_types` không chứa một trong năm tên
`implicit`/`password`/`social`/`telco`/`fast_login`. v9 không từ chối nữa mà tự thêm
`implicit` vào `grant_types`.

Hành vi đầu-cuối **giống nhau**: client vẫn lấy được id_token qua authorization
endpoint, vì cả hai phiên bản gác endpoint đó bằng `response_types`, không bằng
`grant_types`. Việc `implicit` xuất hiện trong `client.grantTypes` là thay đổi hình
thức — `implicit` không có handler ở token endpoint nên `POST /token` với
`grant_type=implicit` vẫn trả `unsupported_grant_type`.

Chỉ lưu ý nếu app **đọc lại** `client.grantTypes` và so khớp chính xác: danh sách giờ
có thêm `implicit`.

---

## 11. Những gì KHÔNG đổi

Bảy tính năng riêng của fork giữ nguyên hành vi, đã có test đối chiếu từng assertion
giữa hai phiên bản:

| Tính năng | Trạng thái |
|---|---|
| `grantTypeParamsDefault` | không đổi |
| `cookies.prefix` | không đổi |
| `partner` / `ui_mode` echo trong authorization response | không đổi |
| `ctx.trackingAction` + event `refresh_token` | không đổi |
| Session `loginFrom` (mặc định `web`) và `deviceId` | không đổi |
| userinfo nhận `api_profile_get` | không đổi, nhưng phải khai config (mục 5) |
| introspection strict `token_type_hint` | phải khai config, và 3 ô đổi (mục 5) |

Hai chi tiết nhỏ đáng biết vì dễ "sửa" sai:

- **`partner`/`ui_mode` với giá trị chuỗi rỗng không được echo.** `lib/helpers/params.js`
  chạy `params[prop] || undefined` nên giá trị falsy thành `undefined` trước khi tới
  chỗ echo. Giống v7.
- **`ctx.trackingAction` với `amr` dạng array** rơi vào nhánh `default` và bị nội suy:
  `['pwd']` → `'loginpwd'`, `['pwd','otp']` → `'loginpwd,otp'`. Chỉ `amr` dạng string
  mới khớp `case`. Giống v7 — đây là hành vi được giữ có chủ ý, không phải lỗi.

`partner` và `ui_mode` vẫn phải đăng ký qua `extraParams` mới vào được
`ctx.oidc.params`.

---

## 12. Danh sách kiểm trước khi lên production

Cài bản đóng gói thật, đừng cài từ đường dẫn thư mục:

```bash
npm pack   # trong repo thư viện -> strongnguyen-oidc-provider-9.11.6.tgz
npm install /đường/dẫn/strongnguyen-oidc-provider-9.11.6.tgz
```

Rồi kiểm từng mục:

- [ ] App khởi động, không có cảnh báo `Unsupported runtime`
- [ ] Luồng authorization code trọn vòng: login → code → token → userinfo
- [ ] Refresh token: consumer nhận được event `refresh_token`, `ctx.trackingAction`
      đúng giá trị mong đợi
- [ ] Cookie `_SID` xuất hiện ở `/auth`, và bị đặt `0` sau `/session/end` (mục 4)
- [ ] Cookie có đúng tiền tố `cookies.prefix` đã cấu hình
- [ ] Grant type tuỳ biến nhận được params khai trong `grantTypeParamsDefault`
- [ ] Userinfo nhận access token scope `api_profile_get` (và hiểu rằng body rỗng nếu
      không có `openid`)
- [ ] Introspection với `token_type_hint` sai trả `active: false` — trừ ba ô ở mục 5
- [ ] `partner` / `ui_mode` quay về trong authorization response
- [ ] Middleware log/đo của app vẫn chạy (mục 3.2)
- [ ] Không còn chỗ nào gọi `POST /auth`, `POST /session/end`,
      `/device/code-check`, `/device/code-verification`
- [ ] Không còn chỗ nào truyền access token qua query string
- [ ] Client nào đổi code chậm hơn 60 giây đã được xử lý (mục 8)
