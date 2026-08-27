# Nâng fork từ v7.16.6 lên v9.11.x

Ngày: 2026-08-27
Trạng thái: đã duyệt thiết kế, chờ viết kế hoạch triển khai

## 1. Mục tiêu

Đưa fork `@strongnguyen/oidc-provider` từ nền upstream `7.14.3` lên nền upstream
`9.11.5`, giữ nguyên hành vi của các tính năng riêng còn dùng, và để lại một
lịch sử git cho phép sync upstream lần sau bằng một lệnh `git rebase`.

Kết quả: nhánh `vlive/oidc-provider-v9` = `origin/main` + 7 commit patch.
Nhánh `vlive/oidc-provider` hiện tại không bị đụng tới.

## 2. Hiện trạng

Fork cắt tại `57541df7` (`chore(release): 7.14.3`) — đúng commit upstream dùng
làm base cho `8.0.0`. Nhờ vậy `git diff 57541df7...HEAD` là tập patch riêng
chính xác, không lẫn code upstream.

Tập patch: 15 file, ~250 dòng thực (không tính `package-lock.json`, `CLAUDE.md`).
Không có một dòng test nào cho các patch này: `git diff --name-only 57541df7...HEAD -- test/`
trả về rỗng.

`origin/main` là bản mirror nguyên vẹn upstream (`homepage: panva/node-oidc-provider`),
fork không có thay đổi riêng trên đó.

## 3. Khoảng cách v7 → v9

Hai major, khoảng 70 breaking change. Ba nhóm ảnh hưởng tới việc port:

**ESM-only** (từ 8.0.0). Package thành `"type": "module"`, không còn `require()`.
App consumer đã ESM + Node 22+, nên không cần lớp tương thích CJS.

**Node 22+** (v9 bỏ Node 18 và 20). Fork hiện khai `engines: 12 || 14 || 16 || 18`;
v9 không khai `engines`.

**API nội bộ đổi:**

| v7 | v9 |
|---|---|
| `instance(p).configuration('a.b')` | `instance(p).configuration.a.b` |
| `instance(p).configuration('features.deviceFlow')` | `instance(p).features.deviceFlow` |
| `provider.app.createContext(...)` | `provider.createContext(...)` — Provider *là* Koa app |
| `ssHandler.set(cookies, name, val, opts)` | `ctx.cookies.set(name, val, opts)` — same-site fallback bị xoá hẳn; đây là lý do cookie `_SID` chuyển ra ngoài library (mục 4.4) |
| `module.exports = { get, post }` | `export const get` / `export const post` |
| `randomFill` + `Buffer.allocUnsafe` | đã bị loại khỏi codebase |
| XSRF viết tay trong action | `generateXsrf` / `checkXsrf` từ `lib/shared/xsrf.js` |
| `module.exports = function getDefaults()` | `export default makeDefaults` + `export const defaults` |

Ngoài ra: mọi route v9 giờ kết thúc request, nên middleware Koa "downstream" đặt
sau provider sẽ không chạy nữa; và provider không còn handler 404 catch-all.
Hai điều này ảnh hưởng app consumer, không ảnh hưởng patch trong repo.

Điểm thuận lợi: `registerGrantType`, `weak_cache`, `cookies.names`, `Session`
model, và cấu trúc `get()/post()` trong `initialize_app.js` đều còn ở v9 — không
patch nào bị mất chỗ đứng.

## 4. Quyết định cho từng patch

### 4.1 Bỏ — upstream đã tự làm (3)

**CORS echo `Origin`.** v9 `lib/shared/cors.js` đã có `const origin = ctx.get('Origin') || '*'`,
trùng nguyên văn ý định của patch. Upstream còn thay hẳn `@koa/cors` bằng bản
transcribe nội bộ, có test parity `test/cors/cors_parity.test.js`.

**`resCookie` array check.** Patch fork thêm `Array.isArray(resCookie) && length > 0`.
v9 đã tự sửa gốc: `if (typeof setCookie === 'string') setCookie = [setCookie]`.

**`client_schema` grant_types.** Patch fork nới `invalidate()` để cho phép
`response_types: ['id_token'|'token']` với grant `password`/`social`/`telco`/`fast_login`.
v9 đổi hẳn cơ chế: không `invalidate()` nữa mà tự `this.grant_types.push('implicit')`
(dòng 313-315). Nên lỗi mà patch từng chữa không còn tồn tại.

Cần một bước xác minh riêng — xem Pha 5 ở mục 6.

### 4.2 Bỏ — theo quyết định của chủ fork (1)

**Hai endpoint device flow qua access token** (`POST /device/code-check`,
`POST /device/code-verification`) cùng config `features.deviceFlow.approvalScopeValidate`.

Đây là patch nặng nhất (~180 dòng) và là phần duy nhất phải viết lại XSRF cùng
việc bỏ `randomFill`. Bỏ nó cắt khoảng một nửa công sức port.

Đã xác minh phạm vi ảnh hưởng là self-contained: `approvalScopeValidate` chỉ được
dùng trong `code_verification.js`; hai route chỉ được khai trong `defaults.js` và
`initialize_app.js`. Khi bỏ, hai file rơi hẳn khỏi phạm vi port:

- `lib/actions/code_verification.js` — không cần đụng, kể cả phần tách
  `codeVerificationCSRF`/`cleanup` thành hàm rời (việc tách đó chỉ nhằm tái dùng
  cho hai endpoint bị bỏ)
- `lib/helpers/initialize_app.js` — không cần đụng

**Hệ quả đã chấp nhận:** hai endpoint trên sẽ không tồn tại ở bản v9. App nào
đang gọi chúng sẽ gãy. Giả định: luồng device flow qua access token đã ngừng dùng.

### 4.3 Hook hoá — tách khỏi luồng upstream (2)

**`userinfo` chấp nhận scope `api_profile_get`.** v9 tách phần này vào
`getValidateAccessToken({ afterFind })` (`lib/shared/access_token.js`), gọi từ
`lib/actions/userinfo.js:25`. Patch chuyển thành config mới:

```
userinfoRequiredScopes: ['openid']
```

`afterFind` đọc config, pass nếu access token có **bất kỳ** scope trong danh sách.
Mặc định `['openid']` giữ đúng hành vi upstream; fork cấu hình
`['openid', 'api_profile_get']`. Thông điệp lỗi `InsufficientScope` dựng từ danh sách.

**`introspection` không cross-lookup khi `token_type_hint` sai.** v9 tách phần tìm
token vào `createTokenFinder(provider, grantTypeHandlers)` (`lib/helpers/token_find.js`).
Patch chuyển thành config mới:

```
features.introspection.strictTokenTypeHint: false
```

Khi `true`, `findTokenByHint` chỉ tra đúng loại theo hint, không fallback sang loại
khác. Mặc định `false` giữ đúng hành vi upstream (và đúng RFC 7662). Patch còn
khoảng 3 dòng, đặt trong `token_find.js`.

Lý do hook hoá thay vì port nguyên trạng: cả hai chỗ upstream đã chừa sẵn khớp nối,
nên đưa vào config khiến lần rebase sau gần như không đụng gì; đồng thời mặc định
vẫn là hành vi chuẩn, ai đọc code cũng thấy rõ chỗ fork lệch.

### 4.4 Chuyển ra ngoài library (1)

**Cookie `_SID` chia sẻ root-domain.** Không port. Chuyển hẳn sang app tích hợp,
đặt qua một middleware upstream. Ba chỗ trong lib rời khỏi phạm vi:
`lib/shared/session.js`, `lib/actions/end_session.js`, và
`cookies.names.sessionAccountId` + `cookies.share` trong `defaults.js`.

Nếu port vào lib thì đây là patch duy nhất phải viết lại, vì `ssHandler`
(same-site legacy fallback) bị xoá hẳn ở v9. Chuyển ra ngoài thì patch biến mất.

#### Không đi bằng event

v9 **không có event nào cho session** — không `session.saved`, không
`session.destroyed`. Mọi event trong `docs/events.md` đều theo endpoint. Thêm
event mới lại chính là một patch fork, đúng thứ đang muốn giảm. Ngoài ra
`EventEmitter.emit` chạy đồng bộ và không `await` listener async, nên một
listener async đi set cookie sẽ đua với lúc Koa ghi response.

#### Đi bằng `provider.use()`

```js
provider.use(async (ctx, next) => {
  try {
    await next();
  } finally {
    const session = ctx.oidc?.session;
    if (session) {
      const opts = {
        httpOnly: false, overwrite: true, signed: false,
        sameSite: 'lax', secure: true, domain: '.example.vn',
      };
      if (!session.transient && session.exp) {
        opts.expires = new Date(session.exp * 1000);
      }
      ctx.cookies.set('_SID', session.destroyed ? '0' : (session.accountId || '0'), opts);
    }
  }
});
```

Bốn điều đã kiểm chứng trong code v9 để chắc chắn cơ chế này chạy:

1. `Provider extends Koa`, và `use()` được **override** (`lib/provider.js:440-444`):
   nó splice middleware vào **trước** `#exec`, nên mọi middleware thêm bằng
   `provider.use()` chắc chắn ở vị trí upstream. Changelog v9 nói thẳng:
   *"upstream control flows are unaffected"*.
2. Cụm "routes will now end the HTTP request" trong changelog **không phải**
   `res.end()`. Quét toàn bộ `lib/` v9 chỉ có đúng một `res.end()`, ở
   `interactionFinished` (`lib/provider.js:235`) — helper app tự gọi, ngoài Koa
   stack. `lib/helpers/router.js` chỉ là koa-compose thuần. Nên Koa vẫn ghi
   response sau khi stack unwind xong, và set cookie lúc đó vẫn kịp.
3. `ctx.oidc` được gắn bằng `Object.defineProperty` trong `ensureOIDC`
   (`lib/helpers/initialize_app.js:56-65`) — gắn theo từng route, nhưng đó là
   mutation trên `ctx`, nên nó còn nguyên khi unwind về middleware upstream.
4. `ensureSessionSave` persist session **trong** route stack, và `destroy()` set
   `this.destroyed = true` (`lib/models/session.js:110-113`). Nên lúc unwind,
   `accountId` đã chốt và `destroyed` đọc được.

#### Ba điều bắt buộc với người triển khai phía app

- **`try/finally` là bắt buộc**, không phải cho gọn. Patch cũ nằm trong `finally`
  của session handler nên vẫn set cookie khi route ném lỗi. Bỏ `finally` là đổi
  hành vi so với bản v7.
- **Hai guard bắt buộc:** `ctx.oidc?` (request không match route nào thì `ctx.oidc`
  undefined, vì `ensureOIDC` chạy theo route) và `if (session)` (route như
  `/token` không chạy session middleware).
- **Chỉ đọc, không ghi vào `session`.** Proxy trong `lib/shared/session.js` chỉ
  bẫy `set`; mọi phép ghi sẽ bật `touched` và kéo theo một lần persist ngoài ý muốn.

#### Điểm được thêm

Cái hack tệ nhất của patch cũ — dùng regex chắp `; expires=...` vào chuỗi
set-cookie — biến mất hẳn. Từ ngoài ta biết `session.exp` nên truyền `expires`
trực tiếp cho `cookies.set()`. Fork phải hack vì nó set cookie ngay trong session
handler, nơi `cookies.share` là config tĩnh.

Phần `Array.isArray` trong patch cũ cũng không còn liên quan (xem 4.1).

### 4.5 Port thẳng (5)

| Patch | File | Việc cần làm |
|---|---|---|
| `grantTypeParamsDefault` | `lib/provider.js`, `lib/helpers/defaults.js` | Đổi `instance(this).configuration('grantTypeParamsDefault')` → `this.#int.configuration.grantTypeParamsDefault`. Thêm default vào `makeDefaults()`. |
| Cookie prefix | `lib/provider.js` | `cookieName()` v9 đọc `this.#int.configuration.cookies.names[type]` và `throw` thay vì `assert`. Thêm `cookies.prefix` vào defaults. |
| `partner` / `ui_mode` | `lib/actions/authorization/respond.js` | Nguyên văn — vùng code quanh `params.state` không đổi. |
| `trackingAction` + emit `refresh_token` | `lib/actions/grants/refresh_token.js` | Nguyên văn. |
| Session `loginFrom` / `deviceId` / reuse `entities.Session` | `lib/models/session.js` | `payload()` list và `loginAccount()` không đổi. Phần `provider.app.createContext` là code upstream đã tự đổi, không phải việc của patch. |

### 4.6 Tổng kết phạm vi

**7 patch, 7 file lib** — cộng một việc nằm ở repo app (cookie `_SID`, mục 4.4).

| File | Patch dùng tới |
|---|---|
| `lib/helpers/defaults.js` | cả 4 mục config mới |
| `lib/provider.js` | `grantTypeParamsDefault`, cookie prefix |
| `lib/helpers/token_find.js` | hook `strictTokenTypeHint` |
| `lib/shared/access_token.js` | hook `userinfoRequiredScopes` |
| `lib/actions/authorization/respond.js` | `partner` / `ui_mode` |
| `lib/actions/grants/refresh_token.js` | `trackingAction` |
| `lib/models/session.js` | `loginFrom` / `deviceId` |

`defaults.js` (4 patch chạm) và `provider.js` (2 patch chạm) là hai file nhiều
patch cùng dùng. Với chúng, đặt thay đổi vào commit của từng patch tương ứng thay
vì gom một commit riêng, để mỗi commit vẫn tự đứng được.

Kiểm chứng con số: 12 patch ban đầu = 4 bỏ (4.1 + 4.2) + 2 hook hoá (4.3) +
1 chuyển ra ngoài (4.4) + 5 port thẳng (4.5). Còn lại trong library: 2 + 5 = 7.

Bốn mục config mới thêm vào `defaults.js`:

```
grantTypeParamsDefault: []
cookies.prefix: undefined
userinfoRequiredScopes: ['openid']
features.introspection.strictTokenTypeHint: false
```

So với bản trước khi chuyển `_SID` ra ngoài: từ 8 patch xuống 7, bớt 3 file
(`lib/shared/session.js`, `lib/actions/end_session.js`, và phần `cookies.share` +
`cookies.names.sessionAccountId` của `defaults.js`), và bớt đúng cái patch duy
nhất phải viết lại.

## 5. Chiến lược git

```
git switch -c vlive/oidc-provider-v9 origin/main
```

Rồi áp lại 7 patch, mỗi patch một commit.

**Loại phương án rebase 30 commit fork lên `origin/main`:** mỗi commit là code CJS
đặt trên file ESM đã viết lại — conflict toàn file, 30 lần, không cho kết quả tốt hơn.

**Loại phương án merge `origin/main` vào nhánh hiện tại:** cùng vấn đề, tệ hơn, và
để lại một merge commit khổng lồ không ai review được.

Sau khi nghiệm thu xong mới quyết định merge hay đổi tên nhánh. Không force-push
lên `vlive/oidc-provider` trong phạm vi việc này.

## 6. Thứ tự thi công

### Pha 0 — lưới an toàn

Viết test đặc tả cho 7 patch **trên nhánh v7 hiện tại**, chốt hành vi đang chạy.

Test viết ở đây là CJS/`jose2`/`nock`/chai 4; khi sang v9 phải dịch sang
ESM/chai 6/undici-mock. Nhưng phần assertion giữ nguyên — đó chính là thứ chứng
minh hành vi không đổi qua hai major.

Ưu tiên theo rủi ro: hai hook (`userinfo`, `introspection`) > 5 patch port thẳng.

Cookie `_SID` không nằm trong pha này nữa — nó thành việc của repo app (Pha 3).

### Pha 1 — nền

- Cắt nhánh từ `origin/main`
- Sửa `package.json`: `name` `@strongnguyen/oidc-provider`, `version` `9.11.6`,
  `homepage`/`repository` trỏ về fork, giữ script `publish`
- Bỏ `overrides` (`serialize-javascript`, `diff`) — kiểm tra lại xem v9 còn cần không
- `npm install && npm test` trên code upstream nguyên bản, xác nhận baseline xanh
  **trước khi** thêm bất cứ patch nào

### Pha 2 — 5 patch port thẳng

Theo bảng 4.5, mỗi patch một commit kèm test đã dịch từ Pha 0.

### Pha 3 — cookie `_SID` ở repo app

Nằm ngoài repo này. Theo mục 4.4: thêm middleware `provider.use()`, kèm một test
**trong repo app** khẳng định `Set-Cookie: _SID=...` có mặt trong response của
route authorization và route end_session.

Test đó không phải để cho đủ — nó là thứ duy nhất phát hiện khi upstream đổi
`use()` hoặc đổi chỗ `ensureOIDC`, vì lúc đó cookie sẽ âm thầm ngừng được set,
không lỗi, không log. Xem mục 9.

Pha này chạy song song được với Pha 2 và Pha 4, không phụ thuộc thứ tự.

### Pha 4 — hai hook

`userinfoRequiredScopes` và `features.introspection.strictTokenTypeHint`.
Mỗi config phải có khối JSDoc theo convention của repo, rồi chạy
`node docs/update-configuration.js` để sinh lại `docs/README.md`.

### Pha 5 — xác minh `client_schema`

Kiểm chứng ở v9: client khai `grant_types: ['password']` +
`response_types: ['id_token']` sẽ bị upstream tự thêm `implicit` vào `grant_types`.

Câu hỏi cần trả lời: việc `implicit` xuất hiện trong `grant_types` có làm
`check_client_grant_type` cho phép luồng implicit mà fork không muốn mở không?

- Nếu không: đóng lại, patch bỏ được như đã quyết.
- Nếu có: mở lại quyết định 4.1, cân nhắc hook hoá thành config thay vì bỏ.

Bước này phải làm **trước** khi tuyên bố hoàn thành, vì nó có thể thêm patch thứ 8.

### Pha 6 — nghiệm thu

- `npm test`
- `npm run test-ci` (ma trận express/koa/hapi/fastify)
- `npm run lint` (biome)
- Smoke test app consumer trên bản đóng gói `npm pack`, trong đó **phải** kiểm
  `_SID` xuất hiện đúng ở authorization và end_session (Pha 3)

## 7. Đổi tooling

v9 bỏ eslint/airbnb, dùng biome (`biome.json`, script `lint`). Script `format`
cũ (`eslint lib example certification test --fix`) không còn nghĩa — thay bằng
`npm run lint`. Script `publish` của fork phải cập nhật theo.

`docs/update-configuration.js` vẫn tồn tại ở v9, nên convention "thêm config thì
kèm khối JSDoc rồi regenerate docs" trong `CLAUDE.md` giữ nguyên hiệu lực.

`CLAUDE.md` cần cập nhật sau khi xong: mục "Fork-specific changes", danh sách
lệnh, và ghi chú diff-against là `panva/main` thay vì `panva/v7.x`.

## 8. Giả định

1. `origin/main` là mirror nguyên vẹn upstream, không có thay đổi riêng của fork.
2. App consumer đã ESM và chạy Node 22+ (đã xác nhận).
3. Luồng device flow qua access token (`/device/code-check`,
   `/device/code-verification`) đã ngừng dùng.
4. Version phát hành mới là `9.11.6` — bám số upstream, bump patch. Giữ tên
   `@strongnguyen/oidc-provider`.
5. Kết quả land ở nhánh mới `vlive/oidc-provider-v9`; việc merge về đâu quyết
   định sau nghiệm thu.
6. Repo app nhận trách nhiệm cookie `_SID` — cả code lẫn test. Nếu điều này không
   khả thi, mục 4.4 phải lật lại và patch quay vào library.

## 9. Rủi ro

| Rủi ro | Xử lý |
|---|---|
| Patch fork chưa từng có test → port sai mà không biết | Pha 0 |
| `client_schema` bỏ patch có thể mở nhầm implicit flow | Pha 5, chặn trước khi tuyên bố xong |
| App consumer gãy vì route v9 kết thúc request, không còn 404 catch-all | Smoke test Pha 6; nằm ngoài repo này |
| Mất hai endpoint device flow | Đã chấp nhận, xem giả định 3 |
| `overrides` trong `package.json` che một CVE nào đó | Kiểm tra lại ở Pha 1 trước khi bỏ |
| Cookie `_SID` **âm thầm ngừng được set** nếu upstream đổi hành vi splice của `use()` hoặc đổi chỗ `ensureOIDC` — không lỗi, không log, chỉ là session chia sẻ root-domain hết hoạt động | Test bắt buộc trong repo app (Pha 3) + kiểm lại ở mỗi lần sync upstream. Đây là cái giá đã chấp nhận khi chuyển `_SID` ra ngoài |
| Đọc `ctx.oidc.session` từ middleware app làm bật `touched` → persist ngoài ý muốn | Proxy chỉ bẫy `set`, nên chỉ đọc là an toàn; ghi rõ trong 4.4 là cấm ghi |
