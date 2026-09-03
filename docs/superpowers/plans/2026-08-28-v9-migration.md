# Nâng fork oidc-provider v7 → v9 — Kế hoạch triển khai

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Đưa fork `@strongnguyen/oidc-provider` từ nền upstream 7.14.3 lên nền upstream 9.11.5, giữ nguyên hành vi của 7 patch riêng còn dùng.

**Architecture:** Không rebase, không merge. Cắt nhánh mới từ `origin/main` (mirror upstream 9.11.5) rồi replay 7 patch thành 7 commit sạch. Trước khi replay, viết test đặc tả (characterization test) cho từng patch trên nhánh v7 hiện tại để chốt hành vi đang chạy; test đó là trọng tài cho bước port. Cookie `_SID` không port vào lib mà chuyển sang app tích hợp qua middleware `provider.use()`.

**Tech Stack:** Node 22+, ESM, Koa 3, jose 6, Mocha 11 + Chai 6 + Sinon 22 + supertest 7, biome (thay eslint/airbnb).

**Spec:** `docs/superpowers/specs/2026-08-27-v9-migration-design.md`

## Global Constraints

- Nhánh v7 (Task 1-6): `vlive/oidc-provider`, CommonJS, `engines: 12 || 14 || 16 || 18`, eslint airbnb-base, chai 4, `bootstrap(__dirname)`.
- Nhánh v9 (Task 7-18): `vlive/oidc-provider-v9` cắt từ `origin/main`, ESM-only (`"type": "module"`), Node 22+, biome, chai 6, `bootstrap(import.meta.url)`.
- Tên package giữ nguyên `@strongnguyen/oidc-provider`. Version mới: `9.11.6`.
- Truy cập config trong lib v9: `instance(provider).configuration.a.b` (property), **không** `configuration('a.b')` (function). Với feature flags có lối tắt `instance(provider).features.<name>`.
- Trong `lib/provider.js` dùng private field: `this.#int.configuration.a.b`.
- Mọi config mới **bắt buộc** phải có mặt trong `lib/helpers/defaults.js`. `lib/helpers/configuration.js:195` chạy `pick(config, ...Object.keys(this.#defaults))` — key không có trong defaults bị **lặng lẽ loại bỏ** khỏi config người dùng.
- Mọi config mới phải kèm khối JSDoc theo style v9 (`* <tên>` / `* title:` / `* description:` với câu đầy đủ dạng "Specifies ..."), rồi chạy `node docs/update-configuration.js`.
- Không `.only` / `.skip` trong test đã commit — `test/run.js` gọi `forbidOnly()` khi `CI=true`.
- Chỉ dùng lỗi từ `lib/helpers/errors.js`, không `throw new Error` trần trong đường xử lý request.
- Mỗi task kết thúc bằng một commit. Không gộp nhiều patch vào một commit.

## Bốn khác biệt so với spec, phát hiện khi lập kế hoạch

Đọc trước khi bắt đầu — mỗi cái đổi nội dung một task:

1. **Hook `userinfo` đặt ở `lib/actions/userinfo.js`, không phải `lib/shared/access_token.js`.** `getValidateAccessToken({ afterFind })` gọi `await afterFind?.(ctx, accessToken)` với `ctx`, nên closure `afterFind` trong `userinfo.js` đọc được config lúc chạy. Không cần sửa `access_token.js`. (Task 13)
2. **`createTokenFinder` dùng chung bởi `introspection.js` *và* `revocation.js`.** Nhét `strictTokenTypeHint` thẳng vào `token_find.js` sẽ đổi luôn hành vi revocation — vượt phạm vi patch v7 (chỉ sửa introspection). Cách làm: thêm tham số thứ ba `{ strict }`, chỉ introspection truyền vào. (Task 14)
3. **Đoạn `if (ctx.oidc.entities.Session) return ctx.oidc.entities.Session;` trong `Session.get` là code chết.** Nó tồn tại chỉ để phục vụ hai endpoint device flow đã bị bỏ (spec mục 4.2): `accessTokenAuth` set entity `Session` trước, rồi `sessionMiddleware` chạy và sẽ ghi đè. Không port. (Task 12)
4. **`refreshToken.amr` có thể là array.** `RefreshToken` dùng mixin `storesAuth` nên có `amr`, nhưng patch v7 viết `switch (refreshToken.amr)` so sánh với string `'fast_login'` / `'pwd'`. Theo OIDC Core, `amr` là **array**. Nếu app truyền array thì mọi case rơi vào `default` và cho ra `` `login${array}` `` (ví dụ `['pwd']` → `'loginpwd'`, `['pwd','otp']` → `'loginpwd,otp'`). Task 2 ghi lại hành vi thật; Task 11 port nguyên văn, không "sửa" nó.

---

# Phần I — Test đặc tả trên nhánh v7 (Task 1-6)

Mục đích: chốt hành vi đang chạy production **trước khi** đụng vào việc port. Sáu task này commit lên `vlive/oidc-provider`, không lên nhánh v9.

Trước Task 1, chạy một lần:

```bash
git switch vlive/oidc-provider
npm install
npm test
```

## Baseline v7 đã biết (đo ngày 2026-09-03, Node 22.23.0)

**2411 passing / 26 failing.** Baseline v7 xanh là **bất khả đạt** — 22 trong 26 lỗi
do chính fork gây ra và độc lập với phiên bản Node. Cửa chặn "phải xanh mới đi tiếp"
ban đầu dựa trên tiền đề sai, nay thay bằng: **số lỗi cũ không tăng, và test đặc tả
mới phải xanh.**

Cả 26 lỗi đã truy nguyên, và không lỗi nào chạm 7 patch cần viết test đặc tả:

| Nhóm | Số | Nguyên nhân | Trên nhánh v9 |
|---|---|---|---|
| A | 18 | Fork đăng ký **ba route trùng tên** `code_verification` (`initialize_app.js:201-203`). `routeMap.set(name, route)` khiến ghi-sau-thắng, nên `urlFor('code_verification')` trả `/device/code-verification` thay vì `/device`. Sai cả `verification_uri`, action form nhập user-code, và form re-render ở `shared/error_handler.js:44`. | **Tự hết** — patch này đã bỏ (spec §4.2), không port |
| B | 4 | Hành vi fork cố ý đổi, test upstream chưa cập nhật: 3 lỗi introspection `[wrong hint]` (bỏ cross-lookup) + 1 lỗi userinfo (message có `api_profile_get`) | **Xanh** — hai hook mặc định bằng hành vi upstream (Task 13, 14) |
| C | 4 | `lib/helpers/jwt.js` dùng `assert.strict`, mà Node 22 chắp diff vào message tùy chỉnh (`"invalid nbf value\n\n'string' !== 'number'\n"`); test khẳng định message khớp tuyệt đối. Không phải defect. | Không liên quan (`test/jwt/`) |

Nhóm A là **bug production đã ship trong 7.16.6**: thiết bị nhận `verification_uri`
trỏ tới endpoint POST-only đòi Bearer token thay vì trang nhập code. Quyết định của
chủ fork: **không hotfix v7**, để nhánh v9 tự khử theo cấu trúc. Ghi lại ở đây để
không ai tái lập patch đó.

## Cách chạy một file test

Hai công thức chạy-một-file trong plan này và trong `CLAUDE.md` đều **sai**:
`test/test_helper.js:59` phụ thuộc cứng `global.server` và `global.keystore` do
`test/run.js` dựng, còn `run.js` hardcode glob `test/**/*.test.js` và **không** đọc
`MOCHA_FILE`. Nên `npx mocha <file>` throw ngay, và không có `.mocharc` để bù.

Chạy một file bằng runner dựng lại đúng hai global đó:

```bash
node <scratchpad>/run-one.js test/fork_params/fork_params.test.js
```

Runner đặt ngoài repo để không làm bẩn project. Nếu không có nó, dùng `npm test`
rồi lọc theo tên suite.

---

### Task 1: Test đặc tả — `partner` / `ui_mode` trong authorization response

**Files:**
- Create: `test/fork_params/fork_params.config.js`
- Create: `test/fork_params/fork_params.test.js`

**Interfaces:**
- Consumes: `test/test_helper.js` (`bootstrap`, `this.login`, `this.AuthorizationRequest`, `this.wrap`), `test/default.config.js`
- Produces: bộ 4 test, dịch sang ESM ở Task 10. Tên suite `fork: partner and ui_mode in the authorization response` giữ nguyên qua hai nhánh để đối chiếu.

- [x] **Step 1: Viết config cho suite**

Tạo `test/fork_params/fork_params.config.js`:

```js
const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

// partner và ui_mode chỉ vào được ctx.oidc.params khi đăng ký qua extraParams
config.extraParams = ['partner', 'ui_mode'];

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

- [x] **Step 2: Viết test**

Tạo `test/fork_params/fork_params.test.js`:

```js
const { parse: parseUrl } = require('url');

const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('fork: partner and ui_mode in the authorization response', () => {
  before(bootstrap(__dirname));
  before(function () { return this.login(); });

  function fragmentQuery(response) {
    const { hash } = parseUrl(response.headers.location);
    expect(hash).to.exist;
    return parseUrl(response.headers.location.replace('#', '?'), true).query;
  }

  it('echoes both params back when both are sent', function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'id_token',
      scope: 'openid',
      partner: 'vtvlive',
      ui_mode: 'popup',
    });

    return this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect((response) => {
        const query = fragmentQuery(response);
        expect(query).to.have.property('partner', 'vtvlive');
        expect(query).to.have.property('ui_mode', 'popup');
      });
  });

  it('echoes only the param that was sent', function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'id_token',
      scope: 'openid',
      partner: 'vtvlive',
    });

    return this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect((response) => {
        const query = fragmentQuery(response);
        expect(query).to.have.property('partner', 'vtvlive');
        expect(query).not.to.have.property('ui_mode');
      });
  });

  it('omits both when neither is sent', function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'id_token',
      scope: 'openid',
    });

    return this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect((response) => {
        const query = fragmentQuery(response);
        expect(query).not.to.have.property('partner');
        expect(query).not.to.have.property('ui_mode');
      });
  });

  it('echoes an empty string value', function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'id_token',
      scope: 'openid',
      partner: '',
    });

    return this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect((response) => {
        const query = fragmentQuery(response);
        expect(query).to.have.property('partner', '');
      });
  });
});
```

- [x] **Step 3: Chạy test, xác nhận nó PASS**

```bash
npx mocha --timeout 3000 test/fork_params/fork_params.test.js
```

Đây là characterization test, không phải TDD: code đã tồn tại nên test **phải pass ngay**. Nếu đỏ thì hoặc test sai, hoặc hiểu sai hành vi patch — sửa cho tới khi xanh và ghi lại hành vi thật, kể cả khi nó khác kỳ vọng.

Test thứ tư chốt một chi tiết dễ trượt khi port. **Dự đoán ban đầu ở đây sai** và đã
sửa theo hành vi đo được: chuỗi rỗng **không** được echo. `respond.js` gác bằng
`!== undefined`, nhưng `lib/helpers/params.js` chạy `params[prop] || undefined` từ
trước, nên mọi giá trị falsy — với query string thì chỉ có chuỗi rỗng — đã thành
`undefined` trước khi `respond.js` nhìn thấy; nhánh `!== undefined` không bao giờ gặp
chuỗi rỗng.

Đã kiểm: v9 giữ y hệt dòng `params[prop] || undefined`, nên khẳng định này mang sang
Task 10 không đổi. Người port **không** được "sửa" guard đó thành thứ cho chuỗi rỗng
đi qua.

- [x] **Step 4: Chạy cả suite**

```bash
npm test
```

Expected: số `passing` tăng đúng 4, và `failing` vẫn đúng **26** — không phải 0.
Xem "Baseline v7 đã biết" ở đầu Phần I. Nếu `failing` > 26 thì test mới đã làm vỡ
suite khác; dừng lại.

- [x] **Step 5: Commit**

```bash
git add test/fork_params/
git commit -m "test: đặc tả hành vi echo partner/ui_mode của fork"
```

---

### Task 2: Test đặc tả — `trackingAction` và event `refresh_token`

**Files:**
- Create: `test/fork_tracking/fork_tracking.config.js`
- Create: `test/fork_tracking/fork_tracking.test.js`

**Interfaces:**
- Consumes: `test/test_helper.js`, `this.provider.Grant`, `this.provider.RefreshToken`, `this.provider.Client`
- Produces: `mintRefreshToken(ctx, amr) -> Promise<string>` và `exchange(agent, refresh_token) -> supertest.Test`, hai helper cục bộ được Task 11 dùng lại nguyên văn.

- [x] **Step 1: Viết config**

Tạo `test/fork_tracking/fork_tracking.config.js`:

```js
const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, { userinfo: { enabled: true } });

config.scopes = ['openid', 'offline_access'];

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

- [x] **Step 2: Viết test**

Tạo `test/fork_tracking/fork_tracking.test.js`:

```js
const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('fork: trackingAction and the refresh_token event', () => {
  before(bootstrap(__dirname));

  // Dựng refresh token đi thẳng qua adapter thay vì chạy trọn luồng
  // authorization — ngắn hơn và tách biệt hơn.
  async function mintRefreshToken(ctx, amr) {
    const client = await ctx.provider.Client.find('client');

    const grant = new ctx.provider.Grant({ accountId: 'accountId', clientId: 'client' });
    grant.addOIDCScope('openid offline_access');
    const grantId = await grant.save();

    const rt = new ctx.provider.RefreshToken({
      accountId: 'accountId',
      acr: 'urn:mace:incommon:iap:silver',
      amr,
      authTime: Math.floor(Date.now() / 1000),
      claims: {},
      client,
      grantId,
      gty: 'authorization_code',
      scope: 'openid offline_access',
      sessionUid: 'sessionUid',
    });

    return rt.save();
  }

  function exchange(agent, refreshToken) {
    return agent.post('/token')
      .auth('client', 'secret')
      .send({ grant_type: 'refresh_token', refresh_token: refreshToken })
      .type('form');
  }

  // Bắt ctx qua event thay vì assertOnce: event là thứ đang cần kiểm,
  // và cách này không phụ thuộc chữ ký của assertOnce.
  async function capture(ctx, amr) {
    const refreshToken = await mintRefreshToken(ctx, amr);

    const seen = [];
    const listener = (c) => { seen.push(c); };
    ctx.provider.on('refresh_token', listener);

    try {
      await exchange(ctx.agent, refreshToken).expect(200);
    } finally {
      ctx.provider.removeListener('refresh_token', listener);
    }

    return seen;
  }

  it('sets ctx.trackingAction to "login" for amr "pwd" (string)', async function () {
    const seen = await capture(this, 'pwd');
    expect(seen).to.have.lengthOf(1);
    expect(seen[0].trackingAction).to.equal('login');
  });

  it('sets ctx.trackingAction to "loginfast" for amr "fast_login" (string)', async function () {
    const seen = await capture(this, 'fast_login');
    expect(seen[0].trackingAction).to.equal('loginfast');
  });

  it('falls through to `login${amr}` for any other string amr', async function () {
    const seen = await capture(this, 'otp');
    expect(seen[0].trackingAction).to.equal('loginotp');
  });

  // Hành vi được GHI LẠI, không phải hành vi mong muốn. OIDC Core định nghĩa
  // amr là array; switch so với string nên array luôn rơi vào default và bị
  // nội suy qua Array.prototype.toString.
  it('records the array-amr quirk: switch never matches, default interpolates', async function () {
    const seen = await capture(this, ['pwd']);
    expect(seen[0].trackingAction).to.equal('loginpwd');
  });

  it('records the multi-value array-amr quirk', async function () {
    const seen = await capture(this, ['pwd', 'otp']);
    expect(seen[0].trackingAction).to.equal('loginpwd,otp');
  });

  it('emits the event exactly once, and passes the koa ctx', async function () {
    const seen = await capture(this, 'pwd');
    expect(seen).to.have.lengthOf(1);
    expect(seen[0]).to.have.property('oidc');
    expect(seen[0].oidc).to.have.property('provider');
  });
});
```

- [x] **Step 3: Chạy test và ghi lại hành vi thật**

```bash
npx mocha --timeout 3000 test/fork_tracking/fork_tracking.test.js
```

Hai điểm dễ lệch — nếu đỏ thì **sửa test theo output thật**, không sửa lib:

1. `mintRefreshToken` có thể thiếu field bắt buộc. Đọc lỗi và bổ sung theo `lib/models/refresh_token.js` + `lib/models/mixins/stores_auth.js`.
2. Nếu `amr: ['pwd']` cho giá trị khác `'loginpwd'`, ghi đúng giá trị thật vào assertion. Đó là hợp đồng cần bảo toàn.

- [x] **Step 4: Chạy cả suite**

```bash
npm test
```

- [x] **Step 5: Commit**

```bash
git add test/fork_tracking/
git commit -m "test: đặc tả trackingAction và event refresh_token, gồm cả quirk amr array"
```

---

### Task 3: Test đặc tả — Session `loginFrom` và `deviceId`

**Files:**
- Create: `test/fork_session/fork_session.config.js`
- Create: `test/fork_session/fork_session.test.js`
- Create: `test/fork_session/fork_session_device.config.js`
- Create: `test/fork_session/fork_session_device.test.js`

**Interfaces:**
- Consumes: `test/test_helper.js`, `this.provider.Session`
- Produces: khẳng định `loginFrom` mặc định `'web'`, `loginFrom` truyền vào được, `deviceId` lấy từ `ctx.req.deviceId`, cả hai persist qua adapter. Dịch sang ESM ở Task 12.

Hai file test vì test nhánh `ctx.req.deviceId` cần một middleware, và middleware thêm vào provider **không xoá được** — nó phải có provider riêng.

- [x] **Step 1: Viết hai config**

Tạo `test/fork_session/fork_session.config.js`:

```js
const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

Tạo `test/fork_session/fork_session_device.config.js` với **nội dung y hệt** (cần file riêng để có provider riêng, không phải vì config khác).

- [x] **Step 2: Viết test chính**

Tạo `test/fork_session/fork_session.test.js`:

```js
const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('fork: session loginFrom and deviceId', () => {
  before(bootstrap(__dirname));

  describe('loginAccount', () => {
    it('defaults loginFrom to "web" when not given', function () {
      const session = new this.provider.Session({});
      session.loginAccount({ accountId: 'accountId', amr: 'pwd' });
      expect(session.loginFrom).to.equal('web');
    });

    it('keeps the loginFrom that was passed in', function () {
      const session = new this.provider.Session({});
      session.loginAccount({ accountId: 'accountId', amr: 'pwd', loginFrom: 'sdk' });
      expect(session.loginFrom).to.equal('sdk');
    });

    it('does not treat an empty string as absent', function () {
      const session = new this.provider.Session({});
      session.loginAccount({ accountId: 'accountId', loginFrom: '' });
      expect(session.loginFrom).to.equal('');
    });
  });

  describe('IN_PAYLOAD', () => {
    it('includes loginFrom and deviceId', function () {
      expect(this.provider.Session.IN_PAYLOAD).to.include('loginFrom');
      expect(this.provider.Session.IN_PAYLOAD).to.include('deviceId');
    });

    it('round-trips both through the adapter', async function () {
      const session = new this.provider.Session({});
      session.loginAccount({ accountId: 'accountId', loginFrom: 'sdk' });
      session.deviceId = 'device-1';
      const id = await session.save(60);

      const loaded = await this.provider.Session.find(id);
      expect(loaded.loginFrom).to.equal('sdk');
      expect(loaded.deviceId).to.equal('device-1');
    });
  });
});
```

- [x] **Step 3: Viết test nhánh `ctx.req.deviceId`**

Tạo `test/fork_session/fork_session_device.test.js`:

```js
const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('fork: session picks up ctx.req.deviceId', () => {
  // Tham số thứ hai của bootstrap là object { config }, KHÔNG phải string.
  before(bootstrap(__dirname, { config: 'fork_session_device' }));

  before(function () {
    // Phải là provider.use(), KHÔNG phải provider.app.use() — xem Step 4.
    this.provider.use(async (ctx, next) => {
      ctx.req.deviceId = 'device-2';
      await next();
    });
  });

  // Cần login trước: không có session thì /auth đòi interaction và
  // authorization.accepted không bao giờ emit.
  before(function () { return this.login(); });

  it('copies it onto the session', async function () {
    let seen = 'not-set';
    this.provider.once('authorization.accepted', (ctx) => {
      seen = ctx.oidc.session.deviceId;
    });

    await this.agent.get('/auth')
      .query({
        client_id: 'client',
        response_type: 'code',
        scope: 'openid',
        redirect_uri: 'https://client.example.com/cb',
      });

    expect(seen).to.equal('device-2');
  });

  it('persists it with the session', async function () {
    const session = new this.provider.Session({});
    session.loginAccount({ accountId: 'accountId' });
    session.deviceId = 'device-3';
    const id = await session.save(60);

    const loaded = await this.provider.Session.find(id);
    expect(loaded.deviceId).to.equal('device-3');
  });
});
```

- [x] **Step 4: Kiểm ba giả định về API của test helper và provider**

Chạy trước khi debug test:

```bash
grep -n "module.exports = function bootstrap\|module.exports = (" -A 12 test/test_helper.js | head -25
grep -n "^  use(" lib/provider.js
grep -n "authorization.accepted" -r lib/actions/ | head -3
```

Ba điều cần biết. **Đã kiểm ngày 2026-09-03, cả ba đều có bẫy — kết luận:**

1. **`bootstrap(dir, opts)` nhận tham số thứ hai, nhưng là OBJECT `{ config, protocol, mountVia, mountTo }`, không phải string** (`test/test_helper.js:63-68`). `config` mặc định `path.basename(dir)`. Truyền string như `bootstrap(__dirname, 'fork_session_device')` **không báo lỗi** — destructuring một string cho ra `config === undefined` nên rơi về default `'fork_session'`, tức **lặng lẽ nạp sai config**. Dạng đúng: `bootstrap(__dirname, { config: 'fork_session_device' })`. Nhờ vậy hai config **ở cùng một thư mục** được, không cần tách `test/fork_session_device/`. Áp dụng cho cả Task 8-14.
2. **`provider.use` CÓ tồn tại trên v7** (`lib/provider.js:347`) và nó splice middleware vào **trước** middleware nội bộ (mốc `firstInternal` ở `initialize_app.js:242`) — cùng ngữ nghĩa với v9. **Phải dùng `provider.use()`**; `provider.app.use()` append vào cuối stack nên chạy *sau* session middleware, đặt `ctx.req.deviceId` quá muộn và patch không thấy gì. Đã kiểm bằng thực nghiệm: đổi sang `app.use()` thì test `copies it onto the session` đỏ, đổi lại thì xanh.
3. **`authorization.accepted` emit ở `lib/actions/authorization/interactions.js:74` với `ctx`, nhưng chỉ khi request KHÔNG cần interaction.** Nên phải `this.login()` trước, không thì `/auth` chuyển hướng sang interaction và event không bao giờ emit. Không cần `assertOnce`.

- [x] **Step 5: Chạy cả hai file**

```bash
npx mocha --timeout 3000 test/fork_session/fork_session.test.js test/fork_session/fork_session_device.test.js
```

Expected: PASS, 7 test.

- [x] **Step 6: Chạy cả suite**

```bash
npm test
```

- [x] **Step 7: Commit**

```bash
git add test/fork_session/
git commit -m "test: đặc tả session loginFrom và deviceId của fork"
```

---

### Task 4: Test đặc tả — `grantTypeParamsDefault` và cookie prefix

**Files:**
- Create: `test/fork_provider/fork_provider.config.js`
- Create: `test/fork_provider/fork_provider.test.js`

**Interfaces:**
- Consumes: `this.provider.registerGrantType`, `this.provider.cookieName`
- Produces: khẳng định (a) param trong `grantTypeParamsDefault` được nhận ở mọi grant type đăng ký sau đó, (b) `cookies.prefix` đổi tên mọi cookie. Dịch sang ESM ở Task 8 và 9.

Hai patch dùng chung một suite vì cả hai đều là mở rộng `lib/provider.js` và đều kiểm bằng cách dựng Provider trực tiếp.

- [x] **Step 1: Viết config**

Tạo `test/fork_provider/fork_provider.config.js`:

```js
const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

config.grantTypeParamsDefault = ['partner', 'device_id'];
config.cookies = { ...config.cookies, prefix: 'vlive' };

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'urn:fork:test-grant', 'urn:fork:bare-grant'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

Hai grant type ngoài chuẩn khai sẵn trong `client.grant_types` để qua được `check_client_grant_type`.

- [x] **Step 2: Viết test**

Tạo `test/fork_provider/fork_provider.test.js`:

```js
const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('fork: grantTypeParamsDefault', () => {
  before(bootstrap(__dirname));

  it('injects the default params into a newly registered grant type', function () {
    const seen = [];
    this.provider.registerGrantType(
      'urn:fork:test-grant',
      async (ctx) => { seen.push({ ...ctx.oidc.params }); ctx.body = { ok: true }; },
      ['own_param'],
    );

    return this.agent.post('/token')
      .auth('client', 'secret')
      .send({
        grant_type: 'urn:fork:test-grant',
        own_param: 'a',
        partner: 'vtvlive',
        device_id: 'd1',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        expect(seen).to.have.lengthOf(1);
        expect(seen[0]).to.include({ own_param: 'a', partner: 'vtvlive', device_id: 'd1' });
      });
  });

  it('injects them even when the grant type declares no params of its own', function () {
    const seen = [];
    this.provider.registerGrantType(
      'urn:fork:bare-grant',
      async (ctx) => { seen.push({ ...ctx.oidc.params }); ctx.body = { ok: true }; },
    );

    return this.agent.post('/token')
      .auth('client', 'secret')
      .send({ grant_type: 'urn:fork:bare-grant', partner: 'vtvlive' })
      .type('form')
      .expect(200)
      .expect(() => {
        expect(seen[0]).to.include({ partner: 'vtvlive' });
      });
  });
});

describe('fork: cookies.prefix', () => {
  before(bootstrap(__dirname));

  it('prefixes every configured cookie name with "<prefix>."', function () {
    expect(this.provider.cookieName('session')).to.equal('vlive._session');
    expect(this.provider.cookieName('interaction')).to.equal('vlive._interaction');
    expect(this.provider.cookieName('resume')).to.equal('vlive._interaction_resume');
  });

  it('shows the prefixed name in the actual Set-Cookie header', function () {
    return this.agent.get('/auth')
      .query({
        client_id: 'client',
        response_type: 'code',
        scope: 'openid',
        redirect_uri: 'https://client.example.com/cb',
      })
      .expect((response) => {
        const cookies = [].concat(response.headers['set-cookie'] || []).join('\n');
        expect(cookies).to.match(/vlive\._interaction=/);
      });
  });

  it('still throws for an unknown cookie type', function () {
    expect(() => this.provider.cookieName('nope')).to.throw();
  });
});
```

- [x] **Step 3: Chạy và điều chỉnh**

```bash
npx mocha --timeout 3000 test/fork_provider/fork_provider.test.js
```

Hai điểm dễ lệch. **Đã gặp cả hai khi chạy thật, kết luận:**

1. **Phải đăng ký CẢ HAI grant type trong `before()`, không phải trong từng `it()`.** Lý do không phải `unsupported_grant_type` như đoán ban đầu, mà là `400 invalid_client_metadata`: `client_schema` validate `client.grant_types` theo tập grant **đã đăng ký**, và client ở config khai cả hai. Đăng ký lẻ tẻ trong `it()` thì request đầu tiên gãy vì grant type thứ hai còn chưa biết — biểu hiện rất dễ đọc sai, vì test thứ hai lại xanh (lúc đó cả hai đã đăng ký).
2. **Suite `cookies.prefix` cần config RIÊNG** (`fork_provider_cookies.config.js`, cùng thư mục, nạp qua `bootstrap(__dirname, { config: 'fork_provider_cookies' })`). Nó bootstrap một provider riêng nơi không grant type ngoài chuẩn nào được đăng ký, nên nếu dùng chung config thì client invalid và `/auth` lỗi trước khi kịp set cookie — test Set-Cookie sẽ thấy header rỗng. Giữ test Set-Cookie: nó là test đáng giá nhất của nhóm, vì chỉ nó chứng minh prefix ra tới wire chứ không chỉ đúng ở `cookieName()`.
3. `cookieName('nope')` trên v7 dùng `assert` (ném `AssertionError`), trên v9 ném `Error`. `.to.throw()` không tham số nên đúng cho cả hai — giữ vậy, đừng siết.

- [x] **Step 4: Chạy cả suite**

```bash
npm test
```

- [x] **Step 5: Commit**

```bash
git add test/fork_provider/
git commit -m "test: đặc tả grantTypeParamsDefault và cookies.prefix"
```

---

### Task 5: Test đặc tả — userinfo nhận scope `api_profile_get`

**Files:**
- Create: `test/fork_userinfo/fork_userinfo.config.js`
- Create: `test/fork_userinfo/fork_userinfo.test.js`

**Interfaces:**
- Consumes: `this.provider.AccessToken`, `this.provider.Grant`, `this.provider.Client`
- Produces: `mintAccessToken(ctx, scope) -> Promise<string>` (Task 13 dùng lại nguyên văn) và bảng 6 trường hợp. Task 13 phải reproduce đúng bảng này qua config `userinfoRequiredScopes`.

- [x] **Step 1: Viết config**

Tạo `test/fork_userinfo/fork_userinfo.config.js`:

```js
const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, { userinfo: { enabled: true } });

config.scopes = ['openid', 'api_profile_get', 'other_scope'];
config.findAccount = (ctx, id) => ({
  accountId: id,
  claims() { return { sub: id }; },
});

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

- [x] **Step 2: Viết test**

Tạo `test/fork_userinfo/fork_userinfo.test.js`:

```js
const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('fork: userinfo accepts api_profile_get as well as openid', () => {
  before(bootstrap(__dirname));

  async function mintAccessToken(ctx, scope) {
    const client = await ctx.provider.Client.find('client');

    const grant = new ctx.provider.Grant({ accountId: 'accountId', clientId: 'client' });
    if (scope) grant.addOIDCScope(scope);
    const grantId = await grant.save();

    const at = new ctx.provider.AccessToken({
      accountId: 'accountId',
      client,
      grantId,
      gty: 'authorization_code',
      scope,
      sessionUid: 'sessionUid',
    });

    return at.save();
  }

  it('accepts a token scoped openid only', async function () {
    const token = await mintAccessToken(this, 'openid');
    await this.agent.get('/me')
      .auth(token, { type: 'bearer' })
      .expect(200)
      .expect((response) => { expect(response.body).to.have.property('sub', 'accountId'); });
  });

  it('accepts a token scoped api_profile_get only', async function () {
    const token = await mintAccessToken(this, 'api_profile_get');
    await this.agent.get('/me')
      .auth(token, { type: 'bearer' })
      .expect(200)
      .expect((response) => { expect(response.body).to.have.property('sub', 'accountId'); });
  });

  it('accepts a token scoped with both', async function () {
    const token = await mintAccessToken(this, 'openid api_profile_get');
    await this.agent.get('/me').auth(token, { type: 'bearer' }).expect(200);
  });

  it('rejects a token with neither', async function () {
    const token = await mintAccessToken(this, 'other_scope');
    await this.agent.get('/me')
      .auth(token, { type: 'bearer' })
      .expect(403)
      .expect((response) => {
        expect(response.body).to.have.property('error', 'insufficient_scope');
      });
  });

  it('rejects a token with an empty scope', async function () {
    const token = await mintAccessToken(this, undefined);
    await this.agent.get('/me')
      .auth(token, { type: 'bearer' })
      .expect(403)
      .expect((response) => {
        expect(response.body).to.have.property('error', 'insufficient_scope');
      });
  });

  it('records the exact error message and scope hint', async function () {
    const token = await mintAccessToken(this, 'other_scope');
    await this.agent.get('/me')
      .auth(token, { type: 'bearer' })
      .expect(403)
      .expect((response) => {
        expect(response.body.error_description)
          .to.equal('access token missing openid or api_profile_get scope');
        expect(response.headers['www-authenticate']).to.match(/scope="openid"/);
      });
  });
});
```

- [x] **Step 3: Chạy và điều chỉnh**

```bash
npx mocha --timeout 3000 test/fork_userinfo/fork_userinfo.test.js
```

Test cuối chốt **chuỗi lỗi và scope hint chính xác** — đây là hợp đồng Task 13 phải reproduce từ config. Nếu chuỗi thật khác, ghi đúng chuỗi thật.

**Phát hiện khi chạy thật (2026-09-03) — điều đáng chú ý nhất của patch này:**
token chỉ có `api_profile_get` **đi qua được cửa scope (200) nhưng body rỗng `{}`**,
kể cả `sub` cũng không có. Kế hoạch ban đầu đoán sai là sẽ trả `sub`.

Lý do: patch chỉ nới điều kiện ở `lib/actions/userinfo.js:27`. Xuống tới hàm
`respond`, `mask.scope(scope)` (dòng 204) lọc claims theo OIDC scope, mà `scope` ở
đây là `grant.getOIDCScopeFiltered(...)` trên `'api_profile_get'` — scope không mang
claim OIDC nào — nên cho ra chuỗi rỗng và `Claims.result()` trả `{}`. `sub` chỉ đi
kèm scope `openid`.

Nghĩa là **patch mở cửa nhưng không làm `/me` trả profile**, trái với tên scope gợi
ý. Task 13 phải reproduce đúng điều này qua `userinfoRequiredScopes`, **không** được
"sửa" thành trả `sub`. Nếu hành vi mong muốn là trả profile thì đó là một thay đổi
riêng, nằm ngoài phạm vi migration — phải hỏi chủ fork trước.

- [x] **Step 4: Chạy cả suite**

```bash
npm test
```

- [x] **Step 5: Commit**

```bash
git add test/fork_userinfo/
git commit -m "test: đặc tả userinfo chấp nhận scope api_profile_get"
```

---

### Task 6: Test đặc tả — introspection không cross-lookup theo `token_type_hint`

**Files:**
- Create: `test/fork_introspection/fork_introspection.config.js`
- Create: `test/fork_introspection/fork_introspection.test.js`

**Interfaces:**
- Consumes: `this.provider.AccessToken` / `RefreshToken` / `ClientCredentials` / `Grant` / `Client`
- Produces: `mint(ctx, kind) -> Promise<string>` với `kind` là `'AccessToken' | 'RefreshToken' | 'ClientCredentials'`, và ma trận `cases` dạng `[kind, hint, expectedActive]`. Task 14 dùng lại cả hai, với hai ô đã biết sẽ khác.

- [x] **Step 1: Viết config**

Tạo `test/fork_introspection/fork_introspection.config.js`:

```js
const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, {
  introspection: { enabled: true },
  clientCredentials: { enabled: true },
});

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

- [x] **Step 2: Viết test**

Tạo `test/fork_introspection/fork_introspection.test.js`:

```js
const { expect } = require('chai');

const bootstrap = require('../test_helper');

const route = '/token/introspection';

describe('fork: introspection does not cross-look-up on token_type_hint', () => {
  before(bootstrap(__dirname));

  async function newGrantId(ctx) {
    const grant = new ctx.provider.Grant({ accountId: 'accountId', clientId: 'client' });
    grant.addOIDCScope('openid');
    return grant.save();
  }

  async function mint(ctx, kind) {
    const client = await ctx.provider.Client.find('client');
    const common = { client, scope: 'openid' };

    if (kind === 'ClientCredentials') {
      return new ctx.provider.ClientCredentials({ ...common }).save();
    }

    const shared = {
      ...common,
      accountId: 'accountId',
      grantId: await newGrantId(ctx),
      gty: 'authorization_code',
      sessionUid: 'sessionUid',
    };

    if (kind === 'AccessToken') return new ctx.provider.AccessToken(shared).save();
    return new ctx.provider.RefreshToken(shared).save();
  }

  function introspect(agent, token, hint) {
    return agent.post(route)
      .auth('client', 'secret')
      .send(hint === undefined ? { token } : { token, token_type_hint: hint })
      .type('form')
      .expect(200);
  }

  const cases = [
    // [loại token, hint, mong đợi active]
    ['AccessToken', undefined, true],
    ['AccessToken', 'access_token', true],
    ['AccessToken', 'refresh_token', false],
    ['AccessToken', 'client_credentials', false],
    ['AccessToken', 'foobar', true],

    ['RefreshToken', undefined, true],
    ['RefreshToken', 'refresh_token', true],
    ['RefreshToken', 'access_token', false],
    ['RefreshToken', 'foobar', true],

    ['ClientCredentials', undefined, true],
    ['ClientCredentials', 'client_credentials', true],
    ['ClientCredentials', 'access_token', false],
    ['ClientCredentials', 'refresh_token', false],
    ['ClientCredentials', 'foobar', true],
  ];

  for (const [kind, hint, active] of cases) {
    const label = hint === undefined ? 'no hint' : `hint "${hint}"`;
    it(`${kind} with ${label} -> active ${active}`, async function () {
      const token = await mint(this, kind);
      await introspect(this.agent, token, hint)
        .expect((response) => {
          expect(response.body).to.have.property('active', active);
        });
    });
  }
});
```

- [x] **Step 3: Chạy, ghi lại ma trận thật**

```bash
npx mocha --timeout 3000 test/fork_introspection/fork_introspection.test.js
```

Sửa mọi ô lệch theo output thật — mục đích của task này là **chụp ảnh** hành vi, không phải áp đặt.

- [x] **Step 4: Đánh dấu hai ô sẽ đổi ở v9**

Sau khi xanh, chèn ngay dưới `const cases = [...]`:

**Đã kiểm: cả 14 ô khớp đúng dự đoán ở v7. Nhưng số ô sẽ đổi ở v9 là BA, không
phải hai** — kế hoạch bỏ sót `['AccessToken', 'client_credentials']`. Chú thích đã
chèn vào test:

```js
  // Ba ô sẽ ĐỔI khi sang v9 (xem Task 14). Đối chiếu lib/helpers/token_find.js
  // của v9: hint 'access_token' tra [AccessToken, ClientCredentials] rồi fallback
  // RefreshToken; hint 'refresh_token' tra RefreshToken rồi fallback
  // [AccessToken, ClientCredentials]; mọi hint khác rơi vào default tra cả ba.
  // Chế độ strict ở v9 chỉ chặn fallback RA NGOÀI nhóm của hint, không chia nhỏ
  // trong nhóm — nên:
  //
  //   ['ClientCredentials', 'access_token', false]      -> true ở v9
  //       ClientCredentials nằm CÙNG nhóm với AccessToken cho hint
  //       'access_token', vì theo RFC 7662 cả hai đều LÀ access token.
  //
  //   ['AccessToken', 'client_credentials', false]      -> true ở v9
  //       v9 không còn nhận 'client_credentials' là hint hợp lệ, nên rơi vào
  //       nhánh default tra cả ba. (Kế hoạch bỏ sót ô này.)
  //
  //   ['ClientCredentials', 'client_credentials', true] -> vẫn true, nhưng vì
  //       rơi vào nhánh default chứ không phải vì hint được nhận.
  //
  // Mười một ô còn lại phải giữ nguyên giá trị ở v9.
```

Lưu ý cho Task 14: vòng lặp phải là `cases.forEach(...)`, **không** `for...of` —
eslint airbnb chặn `for...of` bằng `no-restricted-syntax`.

- [x] **Step 5: Chạy cả suite**

```bash
npm test
```

- [x] **Step 6: Commit**

```bash
git add test/fork_introspection/
git commit -m "test: đặc tả ma trận introspection token_type_hint của fork"
```

---

# Phần II — Nền v9 (Task 7)

---

### Task 7: Cắt nhánh, sửa `package.json`, chốt baseline xanh

**Files:**
- Modify: `package.json`

**Interfaces:**
- Consumes: `origin/main` (upstream 9.11.5)
- Produces: nhánh `vlive/oidc-provider-v9` với baseline upstream xanh. Mọi task sau đứng trên nhánh này.

- [ ] **Step 1: Đảm bảo Phần I đã được đẩy lên**

```bash
git switch vlive/oidc-provider
git status --porcelain
git push origin vlive/oidc-provider
```

Expected: working tree sạch, 6 commit test đã lên remote. Đây là điều kiện để không mất Phần I.

- [x] **Step 2: Cắt nhánh mới từ upstream**

```bash
git fetch origin
git switch -c vlive/oidc-provider-v9 origin/main
git log --oneline -1
```

Expected: `chore(release): 9.11.5` hoặc mới hơn.

- [x] **Step 3: Chốt baseline upstream TRƯỚC khi sửa gì**

```bash
node --version
npm install
npm test
```

Expected: Node ≥ 22, suite PASS. Nếu đỏ ở đây thì vấn đề thuộc upstream hoặc môi trường, **không** phải việc port — dừng và báo.

Ghi lại tổng số test đang pass. Con số này là mốc so sánh cho mọi task sau.

**Đã đo 2026-09-03 trên Node 22.23.0: `3227 passing, 6 pending, 0 failing`, exit 0.**
Suite v9 upstream xanh sạch — trái ngược với baseline v7 (26 lỗi, xem Phần I). Mọi
task từ Task 8 trở đi phải giữ `failing = 0`; số `passing` chỉ được tăng.

`npm run lint` (biome) kiểm 434 file, sạch.

**Khoảng trống của kế hoạch, đã xử lý ở đây:** nhánh v9 cắt từ `origin/main` nên
**không có** `docs/superpowers/` — cả spec lẫn kế hoạch này chỉ tồn tại trên nhánh
v7. Task 8-18 chạy trên nhánh v9 mà không có tài liệu để đọc và không có checkbox để
tick. Đã mang tài liệu sang bằng `git checkout vlive/oidc-provider -- docs/superpowers/`
và commit riêng, để việc theo dõi đi cùng code. Từ đây tick checkbox trên nhánh v9.

- [x] **Step 4: Sửa `package.json`**

Sửa đúng bốn field, giữ nguyên mọi thứ khác của upstream:

```json
  "name": "@strongnguyen/oidc-provider",
  "version": "9.11.6",
  "homepage": "https://github.com/strongnguyen29/node-oidc-provider",
  "repository": "strongnguyen29/node-oidc-provider",
```

Thêm script publish (đổi `format` cũ của v7 sang `lint` của v9):

```json
    "publish": "npm run lint && npm publish --access public"
```

**Không** mang `overrides` từ v7 sang. Hai override đó (`serialize-javascript ^7.0.5`, `diff ^9.0.0`) vá CVE trong dependency của mocha 11.7.5; v9 dùng mocha ^11.8.0 với cây dependency khác.

- [x] **Step 5: Kiểm `overrides` có còn cần không**

```bash
npm audit
```

Nếu audit báo lỗ hổng ở `serialize-javascript` hoặc `diff`, thêm lại `overrides` tương ứng và ghi lý do vào commit message. Nếu sạch, không thêm.

- [x] **Step 6: Chạy lint và test lần nữa**

```bash
npm run lint
npm test
```

Expected: cả hai PASS, số test bằng Step 3.

- [x] **Step 7: Commit**

```bash
git add package.json package-lock.json
git commit -m "chore: fork upstream 9.11.5 thành @strongnguyen/oidc-provider 9.11.6"
```

---

# Phần III — Port 7 patch (Task 8-14) và xác minh (Task 15)

Mỗi task theo cùng nhịp: thêm config vào `defaults.js` (nếu có) → sửa lib → dịch test từ Phần I → chạy → regenerate docs (nếu có config mới) → commit.

Dịch test CJS → ESM theo năm phép đổi máy móc:

| v7 | v9 |
|---|---|
| `const { expect } = require('chai');` | `import { expect } from 'chai';` |
| `const bootstrap = require('../test_helper');` | `import bootstrap from '../test_helper.js';` |
| `bootstrap(__dirname)` | `bootstrap(import.meta.url)` |
| `const config = cloneDeep(require('../default.config'));` | `import getConfig from '../default.config.js';` + `const config = getConfig();` |
| `module.exports = { config, client }` | `export default { config, client }` |

`merge` từ lodash: `import merge from 'lodash/merge.js';` — chú ý đuôi `.js`, ESM bắt buộc.

---

### Task 8: Port — `grantTypeParamsDefault`

**Files:**
- Modify: `lib/helpers/defaults.js` (chèn sau `extraParams: [],`, hiện ở dòng ~1052)
- Modify: `lib/provider.js` (trong `registerGrantType`, hiện ở dòng ~158-180)
- Create: `test/fork_provider/fork_provider.config.js`
- Create: `test/fork_provider/grant_type_params_default.test.js`
- Modify: `docs/README.md` (sinh tự động)

**Interfaces:**
- Consumes: `this.#int.configuration.grantTypeParamsDefault` (mảng string)
- Produces: config `grantTypeParamsDefault: []`. **Task 9 dùng lại `test/fork_provider/fork_provider.config.js`**, nên file config phải tạo ở task này với cả `grantTypeParamsDefault` và `cookies.prefix`.

- [x] **Step 1: Xác minh chữ ký `bootstrap` trên v9 — chặn mọi task sau**

```bash
grep -n "export default function bootstrap\|export default (" -A 20 test/test_helper.js | head -30
```

Cần biết: `bootstrap` nhận một hay hai tham số, và nếu hai thì tham số thứ hai là tên file config hay gì khác.

**ĐÃ KIỂM (2026-09-03) — kết luận, áp cho Task 9, 12, 13, 14:**

Chữ ký v9 (`test/test_helper.js:126`) là `bootstrap(importMetaUrl, { config, protocol,
mountVia, mountTo })` — tham số thứ hai là **OBJECT**, không phải string, y như trên
v7. Truyền string sẽ **lặng lẽ nạp sai config**, không báo lỗi. Kế hoạch viết
`bootstrap(import.meta.url, 'fork_provider')` ở Step 5 là **sai**, đã sửa.

Thêm nữa, `base ??= path.basename(dir)` nên file test trong `test/<tên>/` **tự nạp**
`<tên>.config.js` mà không cần tham số thứ hai. Config phụ đặt **cùng thư mục** được,
nạp bằng `{ config: '<tên>' }` — v9 tự dùng cách này (`test/configuration/client_secrets.test.js`,
`test/fapi/fapi2.test.js`). Nên **bốn thư mục riêng** mà kế hoạch dựng ra để phòng xa
(`fork_provider_noprefix`, `fork_userinfo_default`, `fork_introspection_lax`,
`fork_session_device`) là **không cần thiết** — dùng config phụ cùng thư mục cho gọn.

**Chạy một file test trên v9 cũng KHÔNG dùng được `npx mocha`** (câu hỏi treo ở Task 16
Step 2, nay đã trả lời): `test/test_helper.js:122` đọc `globalThis.server.address()`, mà
`globalThis.server` do `test/run.js` dựng. v9 khác v7 ở chỗ không còn `global.keystore`
(jose2 đã bỏ) và dùng `mocha.loadFilesAsync()` cho ESM. Cần runner ESM riêng dựng
`globalThis.server`, hoặc dùng `npm test` rồi lọc theo tên suite.

- [x] **Step 2: Thêm config vào `defaults.js`**

Chèn ngay sau `extraParams: [],`:

```js
    /*
     * grantTypeParamsDefault
     *
     * title: Additional Parameters for Every Grant Type
     *
     * description: Specifies additional parameter names that shall be recognized at the token
     *   endpoint for every grant type registered through `Provider.prototype.registerGrantType`.
     *   These parameters are injected in addition to the ones the grant type declares for itself,
     *   and become available in `ctx.oidc.params` inside the grant type handler.
     *
     * Note: This is a fork-specific extension, it is not part of upstream oidc-provider.
     *
     * example: Making `partner` available to every registered grant type.
     *
     * ```js
     * const grantTypeParamsDefault = ['partner'];
     * ```
     */
    grantTypeParamsDefault: [],
```

- [x] **Step 3: Sửa `registerGrantType`**

Trong `lib/provider.js`, chèn ngay **trước** dòng `grantTypeParams.set(name, grantParams);`:

```js
    const defaultParams = this.#int.configuration.grantTypeParamsDefault;
    if (Array.isArray(defaultParams)) {
      defaultParams.forEach(Set.prototype.add.bind(grantParams));
    }
```

- [x] **Step 4: Tạo config dùng chung cho Task 8 và 9**

Tạo `test/fork_provider/fork_provider.config.js`:

```js
import getConfig from '../default.config.js';

const config = getConfig();

config.grantTypeParamsDefault = ['partner', 'device_id'];
config.cookies = { ...config.cookies, prefix: 'vlive' };

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'urn:fork:test-grant', 'urn:fork:bare-grant'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

- [x] **Step 5: Dịch test từ Task 4 (phần grantTypeParamsDefault)**

Tạo `test/fork_provider/grant_type_params_default.test.js`:

```js
import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('fork: grantTypeParamsDefault', () => {
  before(bootstrap(import.meta.url, 'fork_provider'));

  it('injects the default params into a newly registered grant type', function () {
    const seen = [];
    this.provider.registerGrantType(
      'urn:fork:test-grant',
      async (ctx) => { seen.push({ ...ctx.oidc.params }); ctx.body = { ok: true }; },
      ['own_param'],
    );

    return this.agent.post('/token')
      .auth('client', 'secret')
      .send({
        grant_type: 'urn:fork:test-grant',
        own_param: 'a',
        partner: 'vtvlive',
        device_id: 'd1',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        expect(seen).to.have.lengthOf(1);
        expect(seen[0]).to.include({ own_param: 'a', partner: 'vtvlive', device_id: 'd1' });
      });
  });

  it('injects them even when the grant type declares no params of its own', function () {
    const seen = [];
    this.provider.registerGrantType(
      'urn:fork:bare-grant',
      async (ctx) => { seen.push({ ...ctx.oidc.params }); ctx.body = { ok: true }; },
    );

    return this.agent.post('/token')
      .auth('client', 'secret')
      .send({ grant_type: 'urn:fork:bare-grant', partner: 'vtvlive' })
      .type('form')
      .expect(200)
      .expect(() => {
        expect(seen[0]).to.include({ partner: 'vtvlive' });
      });
  });
});
```

Điều chỉnh `bootstrap(...)` theo kết luận Step 1.

- [x] **Step 6: Chạy test**

```bash
npx mocha --timeout 3000 test/fork_provider/grant_type_params_default.test.js
```

Expected: PASS, 2 test, khớp từng khẳng định với Task 4.

- [x] **Step 7: Sinh lại docs và lint**

```bash
node docs/update-configuration.js
npm run lint
git diff --stat docs/README.md
```

Expected: `docs/README.md` có thêm mục `grantTypeParamsDefault`. Nếu diff rỗng, khối JSDoc ở Step 2 sai format — đối chiếu với khối `extraParams` ngay trên nó.

- [x] **Step 8: Chạy cả suite**

```bash
npm test
```

Expected: PASS. Đặc biệt `test/custom_grants/` phải xanh — nó dùng `registerGrantType`.

- [x] **Step 9: Commit**

```bash
git add lib/provider.js lib/helpers/defaults.js docs/README.md test/fork_provider/
git commit -m "feat: thêm config grantTypeParamsDefault"
```

---

### Task 9: Port — `cookies.prefix`

**Files:**
- Modify: `lib/helpers/defaults.js` (trong khối `cookies`, sau khối `names: { ... },`)
- Modify: `lib/provider.js` (`cookieName`, hiện ở dòng ~182-188)
- Create: `test/fork_provider/cookie_prefix.test.js`
- Create: `test/fork_provider_noprefix/fork_provider_noprefix.config.js`
- Create: `test/fork_provider_noprefix/fork_provider_noprefix.test.js`
- Modify: `docs/README.md`

**Interfaces:**
- Consumes: config riêng `test/fork_provider/fork_provider_prefix.config.js` (xem sửa đổi bên dưới)
- Produces: `provider.cookieName(type)` trả `<prefix>.<name>` khi prefix truthy, trả `<name>` khi falsy.

**Hai sửa đổi so với kế hoạch, đã kiểm thực tế:**

1. **KHÔNG dùng chung `fork_provider.config.js` của Task 8.** Config đó khai hai grant type ngoài chuẩn mà suite cookie không đăng ký, nên `client_schema` làm client invalid và `/auth` lỗi trước khi kịp set cookie — test Set-Cookie thấy header rỗng. Đây đúng là lỗi đã gặp và ghi lại ở Task 4 trên nhánh v7, kế hoạch chưa áp ngược vào Task 9. Dùng `fork_provider_prefix.config.js` riêng, client thường.
2. **Không cần thư mục riêng `test/fork_provider_noprefix/`.** Theo kết luận Task 8 Step 1, `bootstrap` v9 nhận `{ config }` nên config phụ đặt **cùng thư mục** `test/fork_provider/` là đủ. Ba config trong một thư mục: `fork_provider` (grant types), `fork_provider_prefix` (có prefix), `fork_provider_noprefix` (không prefix).

- [x] **Step 1: Thêm config vào `defaults.js`**

Trong khối `cookies`, chèn ngay sau khối `names: { ... },`:

```js
      /*
       * cookies.prefix
       *
       * description: Specifies a prefix that shall be prepended to every cookie name configured
       *   in `cookies.names`, separated by a dot. This allows several provider instances to share
       *   a domain without their cookies colliding. When the value is falsy no prefix is applied
       *   and the names in `cookies.names` are used verbatim.
       *
       * Note: This is a fork-specific extension, it is not part of upstream oidc-provider.
       *
       * example: With `prefix: 'vlive'` the session cookie is named `vlive._session`.
       */
      prefix: undefined,
```

- [x] **Step 2: Sửa `cookieName`**

Thay toàn bộ method trong `lib/provider.js`:

```js
  cookieName(type) {
    const name = this.#int.configuration.cookies.names[type];
    if (!name) {
      throw new Error(`cookie name for type ${type} is not configured`);
    }
    const { prefix } = this.#int.configuration.cookies;
    if (!prefix) return name;
    return `${prefix}.${name}`;
  }
```

- [x] **Step 3: Dịch test từ Task 4 (phần cookie prefix)**

Tạo `test/fork_provider/cookie_prefix.test.js`:

```js
import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('fork: cookies.prefix', () => {
  before(bootstrap(import.meta.url, 'fork_provider'));

  it('prefixes every configured cookie name with "<prefix>."', function () {
    expect(this.provider.cookieName('session')).to.equal('vlive._session');
    expect(this.provider.cookieName('interaction')).to.equal('vlive._interaction');
    expect(this.provider.cookieName('resume')).to.equal('vlive._interaction_resume');
  });

  it('shows the prefixed name in the actual Set-Cookie header', function () {
    return this.agent.get('/auth')
      .query({
        client_id: 'client',
        response_type: 'code',
        scope: 'openid',
        redirect_uri: 'https://client.example.com/cb',
      })
      .expect((response) => {
        const cookies = [].concat(response.headers['set-cookie'] || []).join('\n');
        expect(cookies).to.match(/vlive\._interaction=/);
      });
  });

  it('still throws for an unknown cookie type', function () {
    expect(() => this.provider.cookieName('nope')).to.throw();
  });
});
```

- [x] **Step 4: Test nhánh mặc định — không có prefix**

Đây là nhánh mọi deployment upstream đang dùng, phải chắc nó không hồi quy.

Tạo `test/fork_provider_noprefix/fork_provider_noprefix.config.js`:

```js
import getConfig from '../default.config.js';

export default {
  config: getConfig(),
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

Tạo `test/fork_provider_noprefix/fork_provider_noprefix.test.js`:

```js
import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('fork: cookies.prefix left unset', () => {
  before(bootstrap(import.meta.url));

  it('uses the names in cookies.names verbatim', function () {
    expect(this.provider.cookieName('session')).to.equal('_session');
    expect(this.provider.cookieName('interaction')).to.equal('_interaction');
    expect(this.provider.cookieName('resume')).to.equal('_interaction_resume');
  });

  it('sets an unprefixed cookie on the wire', function () {
    return this.agent.get('/auth')
      .query({
        client_id: 'client',
        response_type: 'code',
        scope: 'openid',
        redirect_uri: 'https://client.example.com/cb',
      })
      .expect((response) => {
        const cookies = [].concat(response.headers['set-cookie'] || []).join('\n');
        expect(cookies).to.match(/(^|\n)_interaction=/);
        expect(cookies).not.to.match(/vlive\./);
      });
  });
});
```

- [x] **Step 5: Chạy cả hai file**

```bash
npx mocha --timeout 3000 test/fork_provider/cookie_prefix.test.js test/fork_provider_noprefix/fork_provider_noprefix.test.js
```

Expected: PASS, 5 test.

- [x] **Step 6: Sinh lại docs, lint, chạy cả suite**

```bash
node docs/update-configuration.js
npm run lint
npm test
```

Expected: PASS. Đặc biệt mọi suite chạm cookie (`test/end_session/`, `test/interaction/`, `test/session/` nếu có) phải xanh — chúng chạy với `prefix` mặc định `undefined`.

- [x] **Step 7: Commit**

```bash
git add lib/provider.js lib/helpers/defaults.js docs/README.md test/fork_provider/ test/fork_provider_noprefix/
git commit -m "feat: thêm config cookies.prefix"
```

---

### Task 10: Port — `partner` / `ui_mode` trong authorization response

**Files:**
- Modify: `lib/actions/authorization/respond.js` (sau khối `if (params.state !== undefined)`)
- Create: `test/fork_params/fork_params.config.js`
- Create: `test/fork_params/fork_params.test.js`

**Interfaces:**
- Consumes: `ctx.oidc.params.partner`, `ctx.oidc.params.ui_mode` — chỉ có mặt khi app đăng ký qua `extraParams`
- Produces: hai key `partner` / `ui_mode` trong object `out` của authorization endpoint, đi qua mọi response mode.

- [x] **Step 1: Sửa `respond.js`**

Chèn ngay sau khối `if (params.state !== undefined) { out.state = params.state; }`:

```js
  if (params.ui_mode !== undefined) {
    out.ui_mode = params.ui_mode;
  }

  if (params.partner !== undefined) {
    out.partner = params.partner;
  }
```

Giữ đúng thứ tự `ui_mode` trước `partner` như bản v7 — thứ tự key ảnh hưởng thứ tự tham số trong URL trả về, và có thể có client đang so khớp chuỗi.

- [x] **Step 2: Dịch config và test từ Task 1**

Tạo `test/fork_params/fork_params.config.js`:

```js
import getConfig from '../default.config.js';

const config = getConfig();

// partner và ui_mode chỉ vào được ctx.oidc.params khi đăng ký qua extraParams
config.extraParams = ['partner', 'ui_mode'];

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

Tạo `test/fork_params/fork_params.test.js` — dịch nguyên văn từ Task 1, đổi ba dòng đầu:

```js
import * as url from 'node:url';

import { expect } from 'chai';

import bootstrap from '../test_helper.js';
```

và `before(bootstrap(import.meta.url));`, `url.parse` thay `parseUrl`. Giữ **y nguyên** cả bốn assertion.

- [x] **Step 3: Chạy test**

```bash
npx mocha --timeout 3000 test/fork_params/fork_params.test.js
```

Expected: PASS, 4 test, khớp từng khẳng định với Task 1.

- [x] **Step 4: Kiểm patch đi qua response mode khác**

`out` được truyền vào response mode, nên hai key phải xuất hiện ở `form_post` nữa. Thêm vào cuối file test:

```js
describe('fork: partner and ui_mode via form_post', () => {
  before(bootstrap(import.meta.url));
  before(function () { return this.login(); });

  it('appears as a hidden field in the auto-submitting form', function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'id_token',
      response_mode: 'form_post',
      scope: 'openid',
      partner: 'vtvlive',
      ui_mode: 'popup',
    });

    return this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect(200)
      .expect((response) => {
        expect(response.text).to.match(/name="partner"/);
        expect(response.text).to.match(/value="vtvlive"/);
        expect(response.text).to.match(/name="ui_mode"/);
      });
  });
});
```

Nếu `form_post` cần bật feature nào, thêm vào config và ghi chú. Nếu v9 từ chối tổ hợp này, bỏ test và ghi rõ vì sao — đừng nới config chỉ để test chạy.

- [x] **Step 5: Chạy lint và cả suite**

```bash
npm run lint
npm test
```

- [x] **Step 6: Commit**

```bash
git add lib/actions/authorization/respond.js test/fork_params/
git commit -m "feat: trả partner và ui_mode trong authorization response"
```

---

### Task 11: Port — `trackingAction` và event `refresh_token`

**Files:**
- Modify: `lib/actions/grants/refresh_token.js` (cuối `refreshTokenHandler`, sau `ctx.body = buildTokenResponse(...)`)
- Create: `test/fork_tracking/fork_tracking.config.js`
- Create: `test/fork_tracking/fork_tracking.test.js`

**Interfaces:**
- Consumes: `refreshToken.amr` (từ mixin `storesAuth`)
- Produces: `ctx.trackingAction` (string) và event `refresh_token` với một tham số `ctx`.

**Khác vị trí so với v7:** handler v9 không nhận `next` và không gọi `await next()` (hệ quả của "routes are final"). Patch v7 nằm **trước** `await next()`; ở v9 nó nằm ở cuối thân hàm. Cùng vị trí về ngữ nghĩa.

- [x] **Step 1: Sửa `refresh_token.js`**

Chèn ngay **sau** khối `ctx.body = buildTokenResponse(...)` và trước dấu `};` đóng hàm:

```js
  // fork: cung cấp nhãn hành động cho tầng tracking phía dưới
  switch (refreshToken.amr) {
    case 'fast_login':
      ctx.trackingAction = 'loginfast';
      break;
    case 'pwd':
      ctx.trackingAction = 'login';
      break;
    default:
      ctx.trackingAction = `login${refreshToken.amr}`;
      break;
  }

  ctx.oidc.provider.emit('refresh_token', ctx);
```

**Không sửa quirk array-amr.** `amr` theo OIDC Core là array, `switch` so với string nên array luôn rơi vào `default`. Đó là hành vi production hiện tại; đổi nó là quyết định riêng, không phải việc của bước port. Task 2 đã ghi lại hành vi thật.

- [x] **Step 2: Dịch config từ Task 2**

Tạo `test/fork_tracking/fork_tracking.config.js`:

```js
import getConfig from '../default.config.js';
import merge from 'lodash/merge.js';

const config = getConfig();

merge(config.features, { userinfo: { enabled: true } });
config.scopes = ['openid', 'offline_access'];

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

- [x] **Step 3: Dịch test từ Task 2**

Tạo `test/fork_tracking/fork_tracking.test.js` — dịch nguyên văn file từ Task 2, đổi hai dòng import và `bootstrap(import.meta.url)`. Giữ **y nguyên** cả sáu assertion, kể cả hai test quirk array-amr.

- [x] **Step 4: Chạy test và đối chiếu với Task 2**

```bash
npx mocha --timeout 3000 test/fork_tracking/fork_tracking.test.js
```

Expected: PASS, 6 test, cùng giá trị như Task 2.

Nếu `mintRefreshToken` đỏ vì field bắt buộc đổi giữa v7 và v9, đọc lỗi và bổ sung — đó là thay đổi model của upstream, ghi chú vào commit message.

- [x] **Step 5: Kiểm event không phát hai lần khi refresh token rotate**

Thêm vào cuối file test:

```js
  it('emits exactly once even when the refresh token rotates', async function () {
    const seen = await capture(this, 'pwd');
    expect(seen.map((c) => c.trackingAction)).to.deep.equal(['login']);
  });
```

- [x] **Step 6: Chạy lint và cả suite**

```bash
npm run lint
npm test
```

Expected: PASS. `test/core/basic/` và mọi suite có refresh token phải xanh — event mới không được làm hỏng chúng.

- [x] **Step 7: Commit**

```bash
git add lib/actions/grants/refresh_token.js test/fork_tracking/
git commit -m "feat: đặt ctx.trackingAction và phát event refresh_token"
```

---

### Task 12: Port — Session `loginFrom` và `deviceId`

**Files:**
- Modify: `lib/models/session.js` (`IN_PAYLOAD`, `static async get`, `loginAccount`)
- Create: `test/fork_session/fork_session.config.js`
- Create: `test/fork_session/fork_session.test.js`
- Create: `test/fork_session/fork_session_device.config.js`
- Create: `test/fork_session/fork_session_device.test.js`

**Interfaces:**
- Consumes: `ctx.req.deviceId` — do middleware của app đặt, thư viện không tự suy ra
- Produces: `session.loginFrom` (mặc định `'web'`), `session.deviceId`, cả hai persist qua adapter.

**Không port một phần:** đoạn `if (ctx.oidc.entities.Session) return ctx.oidc.entities.Session;` ở đầu `static async get`. Nó chỉ tồn tại để phục vụ hai endpoint device flow đã bị bỏ (spec mục 4.2), và trên đường đi thường nó biến `Session.get` thành cache trong cùng request — một thay đổi hành vi không ai cần. Xem "Bốn khác biệt so với spec" ở đầu tài liệu.

- [x] **Step 1: Thêm hai field vào `IN_PAYLOAD`**

Thêm `'loginFrom'` ngay sau `'loginTs'` và `'deviceId'` ngay sau `'state'`, giữ đúng vị trí như bản v7:

```js
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'uid',
      'acr',
      'amr',
      'accountId',
      'loginTs',
      'loginFrom',
      'transient',
      'state',
      'deviceId',
      'authorizations',
    ];
  }
```

- [x] **Step 2: Copy `ctx.req.deviceId` trong `static async get`**

Chèn ngay **trước** `return session;`:

```js
    if (ctx.req.deviceId) {
      session.deviceId = ctx.req.deviceId;
    }
```

- [x] **Step 3: Thêm `loginFrom` vào `loginAccount`**

Thay toàn bộ method:

```js
  loginAccount(details) {
    const {
      transient = false, accountId, loginTs = epochTime(), amr, acr, loginFrom = 'web',
    } = details;

    Object.assign(
      this,
      {
        accountId, loginTs, loginFrom, amr, acr,
      },
      transient ? { transient: true } : undefined,
    );
  }
```

- [x] **Step 4: Dịch config và test chính từ Task 3**

Tạo `test/fork_session/fork_session.config.js`:

```js
import getConfig from '../default.config.js';

export default {
  config: getConfig(),
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

Tạo `test/fork_session/fork_session.test.js` — dịch nguyên văn từ Task 3 Step 2, đổi hai dòng import và `bootstrap(import.meta.url)`. Thêm một describe block cho nhánh không có `ctx.req.deviceId`:

```js
  describe('Session.get without ctx.req.deviceId', () => {
    it('leaves deviceId undefined', async function () {
      let seen = 'not-set';
      this.provider.once('authorization.accepted', (ctx) => {
        seen = ctx.oidc.session.deviceId;
      });

      await this.agent.get('/auth')
        .query({
          client_id: 'client',
          response_type: 'code',
          scope: 'openid',
          redirect_uri: 'https://client.example.com/cb',
        });

      expect(seen).to.equal(undefined);
    });
  });
```

- [x] **Step 5: Dịch test nhánh có `ctx.req.deviceId`, dùng `provider.use()`**

Thư mục riêng vì middleware không xoá được.

Tạo `test/fork_session/fork_session_device.config.js` — nội dung y hệt config ở Step 4.

Tạo `test/fork_session/fork_session_device.test.js`:

```js
import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('fork: session picks up ctx.req.deviceId', () => {
  before(bootstrap(import.meta.url));

  before(function () {
    // v9: Provider extends Koa và use() splice middleware vào trước router,
    // nên đây luôn là vị trí upstream của mọi route.
    this.provider.use(async (ctx, next) => {
      ctx.req.deviceId = 'device-2';
      await next();
    });
  });

  it('copies it onto the session', async function () {
    let seen = 'not-set';
    this.provider.once('authorization.accepted', (ctx) => {
      seen = ctx.oidc.session.deviceId;
    });

    await this.agent.get('/auth')
      .query({
        client_id: 'client',
        response_type: 'code',
        scope: 'openid',
        redirect_uri: 'https://client.example.com/cb',
      });

    expect(seen).to.equal('device-2');
  });

  it('persists it with the session', async function () {
    const session = new this.provider.Session({});
    session.loginAccount({ accountId: 'accountId' });
    session.deviceId = 'device-3';
    const id = await session.save(60);

    const loaded = await this.provider.Session.find(id);
    expect(loaded.deviceId).to.equal('device-3');
  });
});
```

- [x] **Step 6: Chạy cả hai file**

```bash
npx mocha --timeout 3000 test/fork_session/fork_session.test.js test/fork_session/fork_session_device.test.js
```

Expected: PASS, 8 test.

- [x] **Step 7: Chạy lint và cả suite**

```bash
npm run lint
npm test
```

Expected: PASS. `test/interaction/`, `test/end_session/`, `test/auth_time/` — mọi suite chạm Session — phải xanh.

- [x] **Step 8: Commit**

```bash
git add lib/models/session.js test/fork_session/
git commit -m "feat: thêm loginFrom và deviceId vào Session

Bỏ đoạn early-return ctx.oidc.entities.Session của bản v7: nó chỉ phục vụ
hai endpoint device flow đã không port sang v9."
```

---

### Task 13: Port — userinfo nhận thêm scope qua `userinfoRequiredScopes`

**Files:**
- Modify: `lib/helpers/defaults.js` (top-level, sau `grantTypeParamsDefault`)
- Modify: `lib/actions/userinfo.js` (thêm import `instance`, sửa closure `afterFind`)
- Create: `test/fork_userinfo/fork_userinfo.config.js`
- Create: `test/fork_userinfo/fork_userinfo.test.js`
- Create: `test/fork_userinfo/fork_userinfo_default.config.js` (config phụ **cùng thư mục**, không cần thư mục riêng — xem kết luận Task 8 Step 1; hai `describe` nằm chung một file test)
- Modify: `docs/README.md`

**Interfaces:**
- Consumes: `instance(ctx.oidc.provider).configuration.userinfoRequiredScopes` (mảng string, không rỗng)
- Produces: config `userinfoRequiredScopes: ['openid']`. Access token pass khi có **bất kỳ** scope trong mảng.

**Khác spec:** hook đặt trong `lib/actions/userinfo.js`, không phải `lib/shared/access_token.js`. `getValidateAccessToken({ afterFind })` gọi `await afterFind?.(ctx, accessToken)` nên closure đọc được config lúc chạy.

- [x] **Step 1: Thêm config vào `defaults.js`**

Chèn ngay sau khối `grantTypeParamsDefault: [],` (thêm ở Task 8):

```js
    /*
     * userinfoRequiredScopes
     *
     * title: Scopes Accepted at the UserInfo Endpoint
     *
     * description: Specifies the scope values of which an access token must carry at least one in
     *   order to be accepted at the userinfo endpoint. The default value of `['openid']` is the
     *   behaviour mandated by OpenID Connect Core 1.0. Additional values may be added to accept
     *   access tokens issued for non-OpenID purposes at the same endpoint.
     *
     * Note: This is a fork-specific extension, it is not part of upstream oidc-provider. Adding
     *   values other than `openid` is a deliberate deviation from OpenID Connect Core 1.0.
     *
     * example: Also accepting an `api_profile_get` scope.
     *
     * ```js
     * const userinfoRequiredScopes = ['openid', 'api_profile_get'];
     * ```
     */
    userinfoRequiredScopes: ['openid'],
```

- [x] **Step 2: Sửa `lib/actions/userinfo.js`**

Thêm import, đặt cùng nhóm import helper (sau `getCtxAccountClaims`):

```js
import instance from '../helpers/weak_cache.js';
```

Thay toàn bộ khối `const validateAccessToken = ...`:

```js
const validateAccessToken = getValidateAccessToken({
  afterFind(ctx, accessToken) {
    const required = instance(ctx.oidc.provider).configuration.userinfoRequiredScopes;
    if (
      !accessToken.scopes.size
      || !required.some(Set.prototype.has.bind(accessToken.scopes))
    ) {
      throw new InsufficientScope(
        `access token missing ${required.join(' or ')} scope`,
        required[0],
      );
    }
  },
});
```

Hai chi tiết bắt buộc:

- Với `required = ['openid']` đoạn này cho ra đúng thông điệp `'access token missing openid scope'` và scope hint `'openid'` như upstream. Đó là điều kiện để suite upstream không đỏ.
- Upstream đặt tên tham số đầu là `_ctx` vì không dùng; giờ có dùng nên phải đổi thành `ctx`, nếu không biome sẽ báo.
- **Chiều ngược lại cũng đúng và dễ quên:** trong file config test, `config.findAccount = (ctx, id) => ...` không dùng `ctx` nên biome báo `noUnusedFunctionParameters`. Đặt là `_ctx`. `npm test` vẫn xanh khi có warning này, nên phải đọc output của `npm run lint`, đừng chỉ nhìn exit code.

- [x] **Step 3: Dịch config và test từ Task 5**

Tạo `test/fork_userinfo/fork_userinfo.config.js`:

```js
import getConfig from '../default.config.js';
import merge from 'lodash/merge.js';

const config = getConfig();

merge(config.features, { userinfo: { enabled: true } });

config.scopes = ['openid', 'api_profile_get', 'other_scope'];
config.userinfoRequiredScopes = ['openid', 'api_profile_get'];
config.findAccount = (ctx, id) => ({
  accountId: id,
  claims() { return { sub: id }; },
});

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

Tạo `test/fork_userinfo/fork_userinfo.test.js` — dịch nguyên văn từ Task 5, đổi hai dòng import và `bootstrap(import.meta.url)`. Giữ nguyên cả sáu assertion, kể cả test chuỗi lỗi chính xác.

- [x] **Step 4: Test nhánh mặc định — bước quan trọng nhất của task**

Config mặc định phải giữ **đúng** hành vi upstream, không chỉ gần đúng.

Tạo `test/fork_userinfo_default/fork_userinfo_default.config.js`:

```js
import getConfig from '../default.config.js';
import merge from 'lodash/merge.js';

const config = getConfig();

merge(config.features, { userinfo: { enabled: true } });

config.scopes = ['openid', 'api_profile_get'];
config.findAccount = (ctx, id) => ({
  accountId: id,
  claims() { return { sub: id }; },
});
// userinfoRequiredScopes để mặc định

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

Tạo `test/fork_userinfo_default/fork_userinfo_default.test.js`:

```js
import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('fork: userinfoRequiredScopes left at its default', () => {
  before(bootstrap(import.meta.url));

  async function mintAccessToken(ctx, scope) {
    const client = await ctx.provider.Client.find('client');

    const grant = new ctx.provider.Grant({ accountId: 'accountId', clientId: 'client' });
    if (scope) grant.addOIDCScope(scope);
    const grantId = await grant.save();

    const at = new ctx.provider.AccessToken({
      accountId: 'accountId',
      client,
      grantId,
      gty: 'authorization_code',
      scope,
      sessionUid: 'sessionUid',
    });

    return at.save();
  }

  it('accepts openid, exactly as upstream does', async function () {
    const token = await mintAccessToken(this, 'openid');
    await this.agent.get('/me').auth(token, { type: 'bearer' }).expect(200);
  });

  it('rejects api_profile_get, exactly as upstream does', async function () {
    const token = await mintAccessToken(this, 'api_profile_get');
    await this.agent.get('/me').auth(token, { type: 'bearer' }).expect(403);
  });

  it('reproduces the upstream error message verbatim', async function () {
    const token = await mintAccessToken(this, 'api_profile_get');
    await this.agent.get('/me')
      .auth(token, { type: 'bearer' })
      .expect(403)
      .expect((response) => {
        expect(response.body.error_description)
          .to.equal('access token missing openid scope');
        expect(response.headers['www-authenticate']).to.match(/scope="openid"/);
      });
  });
});
```

- [x] **Step 5: Chạy cả hai file**

```bash
npx mocha --timeout 3000 test/fork_userinfo/fork_userinfo.test.js test/fork_userinfo_default/fork_userinfo_default.test.js
```

Expected: PASS, 9 test.

- [x] **Step 6: Chạy suite userinfo của upstream — cổng thật của task này**

```bash
npx mocha --timeout 3000 test/userinfo/userinfo.test.js test/userinfo/bearer.test.js
npx mocha --timeout 3000 test/jwt_userinfo/*.test.js
```

Expected: PASS, không đổi so với Task 7. Nếu đỏ, chuỗi lỗi hoặc scope hint đã lệch khỏi upstream — sửa `afterFind` cho khớp, **đừng** sửa test upstream.

- [x] **Step 7: Sinh lại docs, lint, chạy cả suite**

```bash
node docs/update-configuration.js
npm run lint
npm test
```

- [x] **Step 8: Commit**

```bash
git add lib/actions/userinfo.js lib/helpers/defaults.js docs/README.md test/fork_userinfo/ test/fork_userinfo_default/
git commit -m "feat: thêm config userinfoRequiredScopes"
```

---

### Task 14: Port — introspection `strictTokenTypeHint`

**Files:**
- Modify: `lib/helpers/defaults.js` (trong `features.introspection`, sau `enabled: false,`)
- Modify: `lib/helpers/token_find.js` (thêm tham số thứ ba `{ strict }`)
- Modify: `lib/actions/introspection.js` (truyền `strict` vào `createTokenFinder`)
- Create: `test/fork_introspection/fork_introspection.config.js`
- Create: `test/fork_introspection/fork_introspection.test.js`
- Create: `test/fork_introspection/fork_introspection_lax.config.js` (config phụ **cùng thư mục**, hai `describe` chung một file — xem kết luận Task 8 Step 1)
- Modify: `docs/README.md`

**Interfaces:**
- Consumes: `configuration.features.introspection.strictTokenTypeHint` (boolean)
- Produces: `createTokenFinder(provider, grantTypeHandlers, opts?)` với `opts = { strict?: boolean }`, mặc định `{ strict: false }`. Tham số thứ ba là **tuỳ chọn** để `revocation.js` gọi hai tham số như cũ.

**Khác spec — quan trọng:** `createTokenFinder` được dùng bởi **cả** `introspection.js` và `revocation.js`. Nhét cờ strict vào `token_find.js` sẽ đổi luôn hành vi revocation, vượt phạm vi patch v7. Vì thế cờ phải là **tham số**, và chỉ introspection truyền vào.

**Khác biệt hành vi đã biết so với v7** — reviewer phải đồng ý hoặc từ chối ở cổng task này.
**Đã xác nhận bằng thực nghiệm 2026-09-03: đúng BA ô đổi, 11 ô còn lại giữ nguyên.**

| Token | hint | v7 fork | v9 strict | Vì sao |
|---|---|---|---|---|
| ClientCredentials | `access_token` | inactive | **active** | v9 gộp AccessToken + ClientCredentials vào cùng nhóm cho hint `access_token`, vì theo RFC 7662 cả hai đều LÀ access token |
| AccessToken | `client_credentials` | inactive | **active** | `client_credentials` không còn là hint hợp lệ ở v9 nên rơi vào `default`, tra cả ba loại. **Ma trận ở Step 4 của kế hoạch bỏ sót ô này** — đã thêm lại |
| ClientCredentials | `client_credentials` | active | active | Vẫn active nhưng vì rơi vào `default`, không phải vì hint được nhận |

Chế độ strict ở đây định nghĩa là: **không fallback ra ngoài nhóm của hint**. Nó không chia nhỏ bên trong nhóm.

- [x] **Step 1: Thêm config vào `defaults.js`**

Trong khối `features.introspection`, chèn ngay sau `enabled: false,`:

```js
        /*
         * features.introspection.strictTokenTypeHint
         *
         * description: Specifies whether a recognized `token_type_hint` shall be treated as
         *   binding. When enabled, a token that does not match the hinted type is reported as
         *   inactive rather than being looked up as the other token types. When disabled, which
         *   is the default and the behaviour
         *   [RFC7662](https://www.rfc-editor.org/info/rfc7662/) recommends, the hint is only an
         *   optimisation and the remaining token types are still searched.
         *
         *   The recognized hints are `access_token` and `refresh_token`, together with their
         *   `urn:ietf:params:oauth:token-type:` forms. An unrecognized hint searches every token
         *   type regardless of this setting. Access tokens and client credentials tokens form a
         *   single group under the `access_token` hint and are not distinguished from one another.
         *
         * Note: This is a fork-specific extension, it is not part of upstream oidc-provider.
         *   Enabling it is a deliberate deviation from RFC 7662 Section 2.1.
         */
        strictTokenTypeHint: false,
```

- [x] **Step 2: Sửa `lib/helpers/token_find.js`**

Thay toàn bộ file:

```js
export function createTokenFinder(provider, grantTypeHandlers, { strict = false } = {}) {
  const { AccessToken, ClientCredentials, RefreshToken } = provider;

  function getAccessToken(token) {
    return AccessToken.find(token);
  }

  function getClientCredentials(token) {
    if (!grantTypeHandlers.has('client_credentials')) {
      return undefined;
    }
    return ClientCredentials.find(token);
  }

  function getRefreshToken(token) {
    if (!grantTypeHandlers.has('refresh_token')) {
      return undefined;
    }
    return RefreshToken.find(token);
  }

  function findResult(results) {
    return results.find((found) => !!found);
  }

  return async function findTokenByHint(tokenValue, tokenTypeHint) {
    switch (tokenTypeHint) {
      case 'access_token':
      case 'urn:ietf:params:oauth:token-type:access_token': {
        const inGroup = await Promise.all([
          getAccessToken(tokenValue),
          getClientCredentials(tokenValue),
        ]).then(findResult);
        if (inGroup || strict) return inGroup;
        return getRefreshToken(tokenValue);
      }
      case 'refresh_token':
      case 'urn:ietf:params:oauth:token-type:refresh_token': {
        const inGroup = await getRefreshToken(tokenValue);
        if (inGroup || strict) return inGroup;
        return Promise.all([
          getAccessToken(tokenValue),
          getClientCredentials(tokenValue),
        ]).then(findResult);
      }
      default:
        return Promise.all([
          getAccessToken(tokenValue),
          getClientCredentials(tokenValue),
          getRefreshToken(tokenValue),
        ]).then(findResult);
    }
  };
}
```

Với `strict === false` hàm này tương đương từng bước với bản upstream — điều kiện để `test/introspection/` và `test/revocation/` không đỏ.

- [x] **Step 3: Truyền cờ từ `introspection.js`**

Phần destructure config đã có `introspection: { allowedPolicy }`. Đổi thành:

```js
      introspection: { allowedPolicy, strictTokenTypeHint },
```

Và đổi dòng khởi tạo:

```js
  const findToken = createTokenFinder(provider, grantTypeHandlers, { strict: strictTokenTypeHint });
```

**Không** đụng `lib/actions/revocation.js` — nó tiếp tục gọi `createTokenFinder(provider, grantTypeHandlers)` và nhận `strict: false`.

- [x] **Step 4: Dịch config và test từ Task 6, cập nhật hai ô đã biết sẽ khác**

Tạo `test/fork_introspection/fork_introspection.config.js`:

```js
import getConfig from '../default.config.js';
import merge from 'lodash/merge.js';

const config = getConfig();

merge(config.features, {
  introspection: { enabled: true, strictTokenTypeHint: true },
  clientCredentials: { enabled: true },
});

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
```

Tạo `test/fork_introspection/fork_introspection.test.js` — dịch từ Task 6, với ma trận cập nhật:

```js
  const cases = [
    // [loại token, hint, mong đợi active]
    ['AccessToken', undefined, true],
    ['AccessToken', 'access_token', true],
    ['AccessToken', 'urn:ietf:params:oauth:token-type:access_token', true],
    ['AccessToken', 'refresh_token', false],
    ['AccessToken', 'foobar', true],

    ['RefreshToken', undefined, true],
    ['RefreshToken', 'refresh_token', true],
    ['RefreshToken', 'urn:ietf:params:oauth:token-type:refresh_token', true],
    ['RefreshToken', 'access_token', false],
    ['RefreshToken', 'foobar', true],

    ['ClientCredentials', undefined, true],
    // KHÁC v7: v9 gộp AccessToken và ClientCredentials cùng nhóm cho hint
    // "access_token", nên strict không chặn ô này. Xem bảng ở đầu Task 14.
    ['ClientCredentials', 'access_token', true],
    ['ClientCredentials', 'refresh_token', false],
    // KHÁC v7: "client_credentials" không còn là hint hợp lệ ở v9, rơi vào
    // nhánh default và tra cả ba loại.
    ['ClientCredentials', 'client_credentials', true],
    ['ClientCredentials', 'foobar', true],
  ];
```

- [x] **Step 5: Suite cho nhánh mặc định `strict: false`**

Tạo `test/fork_introspection_lax/fork_introspection_lax.config.js` — giống config Step 4 nhưng **bỏ** `strictTokenTypeHint` (để mặc định).

Tạo `test/fork_introspection_lax/fork_introspection_lax.test.js` — cùng cấu trúc, `bootstrap(import.meta.url)`, và **mọi ô đều `true`** (không strict thì luôn tìm ra token bất kể hint):

```js
  const cases = [
    ['AccessToken', undefined, true],
    ['AccessToken', 'access_token', true],
    ['AccessToken', 'refresh_token', true],
    ['AccessToken', 'foobar', true],

    ['RefreshToken', undefined, true],
    ['RefreshToken', 'refresh_token', true],
    ['RefreshToken', 'access_token', true],
    ['RefreshToken', 'foobar', true],

    ['ClientCredentials', undefined, true],
    ['ClientCredentials', 'access_token', true],
    ['ClientCredentials', 'refresh_token', true],
    ['ClientCredentials', 'foobar', true],
  ];
```

- [x] **Step 6: Chạy cả hai file**

```bash
npx mocha --timeout 3000 test/fork_introspection/fork_introspection.test.js test/fork_introspection_lax/fork_introspection_lax.test.js
```

Expected: PASS. Sửa mọi ô lệch theo output thật và ghi lý do vào chú thích — **đừng** sửa lib để khớp một ô đoán sai.

- [x] **Step 7: Chạy suite upstream — cổng thật của task này**

```bash
npx mocha --timeout 3000 test/introspection/*.test.js
npx mocha --timeout 3000 test/jwt_introspection/*.test.js
npx mocha --timeout 3000 test/revocation/*.test.js
```

Expected: PASS, không đổi so với Task 7.

Hai bằng chứng cụ thể cần thấy:
- Ba test upstream `[wrong hint]` / `[unrecognized hint]` trong `test/introspection/introspection.test.js` vẫn xanh → `strict: false` không hồi quy.
- Suite revocation xanh → cờ không rò sang `revocation.js`.

- [x] **Step 8: Sinh lại docs, lint, chạy cả suite**

```bash
node docs/update-configuration.js
npm run lint
npm test
```

- [x] **Step 9: Commit**

```bash
git add lib/helpers/token_find.js lib/actions/introspection.js lib/helpers/defaults.js docs/README.md test/fork_introspection/ test/fork_introspection_lax/
git commit -m "feat: thêm config features.introspection.strictTokenTypeHint

Cờ truyền qua tham số của createTokenFinder chứ không đọc config bên trong,
để revocation.js dùng chung helper mà không đổi hành vi."
```

---

### Task 15: Xác minh việc bỏ patch `client_schema`

**Files:**
- Create: `test/fork_client_schema/fork_client_schema.config.js`
- Create: `test/fork_client_schema/fork_client_schema.test.js`

**Interfaces:**
- Consumes: `lib/helpers/client_schema.js` của upstream, **không sửa**
- Produces: câu trả lời dứt khoát cho câu hỏi mở duy nhất còn lại của spec, dưới dạng test đã commit.

Đây là **bước chặn**: nó có thể làm xuất hiện patch thứ 8. Không tuyên bố hoàn thành trước khi task này xanh.

## KẾT QUẢ (đo 2026-09-03): khả năng (b) — bỏ patch là an toàn, KHÔNG có patch thứ 8

Đo trên **cả hai** nhánh, cùng cấu hình client (`response_types: ['id_token']`, grant
type ngoài chuẩn đã `registerGrantType`):

| | v7 (có patch) | v9 (bỏ patch) |
|---|---|---|
| `client.grantTypes` | `["password"]` | `["urn:fork:password","implicit"]` |
| `/auth` với `response_type=id_token` | 303 + id_token trong fragment | 303 + id_token trong fragment |

**Hành vi đầu-cuối giống nhau.** Cả hai phiên bản gác authorization endpoint bằng
`client.responseTypeAllowed(...)` trong `check_response_type.js` — tức bằng
`response_types`, **không** bằng `grant_types`. `check_client_grant_type.js` chỉ áp cho
`device_authorization` và `backchannel_authentication`, không áp cho `/auth`.

`implicit` xuất hiện trong `grantTypes` là thay đổi **hình thức**: `implicit` không có
handler ở token endpoint nên không mở thêm đường nào. Đã khẳng định bằng test riêng —
`POST /token` với `grant_type=implicit` trả `unsupported_grant_type`.

**Hai điều phát hiện thêm khi đo, đều sửa hiểu sai trong kế hoạch:**

1. Patch v7 **không** tự cho `grant_types: ['password']` đi qua. Nó chỉ nới một
   `invalidate()` xảy ra **sau** check enum ở `client_schema.js` (v7 dòng 527, v9 dòng
   565-589). Grant type phải được `registerGrantType` trước, nếu không client bị từ
   chối ở enum trên **cả hai** phiên bản. Config ở Step 1 của kế hoạch
   (`grant_types: ['password']`, không đăng ký) rơi vào khả năng (a), không phải (b)/(c).
2. Allow-list của patch v7 là **năm tên nguyên văn** `implicit`/`password`/`social`/
   `telco`/`fast_login`. Client khai `urn:fork:password` + `id_token` bị **v7 từ chối**
   mà v9 chấp nhận. Nên theo chiều nới lỏng, v9 rộng hơn v7 ở các tên ngoài năm tên đó
   — nhưng với đúng cấu hình fork thực dùng thì trùng khớp.

Bối cảnh: patch v7 nới `invalidate()` để client khai `response_types: ['id_token'|'token']` với grant `password` / `social` / `telco` / `fast_login` không bị từ chối. v9 đổi hẳn cơ chế — không `invalidate()` nữa mà tự `this.grant_types.push('implicit')` (`lib/helpers/client_schema.js:313-315`). Câu hỏi: việc `implicit` bị thêm vào có mở luồng implicit mà fork không muốn mở?

- [x] **Step 1: Viết config**

Tạo `test/fork_client_schema/fork_client_schema.config.js`:

```js
import getConfig from '../default.config.js';

const config = getConfig();

export default {
  config,
  clients: [{
    client_id: 'client-nonstandard-grant',
    client_secret: 'secret',
    grant_types: ['password'],
    response_types: ['id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
```

`password` không phải grant type v9 biết, nên Provider có thể từ chối ngay lúc khởi tạo — đó là một trong ba kết quả có thể, xem Step 3.

- [x] **Step 2: Viết test dò**

Tạo `test/fork_client_schema/fork_client_schema.test.js`:

```js
import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('fork: dropping the client_schema grant_types patch', () => {
  before(bootstrap(import.meta.url));

  it('records what v9 does to grant_types when response_types has id_token', async function () {
    const client = await this.provider.Client.find('client-nonstandard-grant');
    expect(client).to.exist;
    /* eslint-disable no-console */
    console.log('[Task 15] grantTypes:', client.grantTypes);
    console.log('[Task 15] responseTypes:', client.responseTypes);
    /* eslint-enable no-console */
  });

  it('answers the blocking question: is the implicit flow actually usable now?', async function () {
    await this.login();

    const auth = new this.AuthorizationRequest({
      client_id: 'client-nonstandard-grant',
      response_type: 'id_token',
      scope: 'openid',
    });

    await this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect((response) => {
        /* eslint-disable no-console */
        console.log('[Task 15] status:', response.status);
        console.log('[Task 15] location:', response.headers.location);
        console.log('[Task 15] body:', JSON.stringify(response.body));
        /* eslint-enable no-console */
      });
  });
});
```

- [x] **Step 3: Chạy và đọc kết quả — ba khả năng, ba đường đi**

```bash
npx mocha --timeout 3000 test/fork_client_schema/fork_client_schema.test.js
```

**(a) Provider không khởi tạo được** với `grant_types: ['password']` — v9 từ chối grant type không biết. Kết luận: câu hỏi đặt sai chỗ, vì fork phải đăng ký grant type qua `registerGrantType` trước khi client khai nó. Viết lại config để dùng grant type đã đăng ký (theo mẫu ở Task 8 Step 4), chạy lại từ Step 3.

**(b) Client tồn tại, `grantTypes` có `implicit`, nhưng `/auth` bị từ chối** (`unauthorized_client` / `unsupported_response_type`). Kết luận: **bỏ patch là an toàn**. Sang Step 4.

**(c) Client tồn tại và `/auth` trả về id_token trong fragment.** Kết luận: **bỏ patch mở luồng implicit ngoài ý muốn.** Đây là patch thứ 8. **Dừng lại**, báo người ra quyết định, mở lại mục 4.1 của spec. Hướng khả dĩ: thêm config `clientImplicitGrantAutoAdd` (mặc định `true` = hành vi upstream) để fork tắt việc tự thêm `implicit`. **Không tự ý làm** — đây là quyết định về sản phẩm, không phải về code.

- [x] **Step 4: Chốt test thành assertion cứng**

Bỏ mọi `console.log`, thay bằng khẳng định theo hành vi thật đã quan sát. Ví dụ cho kết quả (b):

```js
  it('adds implicit to grant_types but the flow stays closed', async function () {
    const client = await this.provider.Client.find('client-nonstandard-grant');
    expect(client.grantTypes).to.include('implicit');
  });

  it('rejects an implicit authorization request from that client', async function () {
    await this.login();

    const auth = new this.AuthorizationRequest({
      client_id: 'client-nonstandard-grant',
      response_type: 'id_token',
      scope: 'openid',
    });

    await this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect(auth.validateError('unauthorized_client'));
  });
```

Chữ ký `auth.validateError` cần kiểm: `grep -n "validateError" -A 8 test/test_helper.js`. Nếu không có, so khớp trực tiếp trên `response.headers.location`.

Test này tồn tại lâu dài để lần sync upstream sau phát hiện nếu hành vi đổi.

- [x] **Step 5: Chạy lint và cả suite**

```bash
npm run lint
npm test
```

- [x] **Step 6: Commit**

```bash
git add test/fork_client_schema/
git commit -m "test: chốt hành vi v9 khi bỏ patch client_schema grant_types"
```

---

# Phần IV — Tài liệu, phía app, nghiệm thu (Task 16-18)

---

### Task 16: Cập nhật `CLAUDE.md`

**Files:**
- Modify: `CLAUDE.md`

**Interfaces:**
- Consumes: kết quả Task 8-15
- Produces: `CLAUDE.md` mô tả đúng nhánh v9.

`CLAUDE.md` hiện tại viết cho v7 và **gần như mọi mục đều sai** trên nhánh v9. Câu sai trong file này sẽ dẫn sai người (và agent) làm việc sau.

- [x] **Step 1: Sửa mục Repository**

- Đổi "Active development happens on the `v7.x` branch (the upstream Node 12/14/16/18 line)" thành nhánh `vlive/oidc-provider-v9` trên nền upstream 9.11.5.
- Đổi "diff against `panva/v7.x`" thành "diff against `origin/main` (mirror của `panva/main`)".
- Thay danh sách fork-specific changes bằng 7 patch thật:

```markdown
- `grantTypeParamsDefault` — params thêm vào mọi grant type đăng ký qua `registerGrantType` (`lib/provider.js`, `lib/helpers/defaults.js`).
- `cookies.prefix` — tiền tố cho mọi cookie name (`lib/provider.js`).
- `partner` / `ui_mode` — echo từ authorization request vào response (`lib/actions/authorization/respond.js`).
- `ctx.trackingAction` + event `refresh_token` trong grant refresh_token (`lib/actions/grants/refresh_token.js`).
- Session `loginFrom` (mặc định `web`) và `deviceId` (từ `ctx.req.deviceId`) (`lib/models/session.js`).
- `userinfoRequiredScopes` — scope nào được nhận ở userinfo endpoint (`lib/actions/userinfo.js`, `lib/helpers/defaults.js`).
- `features.introspection.strictTokenTypeHint` — coi `token_type_hint` là bắt buộc (`lib/helpers/token_find.js`, `lib/actions/introspection.js`).

Cookie `_SID` chia sẻ root-domain **không** nằm trong thư viện. Nó do app tích hợp
đặt qua middleware `provider.use()` — xem mục 4.4 của
`docs/superpowers/specs/2026-08-27-v9-migration-design.md`.

Hai endpoint device flow qua access token (`/device/code-check`,
`/device/code-verification`) và config `features.deviceFlow.approvalScopeValidate`
đã bị bỏ khi lên v9, không port.
```

- [x] **Step 2: Sửa mục Common commands**

- `npm install` — bỏ "Node 12 || 14 || 16 || 18 only", đổi thành Node 22+.
- Xoá `npm run format` (eslint không còn), thay bằng `npm run lint` (biome).
- Thêm `npm run build` và `npm run test-dist` (script mới của v9).
- **Sửa** công thức chạy-một-file: `npx mocha --timeout 3000 test/path/to/foo.test.js`
  **không chạy được** ở v7 (xem "Cách chạy một file test" ở đầu Phần I). Kiểm lại xem
  ở v9 nó có chạy được không — v9 bỏ `jose2` nên `test/run.js` dựng ít global hơn,
  có thể công thức này đúng ở v9. Chỉ ghi vào `CLAUDE.md` sau khi đã chạy thử thật.

- [x] **Step 3: Sửa đoạn nói về `test/run.js`**

Câu hiện tại sai hai chỗ: v9 `test/run.js` **không** còn dựng `global.keystore` (jose2 đã bị bỏ), và **không** gọi `forbidPending`. Sửa thành:

```markdown
`test/run.js` là runner tự viết, không phải `mocha` thuần: nó dựng một HTTP server
dùng chung ở `globalThis.server` trước khi mocha nạp `test/**/*.test.js`. Test giả
định global đó tồn tại; không chạy file test lẻ bằng `node` trực tiếp.

`CI=true` khiến `test/run.js` dùng reporter `min` và gọi `forbidOnly()` — đừng
commit `.only`.
```

- [x] **Step 4: Sửa mục Architecture**

Thêm khối này, và xoá mọi câu cũ nói ngược lại:

```markdown
Truy cập config: `instance(provider).configuration.a.b` (property), **không**
`instance(provider).configuration('a.b')` như v7. Với feature flags có lối tắt
`instance(provider).features.<name>`. Trong `lib/provider.js` dùng private field
`this.#int.configuration.a.b`.

`Provider` giờ **là** Koa app (`class Provider extends Koa`); `.app` đã deprecate.
`provider.use(fn)` được override để splice middleware vào trước router, nên mọi
middleware thêm bằng nó luôn ở vị trí upstream của mọi route.

Mọi route đều kết thúc request: middleware Koa đặt "downstream" sau provider sẽ
không chạy. Provider cũng không còn handler 404 catch-all.
```

- Bỏ `paseto` khỏi danh sách format trong `lib/models/formats/` (v8 đã xoá).
- Bỏ `connect` khỏi danh sách framework (v9 đã bỏ hỗ trợ).

- [x] **Step 5: Sửa mục Conventions**

- **"CommonJS only"** → **"ESM only"**. Đây là câu sai nghiêm trọng nhất trong file.
- Bỏ "no ESM", "targets Node 12+".
- Bỏ đoạn ESLint airbnb-base + babel-eslint, thay bằng biome (`biome.json`).
- Kiểm `.eslintrc` còn tồn tại không; nếu không, xoá đoạn về allowed dangling-underscore và đối chiếu lại với `biome.json`.

- [x] **Step 6: Sửa mục Tests**

- chai 4 → chai 6.
- `bootstrap(__dirname)` → `bootstrap(import.meta.url)`.
- Kiểm `nock` còn không: `grep -n nock package.json`. Nếu không, đổi thành `undici`.
- Thêm danh sách thư mục test của fork: `test/fork_params/`, `test/fork_tracking/`, `test/fork_session/`, `test/fork_provider/`, `test/fork_provider_noprefix/`, `test/fork_userinfo/`, `test/fork_userinfo_default/`, `test/fork_introspection/`, `test/fork_introspection_lax/`, `test/fork_client_schema/`.

- [x] **Step 7: Kiểm từng câu lệnh trong file thật sự chạy được**

```bash
npm run lint
npm test
npm run build
node docs/update-configuration.js
grep -n "nock\|jose2\|paseto" package.json
ls .eslintrc* biome.json 2>&1
```

Mọi lệnh nêu trong `CLAUDE.md` phải chạy được thật. Câu nào không kiểm được thì xoá — đừng để lại phỏng đoán.

**Bước này phát hiện một patch thứ 8 mà kế hoạch không lường (tooling, không phải lib):**

`npm run test-dist` **đỏ** sau khi Task 7 đổi tên package. `tools/test-dist.js` hardcode
`node_modules/oidc-provider/lib` và `await import('oidc-provider')` trong script
`IMPORT_ALL`, nên với tên `@strongnguyen/oidc-provider` nó gặp
`ENOENT: scandir 'node_modules/oidc-provider/lib'`.

Sửa: biến `IMPORT_ALL` thành hàm `importAllSource(packageName)` và truyền
`packedManifest.name` vào. Đây là chỗ **bắt buộc** phải sửa với mọi fork đổi tên
package, và chỉ lộ ra khi chạy lệnh thật — `npm test` không bắt được.

Sau khi sửa, `test-dist` xanh: 3284 passing trên chính tarball sẽ phát hành, và pass 1
(import mọi module đã publish chỉ với runtime dependency đã khai) cũng qua — xác nhận
7 patch fork không kéo theo dependency nào chưa khai.

**Ghi chú cần chuyển tới chủ fork, không sửa trong phạm vi này:** script
`"publish": "npm run lint && npm publish --access public"` mang từ v7 sang có nguy cơ
đệ quy — `publish` là một lifecycle event của npm, chạy **sau** khi publish xong, nên
`npm publish` sẽ gọi lại chính script này. Fork đã dùng nó từ v7 nên đây là hiện trạng,
không phải hồi quy; nhưng nếu muốn sạch thì đổi tên thành `release`.

- [x] **Step 8: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: cập nhật CLAUDE.md cho nhánh v9"
```

---

### Task 17: Cookie `_SID` ở repo app

**Files:** nằm ngoài repo này. Trong repo app tích hợp:
- Modify: file dựng Provider
- Create: file test cho middleware

**Interfaces:**
- Consumes: `provider.use()`, `ctx.oidc?.session` (`accountId`, `exp`, `transient`, `destroyed`)
- Produces: cookie `_SID` trên mọi response của route có session.

Task này **không phụ thuộc thứ tự** với Task 8-16, chạy song song được. Nhưng phải xong trước Task 18.

- [ ] **Step 1: Thêm middleware vào chỗ dựng Provider**

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
        domain: '.example.vn', // đổi thành root domain thật
      };
      if (!session.transient && session.exp) {
        opts.expires = new Date(session.exp * 1000);
      }
      ctx.cookies.set('_SID', session.destroyed ? '0' : (session.accountId || '0'), opts);
    }
  }
});
```

Ba điều bắt buộc, không phải cho gọn:

1. **`try/finally`** — patch v7 nằm trong `finally` của session handler nên vẫn set cookie khi route ném lỗi. Bỏ `finally` là đổi hành vi.
2. **`ctx.oidc?`** — request không match route nào thì `ctx.oidc` là `undefined`, vì `ensureOIDC` được gắn theo từng route chứ không phải top-level.
3. **`if (session)`** — route như `/token` không chạy session middleware.

Và **chỉ đọc, không ghi** vào `session`: Proxy trong `lib/shared/session.js` bẫy `set` và sẽ bật `touched`, kéo theo một lần persist ngoài ý muốn.

- [ ] **Step 2: Đối chiếu options với bản v7 đang chạy production**

Đọc `cookies.share` trong config production hiện tại và copy đúng từng option sang `opts`. Mặc định của thư viện v7 là:

```js
{ httpOnly: false, overwrite: true, sameSite: '', secure: false, domain: 'localhost' }
```

`sameSite: ''`, `secure: false`, `domain: 'localhost'` là giá trị **mặc định**, gần như chắc chắn production đã ghi đè. Lấy giá trị production, không lấy ba giá trị này.

- [ ] **Step 3: Viết test — đây là lý do tồn tại của task**

Test này là thứ **duy nhất** báo động khi upstream đổi hành vi splice của `use()` hoặc đổi chỗ `ensureOIDC`. Lúc đó cookie sẽ âm thầm ngừng được set: không lỗi, không log, chỉ là session chia sẻ root-domain hết hoạt động.

Bốn trường hợp tối thiểu:

```
1. route authorization      -> Set-Cookie có _SID=<accountId>
2. sau end_session          -> Set-Cookie có _SID=0
3. session không transient   -> header có chuỗi "expires="
4. route /token             -> KHÔNG có _SID
```

- [ ] **Step 4: Chạy test của repo app**

Expected: PASS cả bốn.

- [ ] **Step 5: Commit trong repo app**

```bash
git commit -m "feat: đặt cookie _SID chia sẻ root-domain qua middleware provider.use()"
```

---

### Task 18: Nghiệm thu

**Files:** không sửa file nào. Task này chỉ chạy và đọc.

**Interfaces:**
- Consumes: toàn bộ Task 7-17
- Produces: bằng chứng để tuyên bố hoàn thành, hoặc danh sách việc còn lại.

- [ ] **Step 1: Suite đầy đủ**

```bash
npm run lint
npm test
```

Expected: PASS cả hai. Số test = mốc Task 7 Step 3 + số test fork đã thêm.

- [ ] **Step 2: Ma trận mounted**

```bash
npm run test-ci
```

Expected: PASS ở cả express / koa / hapi / fastify.

Đây là chỗ bắt lỗi hardcode đường dẫn: test nào của fork hardcode `/auth` hay `/token` mà không tính `process.env.MOUNT_TO` sẽ đỏ ở đây. Nếu `test-ci` chỉ đỏ ở chế độ mounted, sửa test của fork để dùng `MOUNT_TO`, **đừng** sửa lib.

- [ ] **Step 3: Đối chiếu từng patch với Phần I**

Với mỗi cặp, mở hai file test và so từng assertion:

| Patch | v7 (Phần I) | v9 (Phần III) |
|---|---|---|
| `grantTypeParamsDefault` | Task 4 | Task 8 |
| `cookies.prefix` | Task 4 | Task 9 |
| `partner` / `ui_mode` | Task 1 | Task 10 |
| `trackingAction` | Task 2 | Task 11 |
| session `loginFrom` / `deviceId` | Task 3 | Task 12 |
| userinfo scope | Task 5 | Task 13 |
| introspection hint | Task 6 | Task 14 |

Mọi khác biệt phải có **một dòng giải thích** đã ghi trong commit message hoặc chú thích test. Khác biệt không giải thích được = lỗi port, không phải "chấp nhận được".

Ba khác biệt đã biết và đã chấp nhận, không cần điều tra lại:
- Ô `ClientCredentials` × `access_token` trong ma trận introspection (Task 14).
- Ô `*` × `client_credentials` trong cùng ma trận (Task 14).
- Bỏ early-return `ctx.oidc.entities.Session` trong `Session.get` (Task 12).

- [ ] **Step 4: Đóng gói và smoke test thật**

```bash
npm pack
```

Trong repo app: cài file `.tgz` vừa tạo, chạy suite của app, rồi khởi động app và kiểm bằng tay:

- Luồng authorization code trọn vòng (login → code → token → userinfo).
- Refresh token: consumer nhận được event `refresh_token` và `ctx.trackingAction` đúng.
- Cookie `_SID` xuất hiện ở authorization và bị đặt `0` sau end_session (Task 17).
- Grant type tuỳ biến của fork nhận được params trong `grantTypeParamsDefault`.
- Cookie có đúng tiền tố cấu hình.
- Userinfo nhận access token scope `api_profile_get`.

- [ ] **Step 5: Kiểm `docs/README.md` đã sinh đủ**

```bash
node docs/update-configuration.js
git diff --stat docs/README.md
grep -c "grantTypeParamsDefault" docs/README.md
grep -c "userinfoRequiredScopes" docs/README.md
grep -c "strictTokenTypeHint" docs/README.md
grep -c "cookies.prefix\|prefix" docs/README.md
```

Expected: `git diff` rỗng (đã sinh đủ ở các task trước), và bốn config đều tìm thấy.

- [ ] **Step 6: Đẩy nhánh, chưa merge**

```bash
git push -u origin vlive/oidc-provider-v9
```

**Không** merge vào `main`, **không** force-push lên `vlive/oidc-provider`, **không** `npm publish`. Ba việc đó là quyết định của chủ fork sau khi đọc kết quả nghiệm thu.

- [ ] **Step 7: Viết báo cáo nghiệm thu**

Nêu đủ bảy mục:

1. Số commit trên nhánh: kỳ vọng 10 (1 nền + 7 patch + 1 client_schema + 1 docs).
2. Kết quả `npm test` và `npm run test-ci`.
3. Kết luận Task 15 — (a), (b) hay (c) — và hệ quả.
4. Danh sách khác biệt hành vi so với v7, kèm lý do từng cái.
5. Trạng thái Task 17 ở repo app.
6. Kết quả smoke test Step 4.
7. Những gì **chưa** làm: merge, publish, xoá nhánh v7.

---

## Self-review

**Spec coverage:**

| Mục spec | Task |
|---|---|
| 4.1 bỏ CORS `Origin` | không cần task — upstream đã có, xác minh khi lập spec |
| 4.1 bỏ `resCookie` array check | không cần task — upstream đã sửa |
| 4.1 bỏ `client_schema` | Task 15 (bước chặn) |
| 4.2 bỏ 2 endpoint device flow | không cần task — không port gì; ghi vào `CLAUDE.md` ở Task 16 |
| 4.3 hook `userinfo` | Task 13 |
| 4.3 hook `introspection` | Task 14 |
| 4.4 cookie `_SID` ra ngoài | Task 17 |
| 4.5 `grantTypeParamsDefault` | Task 8 |
| 4.5 cookie prefix | Task 9 |
| 4.5 `partner` / `ui_mode` | Task 10 |
| 4.5 `trackingAction` | Task 11 |
| 4.5 session `loginFrom` / `deviceId` | Task 12 |
| 5 chiến lược git | Task 7 |
| 6 Pha 0 | Task 1-6 |
| 6 Pha 1 | Task 7 |
| 6 Pha 6 nghiệm thu | Task 18 |
| 7 đổi tooling + `CLAUDE.md` | Task 7 Step 4 (package.json) + Task 16 |
| 9 rủi ro "`overrides` che CVE" | Task 7 Step 5 |
| 9 rủi ro "`_SID` âm thầm ngừng" | Task 17 Step 3 |
| 9 rủi ro "test hardcode path đỏ ở mounted" | Task 18 Step 2 |

Không có mục spec nào thiếu task.

**Type consistency:**

- `createTokenFinder(provider, grantTypeHandlers, { strict })` — tham số thứ ba tuỳ chọn, dùng nhất quán ở Task 14 Step 2 và Step 3; `revocation.js` giữ hai tham số.
- `userinfoRequiredScopes` — mảng string, nhất quán ở Task 13 Step 1, 2, 3, 4.
- `grantTypeParamsDefault` — mảng string, nhất quán ở Task 8 Step 2, 3, 4.
- `mintRefreshToken(ctx, amr)` / `capture(ctx, amr)` — định nghĩa ở Task 2, dùng lại ở Task 11.
- `mintAccessToken(ctx, scope)` — định nghĩa ở Task 5, dùng lại ở Task 13 (cả hai file).
- `mint(ctx, kind)` với `kind ∈ {'AccessToken','RefreshToken','ClientCredentials'}` — định nghĩa ở Task 6, dùng lại ở Task 14 (cả hai file).
- `cases` dạng `[kind, hint, expectedActive]` — nhất quán Task 6 và Task 14.

**Điểm yếu đã biết của kế hoạch này:**

Chữ ký `bootstrap(import.meta.url, name)` **chưa được xác minh** trên v9 — Task 8 Step 1 là bước chặn, yêu cầu kiểm trước khi Task 9-15 dựa vào nó.

**Dữ kiện từ v7 (đã kiểm, Task 3 Step 4):** trên v7 chữ ký là `bootstrap(dir, { config })` — tham số thứ hai là **object**, và truyền string vào sẽ **lặng lẽ nạp sai config** thay vì báo lỗi. Nếu v9 giữ dạng object thì mọi suite phụ dùng chung thư mục được và bốn thư mục riêng ở trên là không cần thiết. Kiểm bằng `grep -n "export default function testHelper" -A 10 test/test_helper.js` trên nhánh v9, và **đừng** tin vào việc test xanh để suy ra config đã nạp đúng — hãy khẳng định trực tiếp một giá trị chỉ có trong config phụ. Kế hoạch đã giảm thiểu bằng cách cho mọi suite phụ dùng **thư mục riêng** (`fork_provider_noprefix`, `fork_userinfo_default`, `fork_introspection_lax`, `fork_session_device`) thay vì file config phụ cùng thư mục. Chỉ hai chỗ còn dựa vào tham số thứ hai: Task 8 Step 5 và Task 9 Step 3, cả hai đều trỏ vào `fork_provider`. Nếu helper không nhận tham số thứ hai, tách `grant_type_params_default.test.js` và `cookie_prefix.test.js` thành hai thư mục riêng, mỗi thư mục một config.
