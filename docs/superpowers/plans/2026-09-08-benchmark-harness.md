# Benchmark Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dựng `bench/` — harness đo hiệu năng luồng authorization code, các endpoint token và introspection của `lib/`, chạy được cả chế độ so hai git revision.

**Architecture:** Một vòng đo duy nhất (`loop.js`) chạy trên hai transport hoán đổi được (`inproc` qua `light-my-request`, `http` qua `node:http` + `undici.Pool`). Scenario là dữ liệu thuần: `prepare()` đúc pool fixture ngoài vùng đo, `steps[]` sinh request descriptor, `check()` xác nhận response. Một rep = một tiến trình con `rep.js` ghi JSON ra file; `run.js` điều phối, `compare.js` thêm worktree và chạy xen kẽ hai revision.

**Tech Stack:** Node 22 ESM, `node:test` + `node:assert/strict`, `undici` (có sẵn), `light-my-request` (devDependency mới), `jose` (có sẵn, chỉ dùng lúc sinh fixture jwks), biome.

**Spec:** `docs/superpowers/specs/2026-09-07-benchmark-harness-design.md`

## Global Constraints

- **Node 22+, ESM only.** `import`/`export`, không CommonJS, không TypeScript.
- **Không sửa `lib/` và không sửa `test/`.** Toàn bộ thay đổi nằm trong `bench/`, cộng ba dòng `package.json` và hai dòng `.gitignore`.
- **Harness chỉ dùng API công khai của provider** (`provider.callback()`, `provider.Client`, `provider.Grant`, `provider.Session`, `provider.Interaction`, `provider.AuthorizationCode`, `provider.RefreshToken`, `provider.AccessToken`) cộng builtin của Node. Không `import` từ `lib/helpers/**`: harness phải chạy được trên cả `origin/main`, nơi đường dẫn nội bộ có thể khác.
- **Profile bench không được chứa key riêng của fork.** Cấm `grantTypeParamsDefault`, `cookies.prefix`, `userinfoRequiredScopes`, `features.introspection.strictTokenTypeHint`. Lý do: `lib/helpers/configuration.js` chạy `pick(config, ...Object.keys(defaults))` nên trên `origin/main` các key này bị drop âm thầm, làm phép so sánh vô nghĩa.
- **`features.resourceIndicators` mặc định `enabled: true`** — phải tắt tường minh bằng `{ enabled: false }`.
- **Mọi số liệu latency tính bằng nanosecond** (`process.hrtime.bigint()`), chuyển sang `Number` khi ghi JSON.
- **Percentile dùng nearest-rank:** `sorted[Math.min(sorted.length - 1, Math.ceil(p / 100 * sorted.length) - 1)]`. Với input `1..100` thì p95 = 95. Định nghĩa này là hợp đồng, test khoá nó lại.
- **`npm test` và `npm run lint` phải không bị ảnh hưởng.** `test/run.js` chỉ glob `test/**/*.test.js` nên `bench/**/*.test.js` không lọt vào suite OIDC.
- **Giới hạn phải ghi trong mọi báo cáo:** phạm vi cô lập ⇒ số của mục đích B là *library ceiling*, không phải capacity production.

---

## File Structure

| File | Trách nhiệm |
|---|---|
| `bench/profiles/upstream-compatible.js` | Hằng số dùng chung + factory cấu hình provider. Không có logic đo. |
| `bench/fixtures/jwks.json` | Keypair RS256 + ES256 cố định, commit vào repo. Tránh sinh RSA mỗi rep và giữ chi phí chữ ký giống nhau giữa các revision. |
| `bench/lib/provider.js` | `createProvider({ libPath, profile })` — nạp `lib/index.js` theo đường dẫn, trả provider + handler. |
| `bench/lib/fixtures.js` | Đúc grant/session/interaction/code/refresh token/access token. Không biết gì về transport. |
| `bench/lib/stats.js` | Hàm thuần: percentile, summarize, median, iqr. Không I/O. |
| `bench/lib/loop.js` | Vòng đo: warmup, mode, concurrency, cấp item, thu mẫu, abort khi `check` fail. Không biết transport nào. |
| `bench/lib/transport-inproc.js` | `send(descriptor) → response` qua `light-my-request`. |
| `bench/lib/transport-http.js` | `send(descriptor) → response` qua `node:http` + `undici.Pool`. |
| `bench/scenarios/*.js` | Mỗi file một (hoặc một mảng) scenario. Chỉ dữ liệu + `prepare`/`steps`/`check`. |
| `bench/lib/report.js` | Định dạng bảng console và ghi file JSON. |
| `bench/lib/compare.js` | Worktree, kiểm dependencies, sinh thứ tự xen kẽ, gộp kết quả hai revision. |
| `bench/rep.js` | CLI một rep: dựng provider → prepare → loop → ghi JSON ra `--out`. |
| `bench/run.js` | CLI điều phối: spawn rep, `--smoke`, `--compare`, `--cpu-prof`. |
| `bench/README.md` | Cách dùng + cảnh báo library ceiling. |

Ranh giới quan trọng: `loop.js` không biết transport, transport không biết scenario, scenario không biết cách đo. Nhờ vậy thêm scenario hay thêm transport không sửa vòng đo.

---

## Task 1: Scaffold, profile, và provider factory

**Files:**
- Create: `bench/profiles/upstream-compatible.js`
- Create: `bench/fixtures/jwks.json`
- Create: `bench/lib/provider.js`
- Create: `bench/lib/provider.test.js`
- Modify: `.gitignore` (thêm 2 dòng)
- Modify: `package.json` (thêm 3 script + 1 devDependency)

**Interfaces:**
- Consumes: không có (task đầu).
- Produces:
  - `bench/profiles/upstream-compatible.js`: `export const constants` = `{ issuer, clientId, clientSecret, redirectUri, accountId, scope, offlineScope, ccScope, codeVerifier, codeChallenge }` (tất cả `string`); `export function configuration(jwks: object): object`.
  - `bench/lib/provider.js`: `export async function createProvider({ libPath: string, profile?: string }): Promise<{ provider, handler: (req, res) => void, constants: object, libPath: string }>`.

- [ ] **Step 1: Thêm devDependency và script**

`light-my-request` hiện chỉ là dep bắc cầu qua fastify; phải khai tường minh.

```bash
npm install --save-dev light-my-request@^6.6.0
```

Thêm vào `"scripts"` của `package.json`:

```json
    "bench": "node bench/run.js",
    "bench:smoke": "node bench/run.js --smoke",
    "bench:test": "node --test bench/"
```

- [ ] **Step 2: Thêm 2 dòng vào `.gitignore`**

Chèn ngay dưới khối `# Build output`:

```
# Benchmark artifacts
bench/results
bench/.worktrees
```

- [ ] **Step 3: Sinh `bench/fixtures/jwks.json`**

Key cố định, commit vào repo: nếu sinh RSA mỗi rep thì mỗi lần khởi tạo provider tốn thêm hàng trăm ms, nhân với 11 scenario × 5 rep × 2 revision.

```bash
mkdir -p bench/fixtures && node -e "
import('jose').then(async ({ generateKeyPair, exportJWK }) => {
  const { writeFileSync } = await import('node:fs');
  const keys = [];
  for (const alg of ['RS256', 'ES256']) {
    const { privateKey } = await generateKeyPair(alg, { extractable: true });
    keys.push(await exportJWK(privateKey));
  }
  writeFileSync('bench/fixtures/jwks.json', JSON.stringify({ keys }, null, 2) + '\n');
});
"
```

Kiểm tra: `node -e "const j=require('./bench/fixtures/jwks.json'); console.log(j.keys.map(k=>k.kty).join(','))"` phải in `RSA,EC`.

- [ ] **Step 4: Viết test thất bại cho provider factory**

Tạo `bench/lib/provider.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';

import { createProvider } from './provider.js';

const LIB = join(import.meta.dirname, '../../lib/index.js');

test('createProvider dựng provider từ đường dẫn lib tường minh', async () => {
  const { provider, handler, constants, libPath } = await createProvider({ libPath: LIB });

  assert.equal(provider.issuer, constants.issuer);
  assert.equal(typeof handler, 'function');
  assert.equal(libPath, LIB);
});

test('client của profile tìm được và dùng client_secret_basic', async () => {
  const { provider, constants } = await createProvider({ libPath: LIB });
  const client = await provider.Client.find(constants.clientId);

  assert.equal(client.clientId, constants.clientId);
  assert.equal(client.clientAuthMethod, 'client_secret_basic');
  assert.ok(client.grantTypeAllowed('authorization_code'));
  assert.ok(client.grantTypeAllowed('refresh_token'));
  assert.ok(client.grantTypeAllowed('client_credentials'));
});

test('profile không chứa key riêng của fork', async () => {
  const { configuration } = await import('../profiles/upstream-compatible.js');
  const config = configuration({ keys: [] });
  const forkOnly = ['grantTypeParamsDefault', 'cookies', 'userinfoRequiredScopes'];

  for (const key of forkOnly) {
    if (key === 'cookies') {
      assert.equal(config.cookies?.prefix, undefined, 'cookies.prefix là key riêng của fork');
      continue;
    }
    assert.equal(config[key], undefined, `${key} là key riêng của fork`);
  }
  assert.equal(config.features.introspection.strictTokenTypeHint, undefined);
});

test('resourceIndicators bị tắt tường minh', async () => {
  const { configuration } = await import('../profiles/upstream-compatible.js');
  assert.equal(configuration({ keys: [] }).features.resourceIndicators.enabled, false);
});
```

- [ ] **Step 5: Chạy test để xác nhận nó fail**

Run: `node --test bench/lib/provider.test.js`
Expected: FAIL — `Cannot find module ... bench/lib/provider.js`

- [ ] **Step 6: Viết `bench/profiles/upstream-compatible.js`**

`codeChallenge` được **tính** từ `codeVerifier` chứ không hardcode, để không có nguy cơ hằng số sai.

```js
import { createHash } from 'node:crypto';

const codeVerifier = 'bench-code-verifier.bench-code-verifier.0123456789';

export const name = 'upstream-compatible';

export const constants = {
  issuer: 'http://localhost:3000',
  clientId: 'bench-client',
  clientSecret: 'bench-client-secret-0123456789abcdef',
  redirectUri: 'https://rp.bench.test/cb',
  accountId: 'bench-account',
  scope: 'openid',
  offlineScope: 'openid offline_access',
  ccScope: 'api:read',
  codeVerifier,
  codeChallenge: createHash('sha256').update(codeVerifier).digest('base64url'),
};

export function configuration(jwks) {
  return {
    jwks,
    clients: [{
      client_id: constants.clientId,
      client_secret: constants.clientSecret,
      redirect_uris: [constants.redirectUri],
      grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
    }],
    scopes: ['openid', 'offline_access', constants.ccScope],
    features: {
      devInteractions: { enabled: false },
      introspection: { enabled: true },
      revocation: { enabled: true },
      clientCredentials: { enabled: true },
      resourceIndicators: { enabled: false },
    },
    ttl: {
      AccessToken: 3600,
      AuthorizationCode: 600,
      ClientCredentials: 600,
      Grant: 1209600,
      IdToken: 3600,
      Interaction: 3600,
      RefreshToken: 1209600,
      Session: 1209600,
    },
    findAccount(_ctx, sub) {
      return { accountId: sub, claims: () => ({ sub }) };
    },
  };
}
```

Ba lựa chọn có chủ ý, đều để loại nhiễu chứ không phải cho gọn:
- `ttl` khai số tường minh: mặc định của upstream là **hàm** và có in NOTICE lần đầu; số cố định làm phép đo tất định.
- `findAccount` tự khai: mặc định của upstream gọi `mustChange()` và in NOTICE, lại là placeholder dev.
- `devInteractions` tắt: bỏ route chỉ có trong chế độ dev khỏi router.

- [ ] **Step 7: Viết `bench/lib/provider.js`**

```js
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const JWKS_PATH = join(import.meta.dirname, '../fixtures/jwks.json');

export async function createProvider({ libPath, profile = 'upstream-compatible' }) {
  const { default: Provider } = await import(pathToFileURL(libPath).href);
  const { constants, configuration } = await import(
    pathToFileURL(join(import.meta.dirname, '../profiles', `${profile}.js`)).href
  );

  const jwks = JSON.parse(await readFile(JWKS_PATH, 'utf8'));
  const provider = new Provider(constants.issuer, configuration(jwks));

  return { provider, handler: provider.callback(), constants, libPath };
}
```

- [ ] **Step 8: Chạy test để xác nhận pass**

Run: `node --test bench/lib/provider.test.js`
Expected: PASS — 4 test.

- [ ] **Step 9: Lint và commit**

```bash
npm run lint
git add .gitignore package.json package-lock.json bench/
git commit -m "feat(bench): scaffold harness với profile upstream-compatible và provider factory"
```

---

## Task 2: `stats.js`

**Files:**
- Create: `bench/lib/stats.js`
- Create: `bench/lib/stats.test.js`

**Interfaces:**
- Consumes: không có.
- Produces:
  - `percentile(sortedAsc: number[], p: number): number`
  - `median(values: number[]): number`
  - `iqr(values: number[]): { q1: number, q3: number, iqr: number }`
  - `summarize(samplesNs: number[]): { count, min, max, mean, stddev, p50, p95, p99 }` (mọi giá trị là `number`, đơn vị nanosecond)

- [ ] **Step 1: Viết test thất bại**

Tạo `bench/lib/stats.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { percentile, median, iqr, summarize } from './stats.js';

const oneToHundred = Array.from({ length: 100 }, (_, i) => i + 1);

test('percentile nearest-rank khớp hợp đồng trong spec', () => {
  assert.equal(percentile(oneToHundred, 95), 95);
  assert.equal(percentile(oneToHundred, 50), 50);
  assert.equal(percentile(oneToHundred, 99), 99);
  assert.equal(percentile(oneToHundred, 100), 100);
  assert.equal(percentile([42], 95), 42);
});

test('percentile không sửa mảng đầu vào', () => {
  const input = [3, 1, 2];
  percentile([...input].sort((a, b) => a - b), 50);
  assert.deepEqual(input, [3, 1, 2]);
});

test('median xử lý cả số lẻ và số chẵn phần tử', () => {
  assert.equal(median([5, 1, 3]), 3);
  assert.equal(median([4, 1, 3, 2]), 2.5);
});

test('iqr trả q1, q3 và hiệu của chúng', () => {
  const result = iqr(oneToHundred);
  assert.equal(result.q1, 25);
  assert.equal(result.q3, 75);
  assert.equal(result.iqr, 50);
});

test('summarize trả đủ trường và mean đúng', () => {
  const s = summarize([10, 20, 30, 40]);
  assert.equal(s.count, 4);
  assert.equal(s.min, 10);
  assert.equal(s.max, 40);
  assert.equal(s.mean, 25);
  assert.equal(s.p50, 20);
  assert.ok(s.stddev > 11 && s.stddev < 12, `stddev=${s.stddev}`);
});

test('summarize từ chối mảng rỗng thay vì trả NaN', () => {
  assert.throws(() => summarize([]), /rỗng/);
});
```

- [ ] **Step 2: Chạy test để xác nhận fail**

Run: `node --test bench/lib/stats.test.js`
Expected: FAIL — `Cannot find module ... stats.js`

- [ ] **Step 3: Viết `bench/lib/stats.js`**

```js
export function percentile(sortedAsc, p) {
  if (sortedAsc.length === 0) {
    throw new Error('percentile: mảng rỗng');
  }
  const rank = Math.ceil((p / 100) * sortedAsc.length) - 1;
  return sortedAsc[Math.min(sortedAsc.length - 1, Math.max(0, rank))];
}

export function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

export function iqr(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const q1 = percentile(sorted, 25);
  const q3 = percentile(sorted, 75);
  return { q1, q3, iqr: q3 - q1 };
}

export function summarize(samplesNs) {
  if (samplesNs.length === 0) {
    throw new Error('summarize: mảng mẫu rỗng');
  }
  const sorted = [...samplesNs].sort((a, b) => a - b);
  const mean = sorted.reduce((acc, v) => acc + v, 0) / sorted.length;
  const variance = sorted.reduce((acc, v) => acc + (v - mean) ** 2, 0) / sorted.length;

  return {
    count: sorted.length,
    min: sorted[0],
    max: sorted[sorted.length - 1],
    mean,
    stddev: Math.sqrt(variance),
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
  };
}
```

- [ ] **Step 4: Chạy test để xác nhận pass**

Run: `node --test bench/lib/stats.test.js`
Expected: PASS — 6 test.

- [ ] **Step 5: Commit**

```bash
git add bench/lib/stats.js bench/lib/stats.test.js
git commit -m "feat(bench): stats với percentile nearest-rank"
```

---

## Task 3: `fixtures.js` — đúc artifact bằng API công khai

Đây là task rủi ro nhất và đã được dò thử trước: cả ba đường (đổi code lấy token, resume ra code, đúc refresh/access token) đã chạy thật trên `HEAD` trước khi kế hoạch này được viết.

**Files:**
- Create: `bench/lib/fixtures.js`
- Create: `bench/lib/fixtures.test.js`

**Interfaces:**
- Consumes: `createProvider` (Task 1), `constants` (Task 1).
- Produces: `export async function createFixtures({ provider, constants })` trả object:
  - `client` — instance `Client` đã `find`.
  - `grantId: string` — grant chứa cả `openid` và `offline_access`.
  - `basicAuth: string` — giá trị header `Authorization` sẵn dùng.
  - `async mintSession(): Promise<{ sessionJti: string, sessionUid: string, sid: string }>`
  - `async mintInteraction({ sessionJti, sessionUid }): Promise<{ uid: string, sessionJti: string }>`
  - `async mintCode({ sessionUid }): Promise<string>` — giá trị authorization code
  - `async mintRefreshToken({ sessionUid, sid }): Promise<string>`
  - `async mintAccessToken({ sessionUid, sid, scope? }): Promise<string>`
  - `authorizationParams(state?): URLSearchParams` — params cho `GET /auth`
  - `codeVerifier: string`, `redirectUri: string`, `clientId: string`, `accountId: string` — phơi lại từ `constants` để scenario không phải tự import profile.

- [ ] **Step 1: Viết test thất bại**

Tạo `bench/lib/fixtures.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';

import { createProvider } from './provider.js';
import { createFixtures } from './fixtures.js';

const LIB = join(import.meta.dirname, '../../lib/index.js');

async function setup() {
  const { provider, handler, constants } = await createProvider({ libPath: LIB });
  const fixtures = await createFixtures({ provider, constants });
  return { provider, handler, constants, fixtures };
}

test('grant chứa cả openid và offline_access', async () => {
  const { provider, fixtures } = await setup();
  const grant = await provider.Grant.find(fixtures.grantId);

  assert.ok(grant.getOIDCScopeFiltered(new Set(['openid'])).includes('openid'));
  assert.ok(grant.getOIDCScopeFiltered(new Set(['offline_access'])).includes('offline_access'));
});

test('mintSession lưu được session và trả uid khác jti', async () => {
  const { provider, fixtures } = await setup();
  const { sessionJti, sessionUid } = await fixtures.mintSession();

  assert.notEqual(sessionJti, sessionUid);
  const found = await provider.Session.find(sessionJti);
  assert.equal(found.uid, sessionUid);
  assert.equal(found.accountId, fixtures.accountId);
});

test('mintCode trả code tìm lại được qua adapter', async () => {
  const { provider, fixtures } = await setup();
  const { sessionUid } = await fixtures.mintSession();
  const code = await fixtures.mintCode({ sessionUid });

  const found = await provider.AuthorizationCode.find(code);
  assert.equal(found.accountId, fixtures.accountId);
  assert.equal(found.redirectUri, fixtures.redirectUri);
});

test('mintRefreshToken tạo token không bị rotate (client confidential)', async () => {
  const { provider, fixtures } = await setup();
  const { sessionUid, sid } = await fixtures.mintSession();
  const value = await fixtures.mintRefreshToken({ sessionUid, sid });

  const found = await provider.RefreshToken.find(value);
  assert.equal(found.gty, 'authorization_code');
  assert.ok(found.scopes.has('offline_access'));
  assert.ok(found.ttlPercentagePassed() < 70, 'token mới không được nằm trong vùng bị rotate');
});

test('mintAccessToken tạo token có scope openid', async () => {
  const { provider, fixtures } = await setup();
  const { sessionUid, sid } = await fixtures.mintSession();
  const value = await fixtures.mintAccessToken({ sessionUid, sid });

  const found = await provider.AccessToken.find(value);
  assert.ok(found.scopes.has('openid'));
  assert.equal(found.accountId, fixtures.accountId);
});

test('mintInteraction tạo interaction resume được (uid dùng làm cookie)', async () => {
  const { provider, fixtures } = await setup();
  const session = await fixtures.mintSession();
  const { uid } = await fixtures.mintInteraction(session);

  const found = await provider.Interaction.find(uid);
  assert.equal(found.uid, uid);
  assert.equal(found.session.uid, session.sessionUid);
  assert.equal(found.session.cookie, session.sessionJti);
  assert.equal(found.result.login.accountId, fixtures.accountId);
});

test('fixtures phơi codeVerifier khớp codeChallenge của profile', async () => {
  const { createHash } = await import('node:crypto');
  const { fixtures, constants } = await setup();

  assert.equal(
    createHash('sha256').update(fixtures.codeVerifier).digest('base64url'),
    constants.codeChallenge,
  );
});

test('mỗi lần mint trả giá trị khác nhau', async () => {
  const { fixtures } = await setup();
  const { sessionUid } = await fixtures.mintSession();
  const a = await fixtures.mintCode({ sessionUid });
  const b = await fixtures.mintCode({ sessionUid });

  assert.notEqual(a, b);
});
```

- [ ] **Step 2: Chạy test để xác nhận fail**

Run: `node --test bench/lib/fixtures.test.js`
Expected: FAIL — `Cannot find module ... fixtures.js`

- [ ] **Step 3: Viết `bench/lib/fixtures.js`**

Chú ý ba chi tiết đã xác minh bằng dò thử, sai một cái là request trả lỗi thay vì thành công:
`client` truyền vào constructor phải là **instance Client** (`await provider.Client.find(...)`);
`Interaction.session.uid` phải khớp `Session.uid` (`resume.js` so hai giá trị này và ném `SessionNotFound` nếu lệch);
cookie resume tên `_interaction_resume` và giá trị đúng bằng `uid` của interaction.

```js
import { randomBytes } from 'node:crypto';

const id = () => randomBytes(20).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);

export async function createFixtures({ provider, constants }) {
  const { clientId, clientSecret, accountId, redirectUri, scope, offlineScope, codeChallenge } = constants;

  const client = await provider.Client.find(clientId);
  if (!client) {
    throw new Error(`fixtures: không tìm thấy client ${clientId}`);
  }

  const grant = new provider.Grant({ clientId, accountId });
  grant.addOIDCScope(offlineScope);
  const grantId = await grant.save();

  const basicAuth = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;

  async function mintSession() {
    const sessionJti = id();
    const sid = id();
    const session = new provider.Session({ jti: sessionJti, loginTs: now(), accountId });
    session.authorizations = { [clientId]: { sid, grantId } };
    await session.save(1209600);
    return { sessionJti, sessionUid: session.uid, sid };
  }

  function authorizationParams(state = id()) {
    return new URLSearchParams({
      client_id: clientId,
      response_type: 'code',
      redirect_uri: redirectUri,
      scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });
  }

  async function mintInteraction({ sessionJti, sessionUid }) {
    const uid = id();
    const interaction = new provider.Interaction(uid, {
      params: Object.fromEntries(authorizationParams()),
      prompt: { name: 'login', reasons: ['no_session'], details: {} },
      session: { accountId, uid: sessionUid, cookie: sessionJti },
      grantId,
      returnTo: `${constants.issuer}/auth/${uid}`,
      result: { login: { accountId, ts: now(), remember: true } },
    });
    await interaction.save(3600);
    return { uid, sessionJti };
  }

  async function mintCode({ sessionUid }) {
    const code = new provider.AuthorizationCode({
      accountId,
      authTime: now(),
      client,
      grantId,
      codeChallenge,
      codeChallengeMethod: 'S256',
      redirectUri,
      scope,
      sessionUid,
    });
    return code.save();
  }

  async function mintRefreshToken({ sessionUid, sid }) {
    const refreshToken = new provider.RefreshToken({
      accountId,
      authTime: now(),
      client,
      grantId,
      gty: 'authorization_code',
      rotations: 0,
      scope: offlineScope,
      sessionUid,
      sid,
    });
    return refreshToken.save();
  }

  async function mintAccessToken({ sessionUid, sid, scope: tokenScope = scope }) {
    const accessToken = new provider.AccessToken({
      accountId,
      client,
      grantId,
      gty: 'authorization_code',
      scope: tokenScope,
      sessionUid,
      sid,
    });
    return accessToken.save();
  }

  return {
    client,
    clientId,
    accountId,
    redirectUri,
    codeVerifier: constants.codeVerifier,
    grantId,
    basicAuth,
    authorizationParams,
    mintSession,
    mintInteraction,
    mintCode,
    mintRefreshToken,
    mintAccessToken,
  };
}
```

- [ ] **Step 4: Chạy test để xác nhận pass**

Run: `node --test bench/lib/fixtures.test.js`
Expected: PASS — 8 test.

Nếu test `grant chứa cả openid và offline_access` fail vì `getOIDCScopeFiltered` không có trên revision đang dùng, đổi assert sang `assert.ok((await provider.Grant.find(fixtures.grantId)).openid.scope.includes('offline_access'))` và ghi lại lý do trong commit message — đây là API nội bộ của model Grant, không phải hợp đồng công khai.

- [ ] **Step 5: Lint và commit**

```bash
npm run lint
git add bench/lib/fixtures.js bench/lib/fixtures.test.js
git commit -m "feat(bench): đúc session/grant/code/token fixture qua API công khai"
```

---

## Task 4: Transport `inproc`

**Files:**
- Create: `bench/lib/transport-inproc.js`
- Create: `bench/lib/transport-inproc.test.js`

**Interfaces:**
- Consumes: `createProvider` (Task 1), `createFixtures` (Task 3).
- Produces: `export function createInprocTransport({ handler, authority }): { kind: 'inproc', send(descriptor): Promise<Response>, close(): Promise<void> }`
  - descriptor: `{ method?: string = 'GET', path: string, headers?: object, body?: string }`
  - Response: `{ status: number, headers: object, body: string }`

Hợp đồng `Response` này là **hợp đồng dùng chung của cả hai transport** — Task 5 phải trả đúng hình dạng đó.

- [ ] **Step 1: Viết test thất bại**

Tạo `bench/lib/transport-inproc.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';

import { createProvider } from './provider.js';
import { createFixtures } from './fixtures.js';
import { createInprocTransport } from './transport-inproc.js';

const LIB = join(import.meta.dirname, '../../lib/index.js');

async function setup() {
  const { provider, handler, constants } = await createProvider({ libPath: LIB });
  const fixtures = await createFixtures({ provider, constants });
  const transport = createInprocTransport({ handler, authority: 'localhost:3000' });
  return { provider, constants, fixtures, transport };
}

test('GET discovery trả 200 và JSON có authorization_endpoint', async () => {
  const { transport } = await setup();
  const res = await transport.send({ path: '/.well-known/openid-configuration' });

  assert.equal(res.status, 200);
  assert.ok(JSON.parse(res.body).authorization_endpoint);
});

test('POST token với Basic auth và body urlencoded trả 200', async () => {
  const { constants, fixtures, transport } = await setup();
  const res = await transport.send({
    method: 'POST',
    path: '/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: fixtures.basicAuth },
    body: new URLSearchParams({ grant_type: 'client_credentials', scope: constants.ccScope }).toString(),
  });

  assert.equal(res.status, 200);
  assert.ok(JSON.parse(res.body).access_token);
});

test('GET /auth không có session trả 303 tới interaction', async () => {
  const { fixtures, transport } = await setup();
  const res = await transport.send({ path: `/auth?${fixtures.authorizationParams()}` });

  assert.equal(res.status, 303);
  assert.match(res.headers.location, /^\/interaction\//);
});

test('cookie truyền được, resume ra 303 kèm code', async () => {
  const { fixtures, transport } = await setup();
  const session = await fixtures.mintSession();
  const { uid } = await fixtures.mintInteraction(session);

  const res = await transport.send({
    path: `/auth/${uid}`,
    headers: { cookie: `_session=${session.sessionJti}; _interaction_resume=${uid}` },
  });

  assert.equal(res.status, 303);
  assert.match(res.headers.location, /[?&]code=/);
});
```

- [ ] **Step 2: Chạy test để xác nhận fail**

Run: `node --test bench/lib/transport-inproc.test.js`
Expected: FAIL — `Cannot find module ... transport-inproc.js`

- [ ] **Step 3: Viết `bench/lib/transport-inproc.js`**

```js
import inject from 'light-my-request';

export function createInprocTransport({ handler, authority }) {
  return {
    kind: 'inproc',

    async send({ method = 'GET', path, headers, body }) {
      const res = await inject(handler, {
        method,
        url: path,
        authority,
        headers,
        payload: body,
      });

      return { status: res.statusCode, headers: res.headers, body: res.payload };
    },

    async close() {},
  };
}
```

Lý do dùng `light-my-request` chứ không tự dựng `IncomingMessage`/`ServerResponse`: cách tự dựng chạy với GET nhưng sự kiện `finish` không phát trên đường POST, và `ctx.is()` trả `null` khi request thiếu `content-length` nên body parser từ chối với `invalid_request`. Đã dò thử và xác nhận cả hai lỗi.

- [ ] **Step 4: Chạy test để xác nhận pass**

Run: `node --test bench/lib/transport-inproc.test.js`
Expected: PASS — 4 test.

- [ ] **Step 5: Commit**

```bash
git add bench/lib/transport-inproc.js bench/lib/transport-inproc.test.js
git commit -m "feat(bench): transport inproc qua light-my-request"
```

---

## Task 5: Transport `http`

**Files:**
- Create: `bench/lib/transport-http.js`
- Create: `bench/lib/transport-http.test.js`

**Interfaces:**
- Consumes: `createProvider` (Task 1), `createFixtures` (Task 3), `createInprocTransport` (Task 4, dùng trong test tương đương).
- Produces: `export async function createHttpTransport({ handler, connections }): Promise<{ kind: 'http', origin: string, send(descriptor): Promise<Response>, close(): Promise<void> }>` — `Response` cùng hình dạng với Task 4.

- [ ] **Step 1: Viết test thất bại**

Tạo `bench/lib/transport-http.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';

import { createProvider } from './provider.js';
import { createFixtures } from './fixtures.js';
import { createInprocTransport } from './transport-inproc.js';
import { createHttpTransport } from './transport-http.js';

const LIB = join(import.meta.dirname, '../../lib/index.js');

async function setup() {
  const { provider, handler, constants } = await createProvider({ libPath: LIB });
  const fixtures = await createFixtures({ provider, constants });
  return { handler, constants, fixtures };
}

test('GET discovery trả 200 qua socket thật', async () => {
  const { handler } = await setup();
  const transport = await createHttpTransport({ handler, connections: 1 });

  try {
    const res = await transport.send({ path: '/.well-known/openid-configuration' });
    assert.equal(res.status, 200);
    assert.ok(JSON.parse(res.body).authorization_endpoint);
    assert.match(transport.origin, /^http:\/\/127\.0\.0\.1:\d+$/);
  } finally {
    await transport.close();
  }
});

test('POST token qua socket thật trả 200', async () => {
  const { handler, constants, fixtures } = await setup();
  const transport = await createHttpTransport({ handler, connections: 1 });

  try {
    const res = await transport.send({
      method: 'POST',
      path: '/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: fixtures.basicAuth },
      body: new URLSearchParams({ grant_type: 'client_credentials', scope: constants.ccScope }).toString(),
    });
    assert.equal(res.status, 200);
    assert.ok(JSON.parse(res.body).access_token);
  } finally {
    await transport.close();
  }
});

test('hai transport trả cùng status và cùng bộ khoá JSON cho cùng descriptor', async () => {
  const { handler } = await setup();
  const descriptor = { path: '/.well-known/openid-configuration' };
  const inproc = createInprocTransport({ handler, authority: 'localhost:3000' });
  const http = await createHttpTransport({ handler, connections: 1 });

  try {
    const a = await inproc.send(descriptor);
    const b = await http.send(descriptor);

    assert.equal(a.status, b.status);
    assert.deepEqual(
      Object.keys(JSON.parse(a.body)).sort(),
      Object.keys(JSON.parse(b.body)).sort(),
    );
  } finally {
    await inproc.close();
    await http.close();
  }
});

test('close giải phóng server, gọi lại send thì lỗi', async () => {
  const { handler } = await setup();
  const transport = await createHttpTransport({ handler, connections: 1 });
  await transport.close();

  await assert.rejects(() => transport.send({ path: '/jwks' }));
});
```

Test tương đương chỉ so status và bộ khoá JSON, **không** so nguyên văn body: hai transport gửi header `Host` khác nhau (`localhost:3000` so với `127.0.0.1:<port>`), mà provider dựng URL trong discovery theo host của request. Khác biệt đó là đúng, không phải lỗi.

- [ ] **Step 2: Chạy test để xác nhận fail**

Run: `node --test bench/lib/transport-http.test.js`
Expected: FAIL — `Cannot find module ... transport-http.js`

- [ ] **Step 3: Viết `bench/lib/transport-http.js`**

```js
import { createServer } from 'node:http';
import { once } from 'node:events';

import { Pool } from 'undici';

export async function createHttpTransport({ handler, connections }) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  const { port } = server.address();
  const origin = `http://127.0.0.1:${port}`;
  const pool = new Pool(origin, { connections, pipelining: 1 });

  return {
    kind: 'http',
    origin,

    async send({ method = 'GET', path, headers, body }) {
      const res = await pool.request({ method, path, headers, body });
      const text = await res.body.text();
      return { status: res.statusCode, headers: res.headers, body: text };
    },

    async close() {
      await pool.close();
      server.close();
      await once(server, 'close');
    },
  };
}
```

Phải luôn đọc hết `res.body` — undici giữ connection ở trạng thái treo nếu body chưa được tiêu thụ, và sau vài nghìn vòng thì pool cạn rồi treo cả rep.

- [ ] **Step 4: Chạy test để xác nhận pass**

Run: `node --test bench/lib/transport-http.test.js`
Expected: PASS — 4 test.

- [ ] **Step 5: Commit**

```bash
git add bench/lib/transport-http.js bench/lib/transport-http.test.js
git commit -m "feat(bench): transport http qua node:http và undici Pool"
```

---

## Task 6: `loop.js` — vòng đo

**Files:**
- Create: `bench/lib/loop.js`
- Create: `bench/lib/loop.test.js`

**Interfaces:**
- Consumes: hình dạng `Response` của Task 4/5 (chỉ qua `transport.send`).
- Produces:
  - `export class CheckFailedError extends Error` — có thuộc tính `responses: Response[]`.
  - `export async function runLoop({ transport, scenario, items, iterations, durationMs, warmupIterations, warmupMs, concurrency }): Promise<{ samplesNs: number[], iterations: number, elapsedMs: number, rps: number, concurrency: number, mode: string }>`
- Hợp đồng scenario mà `runLoop` tiêu thụ:
  - `name: string`
  - `mode: 'fixed-iterations' | 'fixed-duration'`
  - `uniqueItems: boolean` — `true` thì mỗi item dùng đúng một lần, pool cạn là lỗi; `false` thì item được lặp vòng.
  - `steps: Array<(item, prior: Response[]) => descriptor>`
  - `check(responses: Response[], item): void` — ném lỗi nếu sai.

- [ ] **Step 1: Viết test thất bại**

Tạo `bench/lib/loop.test.js`. Test dùng transport giả, không cần provider — vòng đo phải độc lập hoàn toàn với transport:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { runLoop, CheckFailedError } from './loop.js';

function fakeTransport(responder = () => ({ status: 200, headers: {}, body: 'ok' })) {
  const sent = [];
  return {
    kind: 'fake',
    sent,
    async send(descriptor) {
      sent.push(descriptor);
      return responder(descriptor);
    },
    async close() {},
  };
}

const okScenario = {
  name: 'ok',
  mode: 'fixed-iterations',
  uniqueItems: false,
  steps: [(item) => ({ path: `/x/${item.n}` })],
  check(responses) {
    assert.equal(responses[0].status, 200);
  },
};

test('fixed-iterations chạy đúng số vòng và loại warmup khỏi mẫu', async () => {
  const transport = fakeTransport();
  const result = await runLoop({
    transport, scenario: okScenario, items: [{ n: 1 }],
    iterations: 10, warmupIterations: 3, concurrency: 1,
  });

  assert.equal(result.samplesNs.length, 10);
  assert.equal(transport.sent.length, 13);
  assert.equal(result.iterations, 10);
  assert.ok(result.rps > 0);
});

test('uniqueItems: mỗi item dùng đúng một lần', async () => {
  const transport = fakeTransport();
  const scenario = { ...okScenario, uniqueItems: true };
  const items = Array.from({ length: 6 }, (_, n) => ({ n }));

  await runLoop({ transport, scenario, items, iterations: 4, warmupIterations: 2, concurrency: 1 });

  const paths = transport.sent.map((d) => d.path);
  assert.equal(new Set(paths).size, 6);
});

test('uniqueItems: pool thiếu thì báo lỗi rõ ràng, không lặp lại item', async () => {
  const transport = fakeTransport();
  const scenario = { ...okScenario, uniqueItems: true };

  await assert.rejects(
    () => runLoop({ transport, scenario, items: [{ n: 1 }], iterations: 5, warmupIterations: 0, concurrency: 1 }),
    /pool cạn/,
  );
});

test('uniqueItems: false thì item được lặp vòng', async () => {
  const transport = fakeTransport();
  await runLoop({
    transport, scenario: okScenario, items: [{ n: 1 }, { n: 2 }],
    iterations: 6, warmupIterations: 0, concurrency: 1,
  });

  assert.deepEqual(transport.sent.map((d) => d.path), ['/x/1', '/x/2', '/x/1', '/x/2', '/x/1', '/x/2']);
});

test('fixed-duration dừng theo thời gian và có mẫu', async () => {
  const transport = fakeTransport();
  const scenario = { ...okScenario, mode: 'fixed-duration' };
  const result = await runLoop({
    transport, scenario, items: [{ n: 1 }],
    durationMs: 120, warmupMs: 30, concurrency: 1,
  });

  assert.ok(result.samplesNs.length > 0);
  assert.ok(result.elapsedMs >= 120, `elapsedMs=${result.elapsedMs}`);
  assert.ok(result.elapsedMs < 1000, `elapsedMs=${result.elapsedMs}`);
});

test('steps sau đọc được response của steps trước', async () => {
  const transport = fakeTransport((d) => ({ status: 200, headers: { location: '/cb?code=abc' }, body: d.path }));
  const scenario = {
    name: 'chain',
    mode: 'fixed-iterations',
    uniqueItems: false,
    steps: [
      () => ({ path: '/first' }),
      (_item, prior) => ({ path: `/second?from=${new URL(prior[0].headers.location, 'http://x').searchParams.get('code')}` }),
    ],
    check(responses) {
      assert.equal(responses.length, 2);
    },
  };

  await runLoop({ transport, scenario, items: [{}], iterations: 1, warmupIterations: 0, concurrency: 1 });

  assert.deepEqual(transport.sent.map((d) => d.path), ['/first', '/second?from=abc']);
});

test('check fail thì abort ngay và kèm response vào lỗi', async () => {
  const transport = fakeTransport(() => ({ status: 401, headers: {}, body: '{"error":"invalid_client"}' }));

  await assert.rejects(
    () => runLoop({
      transport, scenario: okScenario, items: [{ n: 1 }],
      iterations: 100, warmupIterations: 0, concurrency: 1,
    }),
    (err) => {
      assert.ok(err instanceof CheckFailedError);
      assert.equal(err.responses[0].status, 401);
      return true;
    },
  );

  assert.ok(transport.sent.length < 5, 'phải dừng ngay, không chạy hết 100 vòng');
});

test('concurrency > 1 vẫn cho đúng tổng số vòng', async () => {
  const transport = fakeTransport();
  const result = await runLoop({
    transport, scenario: okScenario, items: [{ n: 1 }],
    iterations: 20, warmupIterations: 0, concurrency: 4,
  });

  assert.equal(result.samplesNs.length, 20);
  assert.equal(result.concurrency, 4);
});
```

- [ ] **Step 2: Chạy test để xác nhận fail**

Run: `node --test bench/lib/loop.test.js`
Expected: FAIL — `Cannot find module ... loop.js`

- [ ] **Step 3: Viết `bench/lib/loop.js`**

```js
export class CheckFailedError extends Error {
  constructor(scenarioName, cause, responses) {
    super(`scenario "${scenarioName}": check thất bại — ${cause.message}`);
    this.name = 'CheckFailedError';
    this.cause = cause;
    this.responses = responses;
  }
}

function createItemSource({ scenario, items }) {
  let cursor = 0;

  if (scenario.uniqueItems) {
    return () => {
      if (cursor >= items.length) {
        throw new Error(`scenario "${scenario.name}": pool cạn sau ${items.length} item`);
      }
      return items[cursor++];
    };
  }

  return () => items[cursor++ % items.length];
}

async function runIteration({ transport, scenario, item }) {
  const responses = [];
  for (const step of scenario.steps) {
    responses.push(await transport.send(step(item, responses)));
  }

  try {
    scenario.check(responses, item);
  } catch (cause) {
    throw new CheckFailedError(scenario.name, cause, responses);
  }

  return responses;
}

async function runPhase({ transport, scenario, nextItem, budget, collect, concurrency }) {
  let issued = 0;
  const deadline = budget.durationMs === undefined
    ? undefined
    : performance.now() + budget.durationMs;

  const claim = () => {
    if (deadline !== undefined) {
      return performance.now() < deadline;
    }
    if (issued >= budget.iterations) {
      return false;
    }
    issued += 1;
    return true;
  };

  async function worker() {
    while (claim()) {
      const item = nextItem();
      const started = process.hrtime.bigint();
      await runIteration({ transport, scenario, item });
      if (collect) {
        collect.push(Number(process.hrtime.bigint() - started));
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, worker));
}

export async function runLoop({
  transport, scenario, items,
  iterations, durationMs, warmupIterations = 0, warmupMs = 0, concurrency = 1,
}) {
  const nextItem = createItemSource({ scenario, items });
  const byDuration = scenario.mode === 'fixed-duration';

  if (byDuration && scenario.uniqueItems) {
    throw new Error(`scenario "${scenario.name}": fixed-duration không dùng được với uniqueItems (pool không chặn được)`);
  }

  const warmupBudget = byDuration ? { durationMs: warmupMs } : { iterations: warmupIterations };
  if ((byDuration ? warmupMs : warmupIterations) > 0) {
    await runPhase({ transport, scenario, nextItem, budget: warmupBudget, collect: undefined, concurrency });
  }

  const samplesNs = [];
  const measureBudget = byDuration ? { durationMs } : { iterations };
  const started = performance.now();
  await runPhase({ transport, scenario, nextItem, budget: measureBudget, collect: samplesNs, concurrency });
  const elapsedMs = performance.now() - started;

  return {
    samplesNs,
    iterations: samplesNs.length,
    elapsedMs,
    rps: (samplesNs.length / elapsedMs) * 1000,
    concurrency,
    mode: scenario.mode,
  };
}
```

Ba chi tiết đáng chú ý trong đoạn trên:
- Số vòng được **claim trước** khi chạy (`issued += 1` trong `claim()`), nên `concurrency` worker không bao giờ vượt quá `iterations`.
- `collect` là `undefined` ở pha warmup, nên mẫu warmup bị loại ngay tại nguồn, không phải cắt về sau.
- `claim()` với `fixed-duration` không chặn số vòng, đúng lý do phải cấm kết hợp `fixed-duration` + `uniqueItems`.

- [ ] **Step 4: Chạy test để xác nhận pass**

Run: `node --test bench/lib/loop.test.js`
Expected: PASS — 8 test.

- [ ] **Step 5: Commit**

```bash
git add bench/lib/loop.js bench/lib/loop.test.js
git commit -m "feat(bench): vòng đo với warmup, concurrency và abort khi check fail"
```

---

## Task 7: Scenario luồng authorization code (1, 2, 3, 7)

**Files:**
- Create: `bench/scenarios/01-auth-new.js`
- Create: `bench/scenarios/02-auth-resume.js`
- Create: `bench/scenarios/03-token-authorization-code.js`
- Create: `bench/scenarios/07-full-authorization.js`
- Create: `bench/lib/scenarios.js`
- Create: `bench/lib/scenarios.test.js`

**Interfaces:**
- Consumes: `createFixtures` (Task 3), hợp đồng scenario của `runLoop` (Task 6).
- Produces:
  - `bench/lib/scenarios.js`: `export async function loadScenarios(): Promise<Scenario[]>` (đọc `bench/scenarios/*.js`, phẳng hoá `export default` dạng object hoặc mảng, sắp theo tên file); `export async function loadScenario(name: string): Promise<Scenario>`.
  - Mỗi scenario có `prepare({ provider, fixtures, constants, count })` trả `Promise<item[]>`. Cả bốn tham số luôn được truyền, scenario dùng cái nào thì nhận cái đó.

- [ ] **Step 1: Viết test thất bại**

Tạo `bench/lib/scenarios.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';

import { createProvider } from './provider.js';
import { createFixtures } from './fixtures.js';
import { createInprocTransport } from './transport-inproc.js';
import { runLoop } from './loop.js';
import { loadScenarios, loadScenario } from './scenarios.js';

const LIB = join(import.meta.dirname, '../../lib/index.js');

async function drive(scenarioName, iterations = 3) {
  const { provider, handler, constants } = await createProvider({ libPath: LIB });
  const fixtures = await createFixtures({ provider, constants });
  const scenario = await loadScenario(scenarioName);
  const count = scenario.uniqueItems ? iterations : 1;
  const items = await scenario.prepare({ provider, fixtures, constants, count });
  const transport = createInprocTransport({ handler, authority: 'localhost:3000' });

  const result = await runLoop({
    transport, scenario, items,
    iterations, durationMs: 60, warmupIterations: 0, warmupMs: 0, concurrency: 1,
  });

  await transport.close();
  return { result, scenario, items };
}

test('prepare nhận đủ provider, fixtures, constants, count', async () => {
  const { provider, constants } = await createProvider({ libPath: LIB });
  const fixtures = await createFixtures({ provider, constants });
  const scenario = await loadScenario('auth-new');
  const items = await scenario.prepare({ provider, fixtures, constants, count: 1 });

  assert.equal(items.length, 1);
});

test('mọi scenario khai đủ các trường của hợp đồng', async () => {
  for (const scenario of await loadScenarios()) {
    assert.equal(typeof scenario.name, 'string', 'name');
    assert.ok(['fixed-iterations', 'fixed-duration'].includes(scenario.mode), `${scenario.name}: mode`);
    assert.equal(typeof scenario.uniqueItems, 'boolean', `${scenario.name}: uniqueItems`);
    assert.ok(Array.isArray(scenario.steps) && scenario.steps.length > 0, `${scenario.name}: steps`);
    assert.equal(typeof scenario.check, 'function', `${scenario.name}: check`);
    assert.equal(typeof scenario.prepare, 'function', `${scenario.name}: prepare`);
  }
});

test('không scenario nào kết hợp fixed-duration với uniqueItems', async () => {
  for (const scenario of await loadScenarios()) {
    assert.ok(
      !(scenario.mode === 'fixed-duration' && scenario.uniqueItems),
      `${scenario.name}: fixed-duration + uniqueItems là cấu hình không chạy được`,
    );
  }
});

test('tên scenario không trùng nhau', async () => {
  const names = (await loadScenarios()).map((s) => s.name);
  assert.equal(new Set(names).size, names.length);
});

test('01 auth-new: 303 tới interaction', async () => {
  const { result } = await drive('auth-new');
  assert.equal(result.samplesNs.length, 3);
});

test('02 auth-resume: mỗi vòng tiêu thụ một interaction và ra code', async () => {
  const { result, scenario, items } = await drive('auth-resume');
  assert.equal(result.samplesNs.length, 3);
  assert.equal(scenario.uniqueItems, true);
  assert.equal(items.length, 3);
});

test('03 token-authorization-code: đổi code thật lấy access_token + id_token', async () => {
  const { result, scenario } = await drive('token-authorization-code');
  assert.equal(result.samplesNs.length, 3);
  assert.equal(scenario.uniqueItems, true);
});

test('07 full-authorization: ba step, step cuối dùng code từ step resume', async () => {
  const { result, scenario } = await drive('full-authorization');
  assert.equal(scenario.steps.length, 3);
  assert.equal(result.samplesNs.length, 3);
});
```

- [ ] **Step 2: Chạy test để xác nhận fail**

Run: `node --test bench/lib/scenarios.test.js`
Expected: FAIL — `Cannot find module ... scenarios.js`

- [ ] **Step 3: Viết `bench/lib/scenarios.js`**

```js
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const DIR = join(import.meta.dirname, '../scenarios');

export async function loadScenarios() {
  const files = (await readdir(DIR)).filter((f) => f.endsWith('.js')).sort();
  const scenarios = [];

  for (const file of files) {
    const mod = await import(pathToFileURL(join(DIR, file)).href);
    for (const scenario of [mod.default].flat()) {
      scenarios.push(scenario);
    }
  }

  return scenarios;
}

export async function loadScenario(name) {
  const found = (await loadScenarios()).find((s) => s.name === name);
  if (!found) {
    throw new Error(`không có scenario tên "${name}"`);
  }
  return found;
}
```

- [ ] **Step 4: Viết `bench/scenarios/01-auth-new.js`**

Item lặp lại được: mỗi request tạo một Interaction mới nên không tiêu thụ gì từ pool.

```js
export default {
  name: 'auth-new',
  title: 'GET /auth — request mới, chưa có session',
  mode: 'fixed-iterations',
  uniqueItems: false,

  async prepare({ fixtures }) {
    return [{ query: fixtures.authorizationParams().toString() }];
  },

  steps: [
    (item) => ({ path: `/auth?${item.query}` }),
  ],

  check([res]) {
    if (res.status !== 303) {
      throw new Error(`mong 303, nhận ${res.status}: ${res.body.slice(0, 200)}`);
    }
    if (!String(res.headers.location).startsWith('/interaction/')) {
      throw new Error(`mong redirect tới /interaction/, nhận ${res.headers.location}`);
    }
  },
};
```

- [ ] **Step 5: Viết `bench/scenarios/02-auth-resume.js`**

```js
export default {
  name: 'auth-resume',
  title: 'GET /auth/:uid — resume, phát authorization code',
  mode: 'fixed-iterations',
  uniqueItems: true,

  async prepare({ fixtures, count }) {
    const items = [];
    for (let i = 0; i < count; i += 1) {
      const session = await fixtures.mintSession();
      const { uid } = await fixtures.mintInteraction(session);
      items.push({ uid, sessionJti: session.sessionJti });
    }
    return items;
  },

  steps: [
    (item) => ({
      path: `/auth/${item.uid}`,
      headers: { cookie: `_session=${item.sessionJti}; _interaction_resume=${item.uid}` },
    }),
  ],

  check([res]) {
    if (res.status !== 303) {
      throw new Error(`mong 303, nhận ${res.status}: ${res.body.slice(0, 200)}`);
    }
    if (!/[?&]code=/.test(String(res.headers.location))) {
      throw new Error(`mong code trong Location, nhận ${res.headers.location}`);
    }
  },
};
```

- [ ] **Step 6: Viết `bench/scenarios/03-token-authorization-code.js`**

Mọi dữ liệu request được đóng gói vào **item** trong `prepare`. Hợp đồng của `runLoop` chỉ truyền `(item, prior)` cho `steps`, nên đừng trông đợi tham số thứ ba nào.

```js
export default {
  name: 'token-authorization-code',
  title: 'POST /token — grant_type=authorization_code',
  mode: 'fixed-iterations',
  uniqueItems: true,

  async prepare({ fixtures, count }) {
    const { sessionUid } = await fixtures.mintSession();
    const items = [];
    for (let i = 0; i < count; i += 1) {
      items.push({
        code: await fixtures.mintCode({ sessionUid }),
        auth: fixtures.basicAuth,
        redirectUri: fixtures.redirectUri,
        codeVerifier: fixtures.codeVerifier,
      });
    }
    return items;
  },

  steps: [
    (item) => ({
      method: 'POST',
      path: '/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: item.auth },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: item.code,
        redirect_uri: item.redirectUri,
        code_verifier: item.codeVerifier,
      }).toString(),
    }),
  ],

  check([res]) {
    if (res.status !== 200) {
      throw new Error(`mong 200, nhận ${res.status}: ${res.body.slice(0, 200)}`);
    }
    const body = JSON.parse(res.body);
    if (!body.access_token || !body.id_token) {
      throw new Error(`mong access_token và id_token, nhận ${Object.keys(body).join(',')}`);
    }
  },
};
```

- [ ] **Step 7: Viết `bench/scenarios/07-full-authorization.js`**

Ba step trong một vòng đo. Step 3 dùng **code thật** lấy từ `Location` của step 2, nên số của scenario này là chi phí thật của một uỷ quyền trọn vẹn, không phải tổng của ba phép đo rời.

```js
export default {
  name: 'full-authorization',
  title: 'Chuỗi đầy đủ — /auth mới + resume + đổi code (một uỷ quyền)',
  mode: 'fixed-iterations',
  uniqueItems: true,

  async prepare({ fixtures, count }) {
    const items = [];
    for (let i = 0; i < count; i += 1) {
      const session = await fixtures.mintSession();
      const { uid } = await fixtures.mintInteraction(session);
      items.push({
        uid,
        sessionJti: session.sessionJti,
        query: fixtures.authorizationParams().toString(),
        auth: fixtures.basicAuth,
        redirectUri: fixtures.redirectUri,
        codeVerifier: fixtures.codeVerifier,
      });
    }
    return items;
  },

  steps: [
    (item) => ({ path: `/auth?${item.query}` }),

    (item) => ({
      path: `/auth/${item.uid}`,
      headers: { cookie: `_session=${item.sessionJti}; _interaction_resume=${item.uid}` },
    }),

    (item, prior) => {
      const code = new URL(prior[1].headers.location).searchParams.get('code');
      return {
        method: 'POST',
        path: '/token',
        headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: item.auth },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: item.redirectUri,
          code_verifier: item.codeVerifier,
        }).toString(),
      };
    },
  ],

  check([authNew, resumed, token]) {
    if (authNew.status !== 303) {
      throw new Error(`step 1: mong 303, nhận ${authNew.status}`);
    }
    if (resumed.status !== 303 || !/[?&]code=/.test(String(resumed.headers.location))) {
      throw new Error(`step 2: mong 303 kèm code, nhận ${resumed.status} ${resumed.headers.location}`);
    }
    if (token.status !== 200) {
      throw new Error(`step 3: mong 200, nhận ${token.status}: ${token.body.slice(0, 200)}`);
    }
    if (!JSON.parse(token.body).access_token) {
      throw new Error('step 3: thiếu access_token');
    }
  },
};
```

Ghi rõ trong `bench/README.md` (Task 10): interaction ở đây là **đúc sẵn**, không phải đến từ một lần login thật, vì trang login thuộc app tích hợp chứ không thuộc thư viện. Mọi thứ khác trong chuỗi là đường thật.

- [ ] **Step 8: Chạy test để xác nhận pass**

Run: `node --test bench/lib/scenarios.test.js bench/lib/fixtures.test.js`
Expected: PASS — 8 test scenario + 8 test fixtures.

- [ ] **Step 9: Lint và commit**

```bash
npm run lint
git add bench/lib/scenarios.js bench/lib/scenarios.test.js bench/lib/fixtures.js bench/lib/fixtures.test.js bench/scenarios/
git commit -m "feat(bench): scenario luồng authorization code (auth mới, resume, đổi code, chuỗi đầy đủ)"
```

---

## Task 8: Scenario token API và baseline (4, 5, 6, 8, 9, 10)

**Files:**
- Create: `bench/scenarios/04-token-refresh.js`
- Create: `bench/scenarios/05-token-client-credentials.js`
- Create: `bench/scenarios/06-introspection.js`
- Create: `bench/scenarios/08-userinfo.js`
- Create: `bench/scenarios/09-revocation.js`
- Create: `bench/scenarios/10-baseline.js`
- Modify: `bench/lib/scenarios.test.js` (thêm test cho 6 scenario mới)

**Interfaces:**
- Consumes: `createFixtures` (Task 3), hợp đồng scenario (Task 6), `loadScenario` (Task 7).
- Produces: 7 scenario mới (`10-baseline.js` export mảng 2 scenario: `discovery` và `jwks`).

- [ ] **Step 1: Thêm test thất bại vào `bench/lib/scenarios.test.js`**

```js
test('04 token-refresh: repeatable, dùng lại một refresh token', async () => {
  const { result, scenario } = await drive('token-refresh');
  assert.equal(scenario.uniqueItems, false);
  assert.ok(result.samplesNs.length > 0);
});

test('05 token-client-credentials: repeatable', async () => {
  const { result, scenario } = await drive('token-client-credentials');
  assert.equal(scenario.uniqueItems, false);
  assert.ok(result.samplesNs.length > 0);
});

test('06 introspection: repeatable, active=true', async () => {
  const { result, scenario } = await drive('introspection');
  assert.equal(scenario.uniqueItems, false);
  assert.ok(result.samplesNs.length > 0);
});

test('08 userinfo: repeatable, trả sub', async () => {
  const { result } = await drive('userinfo');
  assert.ok(result.samplesNs.length > 0);
});

test('09 revocation: one-shot, mỗi vòng thu hồi một token khác', async () => {
  const { result, scenario, items } = await drive('revocation');
  assert.equal(scenario.uniqueItems, true);
  assert.equal(items.length, 3);
  assert.equal(result.samplesNs.length, 3);
});

test('10 baseline: file export hai scenario discovery và jwks', async () => {
  const names = (await loadScenarios()).map((s) => s.name);
  assert.ok(names.includes('discovery'));
  assert.ok(names.includes('jwks'));
});

test('có đúng 11 scenario (10 mục trong spec, mục 10 tính hai)', async () => {
  assert.equal((await loadScenarios()).length, 11);
});
```

- [ ] **Step 2: Chạy test để xác nhận fail**

Run: `node --test bench/lib/scenarios.test.js`
Expected: FAIL — `không có scenario tên "token-refresh"`

- [ ] **Step 3: Viết `bench/scenarios/04-token-refresh.js`**

Repeatable vì với client confidential và token vừa đúc, `rotateRefreshToken` mặc định trả `false` (`ttlPercentagePassed()` ≈ 0, và nhánh rotate chỉ áp cho client `clientAuthMethod === 'none'`). Token không bị tiêu thụ nên dùng lại được.

```js
export default {
  name: 'token-refresh',
  title: 'POST /token — grant_type=refresh_token',
  mode: 'fixed-duration',
  uniqueItems: false,

  async prepare({ fixtures }) {
    const { sessionUid, sid } = await fixtures.mintSession();
    const refreshToken = await fixtures.mintRefreshToken({ sessionUid, sid });
    return [{ refreshToken, auth: fixtures.basicAuth }];
  },

  steps: [
    (item) => ({
      method: 'POST',
      path: '/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: item.auth },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: item.refreshToken }).toString(),
    }),
  ],

  check([res]) {
    if (res.status !== 200) {
      throw new Error(`mong 200, nhận ${res.status}: ${res.body.slice(0, 200)}`);
    }
    const body = JSON.parse(res.body);
    if (!body.access_token) {
      throw new Error(`thiếu access_token: ${Object.keys(body).join(',')}`);
    }
    if (body.refresh_token) {
      // rotate xảy ra ⇒ token đầu vào đã bị tiêu thụ ⇒ scenario không còn repeatable
      throw new Error('refresh token bị rotate: scenario này giả định không rotate, xem lại profile');
    }
  },
};
```

- [ ] **Step 4: Viết `bench/scenarios/05-token-client-credentials.js`**

```js
export default {
  name: 'token-client-credentials',
  title: 'POST /token — grant_type=client_credentials',
  mode: 'fixed-duration',
  uniqueItems: false,

  async prepare({ fixtures, constants }) {
    return [{ auth: fixtures.basicAuth, scope: constants.ccScope }];
  },

  steps: [
    (item) => ({
      method: 'POST',
      path: '/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: item.auth },
      body: new URLSearchParams({ grant_type: 'client_credentials', scope: item.scope }).toString(),
    }),
  ],

  check([res]) {
    if (res.status !== 200) {
      throw new Error(`mong 200, nhận ${res.status}: ${res.body.slice(0, 200)}`);
    }
    if (!JSON.parse(res.body).access_token) {
      throw new Error('thiếu access_token');
    }
  },
};
```

`constants` đã nằm trong hợp đồng `prepare` từ Task 7, không cần sửa gì thêm.

- [ ] **Step 5: Viết `bench/scenarios/06-introspection.js`**

```js
export default {
  name: 'introspection',
  title: 'POST /token/introspection',
  mode: 'fixed-duration',
  uniqueItems: false,

  async prepare({ fixtures }) {
    const { sessionUid, sid } = await fixtures.mintSession();
    const token = await fixtures.mintAccessToken({ sessionUid, sid });
    return [{ token, auth: fixtures.basicAuth }];
  },

  steps: [
    (item) => ({
      method: 'POST',
      path: '/token/introspection',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: item.auth },
      body: new URLSearchParams({ token: item.token }).toString(),
    }),
  ],

  check([res]) {
    if (res.status !== 200) {
      throw new Error(`mong 200, nhận ${res.status}: ${res.body.slice(0, 200)}`);
    }
    if (JSON.parse(res.body).active !== true) {
      throw new Error('mong active=true — đang đo đường token không hợp lệ, số sẽ sai');
    }
  },
};
```

`active !== true` là bẫy điển hình: token sai vẫn trả 200 nhưng đường xử lý ngắn hơn nhiều, cho ra số đẹp giả.

- [ ] **Step 6: Viết `bench/scenarios/08-userinfo.js`**

```js
export default {
  name: 'userinfo',
  title: 'GET /me — userinfo',
  mode: 'fixed-duration',
  uniqueItems: false,

  async prepare({ fixtures }) {
    const { sessionUid, sid } = await fixtures.mintSession();
    const token = await fixtures.mintAccessToken({ sessionUid, sid });
    return [{ token }];
  },

  steps: [
    (item) => ({ path: '/me', headers: { authorization: `Bearer ${item.token}` } }),
  ],

  check([res]) {
    if (res.status !== 200) {
      throw new Error(`mong 200, nhận ${res.status}: ${res.body.slice(0, 200)}`);
    }
    if (!JSON.parse(res.body).sub) {
      throw new Error('thiếu sub');
    }
  },
};
```

- [ ] **Step 7: Viết `bench/scenarios/09-revocation.js`**

```js
export default {
  name: 'revocation',
  title: 'POST /token/revocation',
  mode: 'fixed-iterations',
  uniqueItems: true,

  async prepare({ fixtures, count }) {
    const { sessionUid, sid } = await fixtures.mintSession();
    const items = [];
    for (let i = 0; i < count; i += 1) {
      items.push({
        token: await fixtures.mintAccessToken({ sessionUid, sid }),
        auth: fixtures.basicAuth,
      });
    }
    return items;
  },

  steps: [
    (item) => ({
      method: 'POST',
      path: '/token/revocation',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: item.auth },
      body: new URLSearchParams({ token: item.token }).toString(),
    }),
  ],

  check([res]) {
    if (res.status !== 200) {
      throw new Error(`mong 200, nhận ${res.status}: ${res.body.slice(0, 200)}`);
    }
  },
};
```

- [ ] **Step 8: Viết `bench/scenarios/10-baseline.js`**

File này export **mảng** hai scenario — `loadScenarios` đã phẳng hoá bằng `[mod.default].flat()`.

```js
const baseline = (name, title, path, assertBody) => ({
  name,
  title,
  mode: 'fixed-duration',
  uniqueItems: false,
  baseline: true,

  async prepare() {
    return [{}];
  },

  steps: [() => ({ path })],

  check([res]) {
    if (res.status !== 200) {
      throw new Error(`mong 200, nhận ${res.status}: ${res.body.slice(0, 200)}`);
    }
    assertBody(JSON.parse(res.body));
  },
});

export default [
  baseline('discovery', 'GET /.well-known/openid-configuration', '/.well-known/openid-configuration', (body) => {
    if (!body.authorization_endpoint) {
      throw new Error('thiếu authorization_endpoint');
    }
  }),

  baseline('jwks', 'GET /jwks', '/jwks', (body) => {
    if (!Array.isArray(body.keys) || body.keys.length === 0) {
      throw new Error('thiếu keys');
    }
  }),
];
```

Cờ `baseline: true` là thứ `report.js` (Task 9) dùng cho bất biến "endpoint giao thức không được nhanh hơn discovery".

- [ ] **Step 9: Chạy test để xác nhận pass**

Run: `node --test bench/lib/scenarios.test.js`
Expected: PASS — 15 test.

- [ ] **Step 10: Lint và commit**

```bash
npm run lint
git add bench/scenarios/ bench/lib/scenarios.test.js
git commit -m "feat(bench): scenario refresh, client_credentials, introspection, userinfo, revocation, baseline"
```

---

## Task 9: `rep.js`, `report.js`, `run.js` và `--smoke`

**Files:**
- Create: `bench/rep.js`
- Create: `bench/lib/report.js`
- Create: `bench/lib/report.test.js`
- Create: `bench/run.js`
- Create: `bench/run.test.js`

**Interfaces:**
- Consumes: mọi thứ từ Task 1–8.
- Produces:
  - `bench/rep.js` — CLI. Cờ: `--lib <path>` (bắt buộc), `--scenario <name>` (bắt buộc), `--out <file>` (bắt buộc), `--transport inproc|http`, `--profile <name>`, `--iterations N`, `--duration MS`, `--warmup-iterations N`, `--warmup-ms MS`, `--concurrency N`. Exit 0 khi xong, exit 1 khi `check` fail hoặc pool cạn.
  - `bench/lib/report.js`: `export function formatRunTable(reps): string`; `export function baselineWarnings(reps): string[]`; `export async function writeResults(dir, payload): Promise<string>` (trả đường dẫn file đã ghi).
  - `bench/run.js` — CLI điều phối. Cờ: `--scenario <name,...>`, `--transport <inproc|http>`, `--reps N`, `--smoke`, `--sweep`, `--out-dir <dir>`, cộng các cờ chuyển tiếp cho `rep.js`.
  - `export function sweepLevels(scenario): number[]` — mức concurrency cần chạy cho một scenario: `[1, 8, 32, 128]` nếu repeatable, `[1]` nếu `uniqueItems` (pool chặn số vòng nên không có ngưỡng để tìm).
- Hình dạng JSON của rep (hợp đồng giữa `rep.js`, `report.js` và `compare.js` ở Task 10):

```json
{
  "scenario": "token-authorization-code",
  "transport": "inproc",
  "mode": "fixed-iterations",
  "concurrency": 1,
  "iterations": 20000,
  "elapsedMs": 1234.5,
  "rps": 16200.4,
  "summary": { "count": 20000, "min": 0, "max": 0, "mean": 0, "stddev": 0, "p50": 0, "p95": 0, "p99": 0 },
  "samplesNs": [12345],
  "meta": { "lib": "/abs/path/lib/index.js", "profile": "upstream-compatible", "node": "v22.23.0", "cpu": "…", "os": "darwin 25.5.0", "ts": "2026-09-08T…Z" }
}
```

- [ ] **Step 1: Viết test thất bại cho `report.js`**

Tạo `bench/lib/report.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { formatRunTable, baselineWarnings, writeResults } from './report.js';

const rep = (scenario, p50, rps, extra = {}) => ({
  scenario, transport: 'inproc', mode: 'fixed-duration', concurrency: 1,
  iterations: 100, elapsedMs: 100, rps,
  summary: { count: 100, min: p50, max: p50, mean: p50, stddev: 0, p50, p95: p50, p99: p50 },
  samplesNs: [p50], meta: {}, ...extra,
});

test('formatRunTable in một dòng cho mỗi scenario, có tên và p50', () => {
  const table = formatRunTable([rep('discovery', 50_000, 20_000), rep('introspection', 120_000, 8_000)]);

  assert.match(table, /discovery/);
  assert.match(table, /introspection/);
  assert.equal(table.split('\n').filter((l) => l.includes('discovery')).length, 1);
});

test('baselineWarnings cảnh báo khi endpoint giao thức nhanh hơn discovery', () => {
  const warnings = baselineWarnings([
    rep('discovery', 100_000, 10_000, { baseline: true }),
    rep('introspection', 40_000, 25_000),
  ]);

  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /introspection/);
  assert.match(warnings[0], /discovery/);
});

test('baselineWarnings im lặng khi thứ tự hợp lý', () => {
  const warnings = baselineWarnings([
    rep('discovery', 40_000, 25_000, { baseline: true }),
    rep('introspection', 100_000, 10_000),
  ]);

  assert.deepEqual(warnings, []);
});

test('baselineWarnings không cảnh báo baseline so với chính baseline khác', () => {
  const warnings = baselineWarnings([
    rep('discovery', 100_000, 10_000, { baseline: true }),
    rep('jwks', 40_000, 25_000, { baseline: true }),
  ]);

  assert.deepEqual(warnings, []);
});

test('writeResults ghi JSON đọc lại được và trả đường dẫn', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bench-report-'));
  const path = await writeResults(dir, { hello: 'world' });

  assert.match(path, /\.json$/);
  assert.deepEqual(JSON.parse(await readFile(path, 'utf8')), { hello: 'world' });
});
```

- [ ] **Step 2: Chạy test để xác nhận fail**

Run: `node --test bench/lib/report.test.js`
Expected: FAIL — `Cannot find module ... report.js`

- [ ] **Step 3: Viết `bench/lib/report.js`**

```js
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const us = (ns) => (ns / 1000).toFixed(1);

export function formatRunTable(reps) {
  const header = ['scenario', 'transport', 'conc', 'n', 'p50 µs', 'p95 µs', 'p99 µs', 'rps'];
  const rows = reps.map((r) => [
    r.scenario,
    r.transport,
    String(r.concurrency),
    String(r.summary.count),
    us(r.summary.p50),
    us(r.summary.p95),
    us(r.summary.p99),
    r.rps.toFixed(0),
  ]);

  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((row) => row[i].length)));
  const line = (cells) => cells.map((c, i) => c.padEnd(widths[i])).join('  ').trimEnd();

  return [line(header), line(widths.map((w) => '-'.repeat(w))), ...rows.map(line)].join('\n');
}

export function baselineWarnings(reps) {
  const baselines = reps.filter((r) => r.baseline);
  if (baselines.length === 0) {
    return [];
  }

  const slowestBaseline = Math.max(...baselines.map((r) => r.summary.p50));
  const slowestName = baselines.find((r) => r.summary.p50 === slowestBaseline).scenario;

  return reps
    .filter((r) => !r.baseline && r.summary.p50 < slowestBaseline)
    .map((r) => `CẢNH BÁO: "${r.scenario}" (p50 ${us(r.summary.p50)}µs) nhanh hơn baseline "${slowestName}" (p50 ${us(slowestBaseline)}µs) — nghi đo sai hoặc short-circuit`);
}

export async function writeResults(dir, payload) {
  await mkdir(dir, { recursive: true });
  const path = join(dir, `${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
  await writeFile(path, `${JSON.stringify(payload, null, 2)}\n`);
  return path;
}
```

- [ ] **Step 4: Chạy test để xác nhận pass**

Run: `node --test bench/lib/report.test.js`
Expected: PASS — 5 test.

- [ ] **Step 5: Viết `bench/rep.js`**

```js
import { writeFile } from 'node:fs/promises';
import { cpus, type as osType, release } from 'node:os';
import { parseArgs } from 'node:util';

import { createProvider } from './lib/provider.js';
import { createFixtures } from './lib/fixtures.js';
import { createInprocTransport } from './lib/transport-inproc.js';
import { createHttpTransport } from './lib/transport-http.js';
import { loadScenario } from './lib/scenarios.js';
import { runLoop } from './lib/loop.js';
import { summarize } from './lib/stats.js';

const { values } = parseArgs({
  options: {
    lib: { type: 'string' },
    scenario: { type: 'string' },
    out: { type: 'string' },
    transport: { type: 'string', default: 'http' },
    profile: { type: 'string', default: 'upstream-compatible' },
    iterations: { type: 'string', default: '20000' },
    duration: { type: 'string', default: '10000' },
    'warmup-iterations': { type: 'string', default: '2000' },
    'warmup-ms': { type: 'string', default: '2000' },
    concurrency: { type: 'string', default: '1' },
  },
});

for (const required of ['lib', 'scenario', 'out']) {
  if (!values[required]) {
    throw new Error(`rep.js: thiếu --${required}`);
  }
}

const iterations = Number(values.iterations);
const durationMs = Number(values.duration);
const warmupIterations = Number(values['warmup-iterations']);
const warmupMs = Number(values['warmup-ms']);
const concurrency = Number(values.concurrency);

const { provider, handler, constants, libPath } = await createProvider({
  libPath: values.lib,
  profile: values.profile,
});
const fixtures = await createFixtures({ provider, constants });
const scenario = await loadScenario(values.scenario);

const count = scenario.uniqueItems ? iterations + warmupIterations : 1;
const items = await scenario.prepare({ provider, fixtures, constants, count });

const transport = values.transport === 'inproc'
  ? createInprocTransport({ handler, authority: new URL(constants.issuer).host })
  : await createHttpTransport({ handler, connections: concurrency });

try {
  const result = await runLoop({
    transport, scenario, items,
    iterations, durationMs, warmupIterations, warmupMs, concurrency,
  });

  const payload = {
    scenario: scenario.name,
    title: scenario.title,
    baseline: scenario.baseline === true,
    transport: transport.kind,
    mode: result.mode,
    concurrency: result.concurrency,
    iterations: result.iterations,
    elapsedMs: result.elapsedMs,
    rps: result.rps,
    summary: summarize(result.samplesNs),
    samplesNs: result.samplesNs,
    meta: {
      lib: libPath,
      profile: values.profile,
      node: process.version,
      cpu: cpus()[0]?.model ?? 'unknown',
      os: `${osType()} ${release()}`,
      ts: new Date().toISOString(),
    },
  };

  await writeFile(values.out, `${JSON.stringify(payload)}\n`);
} finally {
  await transport.close();
}
```

Hai điểm cố ý: kết quả ghi ra `--out` chứ không ra stdout (provider in WARNING/NOTICE ra stdout lúc khởi tạo), và pool được đúc `iterations + warmupIterations` item vì warmup cũng tiêu thụ item khi `uniqueItems`.

- [ ] **Step 6: Viết test thất bại cho `run.js --smoke`**

Tạo `bench/run.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';

const exec = promisify(execFile);
const RUN = join(import.meta.dirname, 'run.js');

test('--smoke chạy hết mọi scenario và báo pass', async () => {
  const { stdout } = await exec('node', [RUN, '--smoke'], { timeout: 300_000 });

  assert.match(stdout, /smoke/i);
  assert.match(stdout, /11\/11/);
  assert.doesNotMatch(stdout, /FAIL/);
}, { timeout: 300_000 });

test('sweepLevels: scenario repeatable quét 4 mức, one-shot chỉ 1 mức', async () => {
  const { sweepLevels } = await import('./run.js');

  assert.deepEqual(sweepLevels({ name: 'introspection', uniqueItems: false }), [1, 8, 32, 128]);
  assert.deepEqual(sweepLevels({ name: 'revocation', uniqueItems: true }), [1]);
});

test('scenario không tồn tại thì exit khác 0', async () => {
  await assert.rejects(() => exec('node', [RUN, '--scenario', 'khong-ton-tai', '--reps', '1'], { timeout: 60_000 }));
}, { timeout: 60_000 });
```

- [ ] **Step 7: Chạy test để xác nhận fail**

Run: `node --test bench/run.test.js`
Expected: FAIL — `Cannot find module ... run.js`

- [ ] **Step 8: Viết `bench/run.js`**

```js
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, promisify } from 'node:util';

import { loadScenarios } from './lib/scenarios.js';
import { formatRunTable, baselineWarnings, writeResults } from './lib/report.js';
import { median } from './lib/stats.js';

const exec = promisify(execFile);
const HERE = import.meta.dirname;
const DEFAULT_LIB = join(HERE, '../lib/index.js');

const { values } = parseArgs({
  options: {
    scenario: { type: 'string' },
    transport: { type: 'string', default: 'http' },
    reps: { type: 'string', default: '5' },
    lib: { type: 'string', default: DEFAULT_LIB },
    profile: { type: 'string', default: 'upstream-compatible' },
    concurrency: { type: 'string', default: '1' },
    iterations: { type: 'string', default: '20000' },
    duration: { type: 'string', default: '10000' },
    smoke: { type: 'boolean', default: false },
    sweep: { type: 'boolean', default: false },
    'cpu-prof': { type: 'boolean', default: false },
    'out-dir': { type: 'string', default: join(HERE, 'results') },
  },
});

// Mục đích B (tìm ngưỡng) cần quét concurrency. Nhóm one-shot bị chặn bởi kích
// thước pool nên không có ngưỡng để tìm — chạy một mức và ghi rõ giới hạn.
export function sweepLevels(scenario) {
  return scenario.uniqueItems ? [1] : [1, 8, 32, 128];
}

export async function runRep({ lib, scenario, transport, profile, concurrency, iterations, duration, cpuProf, outDir }) {
  const dir = await mkdtemp(join(tmpdir(), 'bench-rep-'));
  const out = join(dir, 'rep.json');

  const nodeArgs = cpuProf
    ? ['--cpu-prof', '--cpu-prof-dir', join(outDir, 'prof')]
    : [];

  const args = [
    ...nodeArgs,
    join(HERE, 'rep.js'),
    '--lib', lib,
    '--scenario', scenario,
    '--out', out,
    '--transport', transport,
    '--profile', profile,
    '--concurrency', String(concurrency),
    '--iterations', String(iterations),
    '--duration', String(duration),
  ];

  try {
    await exec('node', args, { timeout: 600_000 });
    return JSON.parse(await readFile(out, 'utf8'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function main() {
  const all = await loadScenarios();
  const selected = values.scenario
    ? values.scenario.split(',').map((name) => {
      const found = all.find((s) => s.name === name);
      if (!found) {
        throw new Error(`không có scenario tên "${name}"`);
      }
      return found;
    })
    : all;

  if (values.smoke) {
    let passed = 0;
    for (const scenario of selected) {
      await runRep({
        lib: values.lib, scenario: scenario.name, transport: values.transport,
        profile: values.profile, concurrency: 1,
        iterations: 5, duration: 50, cpuProf: false, outDir: values['out-dir'],
      });
      passed += 1;
      console.log(`smoke ok: ${scenario.name}`);
    }
    console.log(`\nsmoke: ${passed}/${selected.length} scenario pass`);
    return;
  }

  const reps = Number(values.reps);
  const collected = [];

  for (const scenario of selected) {
    const levels = values.sweep ? sweepLevels(scenario) : [Number(values.concurrency)];

    for (const concurrency of levels) {
      const runs = [];
      for (let i = 0; i < reps; i += 1) {
        runs.push(await runRep({
          lib: values.lib, scenario: scenario.name, transport: values.transport,
          profile: values.profile, concurrency,
          iterations: values.iterations, duration: values.duration,
          cpuProf: values['cpu-prof'], outDir: values['out-dir'],
        }));
      }

      const representative = { ...runs[0] };
      representative.summary = { ...runs[0].summary, p50: median(runs.map((r) => r.summary.p50)) };
      representative.rps = median(runs.map((r) => r.rps));
      representative.reps = runs.map((r) => ({ p50: r.summary.p50, p95: r.summary.p95, rps: r.rps }));
      collected.push(representative);
    }

    if (values.sweep && scenario.uniqueItems) {
      console.log(`ghi chú: "${scenario.name}" là one-shot, chỉ chạy concurrency 1 — không có số ngưỡng cho scenario này.`);
    }
  }

  console.log(`\n${formatRunTable(collected)}\n`);
  for (const warning of baselineWarnings(collected)) {
    console.log(warning);
  }

  console.log('\nLƯU Ý: phạm vi cô lập (memory adapter, không app tích hợp) — đây là library ceiling, KHÔNG phải capacity production.');
  const path = await writeResults(values['out-dir'], { kind: 'run', argv: values, results: collected });
  console.log(`kết quả: ${path}`);
}

// Chỉ chạy khi được gọi trực tiếp. Không có guard này thì `import('./run.js')`
// trong test (bài kiểm tra `sweepLevels`) sẽ khởi động cả bộ benchmark.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
```

- [ ] **Step 9: Chạy test để xác nhận pass**

Run: `node --test bench/run.test.js`
Expected: PASS — 3 test. Nếu `--smoke` fail ở một scenario cụ thể, lỗi in ra tên scenario và response nhận được (nhờ `CheckFailedError` của Task 6) — sửa scenario đó, đừng nới `check`.

- [ ] **Step 10: Chạy smoke thật, thử sweep, và lint**

```bash
npm run bench:smoke
npm run bench -- --sweep --scenario introspection --reps 1 --duration 2000
npm run lint
```

Expected: `smoke: 11/11 scenario pass`; lệnh sweep in **bốn dòng** cho
`introspection` (cột `conc` = 1, 8, 32, 128) và cột `rps` tăng theo concurrency
cho tới khi bão hoà. Cột `conc` của `formatRunTable` chính là chỗ đọc kết quả
quét, không cần bảng riêng.

- [ ] **Step 11: Commit**

```bash
git add bench/rep.js bench/run.js bench/run.test.js bench/lib/report.js bench/lib/report.test.js
git commit -m "feat(bench): rep tiến trình con, báo cáo bảng, và run.js với --smoke"
```

---

## Task 10: `compare.js`, `--cpu-prof`, README và nghiệm thu

**Files:**
- Create: `bench/lib/compare.js`
- Create: `bench/lib/compare.test.js`
- Create: `bench/README.md`
- Modify: `bench/run.js` (thêm nhánh `--compare`)

**Interfaces:**
- Consumes: `runRep` (Task 9, đã export sẵn), `median`/`iqr` (Task 2).
- Produces:
  - `export async function resolveSha(rev: string): Promise<string>`
  - `export async function assertDepsMatch(rootA: string, rootB: string): Promise<void>` — ném lỗi nếu khối `dependencies` khác nhau.
  - `export async function withWorktree(sha: string, fn: (worktreePath: string) => Promise<T>): Promise<T>` — thêm worktree `--detach`, dọn trong `finally`.
  - `export function interleavePlan(scenarios: string[], reps: number): Array<{ scenario: string, rep: number, side: 'a' | 'b' }>`
  - `export function compareRows(scenario, repsA, repsB): { scenario, aP50, aIqr, bP50, bIqr, deltaPct, verdict }`
  - `export function formatCompareTable(rows): string`

- [ ] **Step 1: Viết test thất bại**

Tạo `bench/lib/compare.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { resolveSha, interleavePlan, compareRows, formatCompareTable, assertDepsMatch, withWorktree } from './compare.js';

test('resolveSha trả sha 40 ký tự cho HEAD', async () => {
  assert.match(await resolveSha('HEAD'), /^[0-9a-f]{40}$/);
});

test('resolveSha báo lỗi với revision không tồn tại', async () => {
  await assert.rejects(() => resolveSha('khong-phai-revision-nao-ca'));
});

test('interleavePlan xen kẽ a,b,a,b cho từng scenario', () => {
  const plan = interleavePlan(['x', 'y'], 2);

  assert.deepEqual(plan, [
    { scenario: 'x', rep: 0, side: 'a' },
    { scenario: 'x', rep: 0, side: 'b' },
    { scenario: 'x', rep: 1, side: 'a' },
    { scenario: 'x', rep: 1, side: 'b' },
    { scenario: 'y', rep: 0, side: 'a' },
    { scenario: 'y', rep: 0, side: 'b' },
    { scenario: 'y', rep: 1, side: 'a' },
    { scenario: 'y', rep: 1, side: 'b' },
  ]);
});

test('compareRows: delta nhỏ hơn dải nhiễu thì kết luận "nhiễu"', () => {
  const row = compareRows('x', [100, 110, 90, 105, 95], [102, 112, 92, 107, 97]);

  assert.equal(row.scenario, 'x');
  assert.equal(row.verdict, 'nhiễu');
});

test('compareRows: delta lớn hơn dải nhiễu thì kết luận "khác biệt"', () => {
  const row = compareRows('x', [100, 100, 100, 100, 100], [200, 200, 200, 200, 200]);

  assert.equal(row.verdict, 'khác biệt');
  assert.ok(row.deltaPct > 90 && row.deltaPct < 110, `deltaPct=${row.deltaPct}`);
});

test('compareRows: delta âm khi b nhanh hơn a', () => {
  const row = compareRows('x', [200, 200, 200, 200, 200], [100, 100, 100, 100, 100]);
  assert.ok(row.deltaPct < 0);
});

test('formatCompareTable in tên scenario, delta và verdict', () => {
  const table = formatCompareTable([compareRows('x', [100, 100, 100], [100, 100, 100])]);

  assert.match(table, /x/);
  assert.match(table, /nhiễu/);
});

test('assertDepsMatch: repo so với chính nó thì không ném lỗi', async () => {
  const root = new URL('../../', import.meta.url).pathname;
  await assertDepsMatch(root, root);
});

test('withWorktree: tạo worktree cho HEAD rồi dọn sạch', async () => {
  const sha = await resolveSha('HEAD');
  let seen;

  await withWorktree(sha, async (path) => {
    seen = path;
    assert.ok(existsSync(join(path, 'lib/index.js')), 'worktree phải có lib/index.js');
  });

  assert.ok(!existsSync(seen), 'worktree phải được dọn');
});
```

- [ ] **Step 2: Chạy test để xác nhận fail**

Run: `node --test bench/lib/compare.test.js`
Expected: FAIL — `Cannot find module ... compare.js`

- [ ] **Step 3: Viết `bench/lib/compare.js`**

```js
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { median, iqr } from './stats.js';

const exec = promisify(execFile);
const REPO = join(import.meta.dirname, '../..');
const WORKTREES = join(REPO, 'bench/.worktrees');

export async function resolveSha(rev) {
  const { stdout } = await exec('git', ['rev-parse', '--verify', `${rev}^{commit}`], { cwd: REPO });
  return stdout.trim();
}

export async function assertDepsMatch(rootA, rootB) {
  const read = async (root) => JSON.parse(await readFile(join(root, 'package.json'), 'utf8')).dependencies ?? {};
  const [a, b] = await Promise.all([read(rootA), read(rootB)]);

  if (JSON.stringify(a) !== JSON.stringify(b)) {
    throw new Error(
      'khối "dependencies" của hai revision khác nhau — chạy `npm install` trong worktree trước khi so, '
      + `nếu không sẽ đo với version dependency sai.\nA: ${JSON.stringify(a)}\nB: ${JSON.stringify(b)}`,
    );
  }
}

export async function withWorktree(sha, fn) {
  const path = join(WORKTREES, sha);

  // --detach là bắt buộc: không có nó thì `--compare HEAD` và so với một nhánh
  // đang checkout đều bị git từ chối.
  await exec('git', ['worktree', 'add', '--detach', path, sha], { cwd: REPO });

  try {
    return await fn(path);
  } finally {
    await exec('git', ['worktree', 'remove', '--force', path], { cwd: REPO });
  }
}

export function interleavePlan(scenarios, reps) {
  const plan = [];
  for (const scenario of scenarios) {
    for (let rep = 0; rep < reps; rep += 1) {
      plan.push({ scenario, rep, side: 'a' });
      plan.push({ scenario, rep, side: 'b' });
    }
  }
  return plan;
}

export function compareRows(scenario, p50sA, p50sB) {
  const aP50 = median(p50sA);
  const bP50 = median(p50sB);
  const aIqr = iqr(p50sA).iqr;
  const bIqr = iqr(p50sB).iqr;

  const deltaPct = ((bP50 - aP50) / aP50) * 100;
  const noiseBandPct = Math.max((aIqr / aP50) * 100, (bIqr / bP50) * 100);

  return {
    scenario,
    aP50,
    aIqr,
    bP50,
    bIqr,
    deltaPct,
    noiseBandPct,
    verdict: Math.abs(deltaPct) <= noiseBandPct ? 'nhiễu' : 'khác biệt',
  };
}

export function formatCompareTable(rows) {
  const us = (ns) => (ns / 1000).toFixed(1);
  const header = ['scenario', 'A p50 µs', 'A IQR µs', 'B p50 µs', 'B IQR µs', 'Δ%', 'dải nhiễu %', 'kết luận'];
  const body = rows.map((r) => [
    r.scenario, us(r.aP50), us(r.aIqr), us(r.bP50), us(r.bIqr),
    r.deltaPct.toFixed(1), r.noiseBandPct.toFixed(1), r.verdict,
  ]);

  const widths = header.map((h, i) => Math.max(h.length, ...body.map((row) => row[i].length)));
  const line = (cells) => cells.map((c, i) => c.padEnd(widths[i])).join('  ').trimEnd();

  return [
    line(header),
    line(widths.map((w) => '-'.repeat(w))),
    ...body.map(line),
    '',
    'Quy tắc đọc: |Δ| nhỏ hơn dải nhiễu thì KHÔNG gọi là hồi quy.',
  ].join('\n');
}
```

- [ ] **Step 4: Chạy test để xác nhận pass**

Run: `node --test bench/lib/compare.test.js`
Expected: PASS — 9 test.

- [ ] **Step 5: Thêm nhánh `--compare` vào `bench/run.js`**

Thêm `compare: { type: 'string' }` vào `options` của `parseArgs`, và chèn khối sau vào `main()` ngay trước khối `if (values.smoke)`:

```js
  if (values.compare) {
    const sha = await resolveSha(values.compare);
    const headSha = await resolveSha('HEAD');

    await withWorktree(sha, async (worktree) => {
      await assertDepsMatch(join(HERE, '..'), worktree);

      const plan = interleavePlan(selected.map((s) => s.name), Number(values.reps));
      const collected = { a: {}, b: {} };

      for (const { scenario, side } of plan) {
        const lib = side === 'a' ? values.lib : join(worktree, 'lib/index.js');
        const rep = await runRep({
          lib, scenario, transport: values.transport, profile: values.profile,
          concurrency: values.concurrency, iterations: values.iterations,
          duration: values.duration, cpuProf: false, outDir: values['out-dir'],
        });
        (collected[side][scenario] ??= []).push(rep);
      }

      const rows = selected.map((s) => compareRows(
        s.name,
        collected.a[s.name].map((r) => r.summary.p50),
        collected.b[s.name].map((r) => r.summary.p50),
      ));

      console.log(`\nA = HEAD (${headSha.slice(0, 8)})   B = ${values.compare} (${sha.slice(0, 8)})\n`);
      console.log(formatCompareTable(rows));
      console.log('\nLƯU Ý: phạm vi cô lập — library ceiling, KHÔNG phải capacity production.');

      const path = await writeResults(values['out-dir'], {
        kind: 'compare',
        a: { rev: 'HEAD', sha: headSha },
        b: { rev: values.compare, sha },
        argv: values,
        rows,
        raw: collected,
      });
      console.log(`kết quả: ${path}`);
    });

    return;
  }
```

Thêm import: `import { resolveSha, assertDepsMatch, withWorktree, interleavePlan, compareRows, formatCompareTable } from './lib/compare.js';`

- [ ] **Step 6: Chạy bài tự kiểm tra cơ chế so sánh**

```bash
node bench/run.js --compare HEAD --reps 3 --scenario discovery,introspection --duration 3000
```

Expected: bảng in ra với cột `kết luận` = `nhiễu` cho **cả hai** scenario, và `|Δ%|` nhỏ hơn dải nhiễu. Nếu ra `khác biệt` khi so HEAD với chính nó thì cơ chế so sánh sai (thứ tự xen kẽ, hoặc worktree resolve sang `node_modules` khác), không phải code chậm — phải sửa trước khi đi tiếp.

- [ ] **Step 7: Chạy so thật với upstream**

```bash
git fetch origin main
node bench/run.js --compare origin/main --reps 3 --duration 3000
```

Expected: chạy trọn, in bảng 11 dòng. Nếu `assertDepsMatch` chặn lại thì đó là hành vi đúng — chạy `npm install` trong `bench/.worktrees/<sha>` rồi chạy lại, và ghi việc đó vào README.

- [ ] **Step 8: Sinh một cpuprofile**

```bash
node bench/run.js --scenario full-authorization --transport inproc --reps 1 --cpu-prof --iterations 2000
ls bench/results/prof/*.cpuprofile
```

Expected: có ít nhất một file `.cpuprofile`. Mở được bằng Chrome DevTools (Performance → Load profile) hoặc speedscope.

- [ ] **Step 9: Viết `bench/README.md`**

````markdown
# bench — harness đo hiệu năng lib/

Thiết kế: `docs/superpowers/specs/2026-09-07-benchmark-harness-design.md`

## Đọc số này thế nào

Phạm vi đo là **chỉ thư viện, cô lập**: memory adapter, account và interaction
đúc sẵn, không DB, không app tích hợp, không render view thật.

**Số ở đây là library ceiling, KHÔNG phải capacity production.** Nó thiếu I/O của
adapter thật và chi phí render view của app. Đừng dùng để tính số pod hay số máy.

Trong scenario `full-authorization`, interaction là đúc sẵn chứ không đến từ một
lần login thật — trang login thuộc app tích hợp, không thuộc thư viện. Mọi chặng
khác trong chuỗi là đường thật, kể cả authorization code được truyền từ bước
resume sang bước đổi token.

## Lệnh

```bash
npm run bench:smoke                  # 11 scenario × 5 vòng, xác nhận không đo đường lỗi
npm run bench:test                   # test đơn vị của harness
npm run bench                        # chạy đủ, transport http, 5 rep
npm run bench -- --scenario introspection --transport inproc
npm run bench -- --sweep                 # quét concurrency 1/8/32/128 (mục đích B)
npm run bench -- --compare origin/main --reps 5
npm run bench -- --compare HEAD      # tự kiểm tra: mọi dòng phải ra "nhiễu"
npm run bench -- --scenario full-authorization --transport inproc --cpu-prof --reps 1
```

## Tìm ngưỡng (mục đích B)

`--sweep` chạy mỗi scenario repeatable ở concurrency 1, 8, 32, 128; đọc cột `conc`
và `rps` để thấy điểm bão hoà. Scenario one-shot (`auth-resume`,
`token-authorization-code`, `full-authorization`, `revocation`) chỉ chạy ở
concurrency 1 vì kích thước pool chặn số vòng — với nhóm này không có số ngưỡng,
và `run.js` in ghi chú nói rõ điều đó thay vì đưa ra một con số vô căn cứ.

## Quy tắc đọc bảng so sánh

`|Δ%|` nhỏ hơn cột `dải nhiễu %` thì **không** gọi là hồi quy. Dải nhiễu là IQR
của tập p50-các-rep, chia cho p50 median. Không có gate CI: chưa có dữ liệu nhiễu
thực tế thì đặt ngưỡng chỉ là đoán.

## Bốn cơ chế chống đo sai

1. `npm run bench:smoke` — mọi `check` phải pass. Đo nhầm đường lỗi cho ra số
   *đẹp* (401 rẻ hơn 200 nhiều), nên đây là lá chắn chính.
2. `--compare HEAD` — phải ra "nhiễu" trên mọi dòng. Sai là cơ chế so sánh hỏng.
3. Bất biến thứ tự — không endpoint giao thức nào được nhanh hơn `discovery`.
   `run.js` in CẢNH BÁO nếu vi phạm.
4. `npm run bench:test` — test đơn vị, gồm cả bài hai transport trả cùng kết quả.

## Nếu so sánh bị chặn vì lệch dependencies

`assertDepsMatch` dừng khi khối `dependencies` của hai revision khác nhau. Xử lý:

```bash
npm install --prefix bench/.worktrees/<sha>
```

rồi chạy lại. Đừng bỏ qua kiểm tra này — đo với version `jose` hoặc `koa` khác
nhau thì con số không so được.

## Thêm scenario

Thêm một file vào `bench/scenarios/`, `export default` một object (hoặc mảng
object) gồm `name`, `title`, `mode`, `uniqueItems`, `prepare`, `steps`, `check`.
`loadScenarios()` tự nhặt. Không sửa `loop.js`.

Ba ràng buộc:
- `check` phải chặt. Một scenario đo đường lỗi mà `check` lỏng là số sai âm thầm.
- `mode: 'fixed-duration'` không dùng được với `uniqueItems: true` — pool không
  chặn được số vòng. `loop.js` ném lỗi nếu khai vậy.
- Chỉ dùng API công khai của provider. Harness phải chạy được trên `origin/main`.
````

- [ ] **Step 10: Nghiệm thu toàn bộ theo §11 của spec**

```bash
npm run bench:smoke            # mong: smoke: 11/11 scenario pass
npm run bench:test             # mong: toàn bộ test pass
npm run lint                   # mong: không thêm cảnh báo mới
npm test                       # mong: suite OIDC không bị ảnh hưởng
node bench/run.js --compare HEAD --reps 3 --duration 3000    # mong: mọi dòng "nhiễu"
```

Ghi lại output của từng lệnh. Nếu bất kỳ lệnh nào không đạt, sửa trước khi commit — đây là tiêu chí hoàn thành, không phải khuyến nghị.

- [ ] **Step 11: Commit**

```bash
git add bench/lib/compare.js bench/lib/compare.test.js bench/run.js bench/README.md
git commit -m "feat(bench): so hai revision bằng worktree xen kẽ, chế độ cpu-prof, và README"
```

---

## Ước lượng thời gian chạy

Với mặc định (11 scenario, 5 rep, 10 giây mỗi rep fixed-duration / 20 000 vòng mỗi rep fixed-iterations, một transport):

- `npm run bench` — khoảng 10–15 phút.
- `npm run bench -- --compare origin/main` — khoảng gấp đôi, 20–30 phút.
- `npm run bench -- --sweep` — khoảng 4 lần lâu hơn trên nhóm repeatable, tầm 30–40 phút.
- `npm run bench:smoke` — dưới một phút.

Muốn nhanh hơn khi đang phát triển: `--reps 1 --duration 2000 --iterations 2000`. Số đó **không** dùng để kết luận hồi quy, chỉ để kiểm tra harness còn chạy.
