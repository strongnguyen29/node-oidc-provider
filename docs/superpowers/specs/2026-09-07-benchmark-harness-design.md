# Harness benchmark cho luồng authorization code, token và introspection

Ngày: 2026-09-07
Trạng thái: đã duyệt thiết kế, chờ viết kế hoạch triển khai

## 1. Mục tiêu

Dựng một harness đo hiệu năng cho `lib/`, phục vụ ba mục đích:

- **A. Chống hồi quy** — trả lời "commit này chậm hơn commit kia bao nhiêu", và
  "fork chậm hơn `origin/main` bao nhiêu".
- **B. Trần lý thuyết** — trả lời "một tiến trình cấp được bao nhiêu uỷ quyền
  mỗi giây, p95 bao nhiêu".
- **C. Tìm điểm nghẽn** — cho ra `.cpuprofile` của từng chặng trong luồng.

Phạm vi đo là **chỉ thư viện, cô lập**: `memory_adapter`, account/interaction
đúc sẵn, không DB, không app tích hợp, không render view thật.

**Giới hạn phải ghi rõ trong mọi báo cáo:** vì phạm vi cô lập, số của mục đích B
là *trần lý thuyết của thư viện* (library ceiling), **không** phải capacity
production. Nó thiếu I/O của adapter thật và chi phí render view của app. Không
dùng số này để tính số pod hay số máy.

Không thuộc phạm vi vòng đầu: đo end-to-end qua app tích hợp, gate CI, so sánh
cấu hình (opaque vs JWT access token, có/không DPoP), biến thể client auth
(`private_key_jwt`).

## 2. Phạm vi scenario

Mười scenario, đối chiếu route thực tế trong `lib/helpers/initialize_app.js`:

| # | Scenario | Đo cái gì |
|---|---|---|
| 1 | `GET /auth`, chưa có session | parse + validate + tạo Interaction |
| 2 | `GET /auth/:uid` (resume), đã có session/grant | phần cấp authorization code |
| 3 | `POST /token` `grant_type=authorization_code` | cấp access token + id_token |
| 4 | `POST /token` `grant_type=refresh_token` | tra cứu refresh token + cấp access token mới |
| 5 | `POST /token` `grant_type=client_credentials` | đường cấp token ngắn nhất, không có account |
| 6 | `POST /token/introspection` | tra token + dựng payload introspection |
| 7 | Chuỗi 1→2→3 tính một "authorization" | số trả lời "bao nhiêu uỷ quyền/giây" |
| 8 | `GET /me` (userinfo) | xác thực bearer + lắp claims |
| 9 | `POST /token/revocation` | tra token + thu hồi (ghi adapter) |
| 10 | `GET /.well-known/openid-configuration` và `GET /jwks` | baseline route rẻ nhất |

Scenario 10 tồn tại để tách chi phí Koa/router ra khỏi chi phí logic: mọi số
khác đọc được là nhờ có nó làm mốc dưới. Nó là **hai phép đo riêng** trong cùng
một file (`discovery` và `jwks`), báo cáo thành hai dòng; bất biến ở §10.3 dùng
dòng `discovery`.

## 3. Cấu hình provider dưới phép đo

Một profile duy nhất: `bench/profiles/upstream-compatible.js`.

Ràng buộc cứng — profile **không được** chứa key riêng của fork
(`grantTypeParamsDefault`, `cookies.prefix`, `userinfoRequiredScopes`,
`features.introspection.strictTokenTypeHint`, ...). `lib/helpers/configuration.js`
chạy `pick(config, ...Object.keys(defaults))`, nên trên `origin/main` các key này
bị drop âm thầm hoặc bị reject; cả hai đều làm phép so sánh vô nghĩa. Profile
phải là tập con hợp lệ trên mọi revision được so.

Nội dung: access token opaque (mặc định), client confidential
`client_secret_basic`, bật ba feature mà scenario cần — `features.introspection`,
`features.revocation`, `features.clientCredentials`, cả ba mặc định `enabled: false`
— không DPoP/PAR/JAR, và **tắt tường minh** `features.resourceIndicators`
(feature này mặc định `enabled: true`, nên phải ghi `{ enabled: false }`, không
được bỏ trống).

Profile là file rời để thêm profile khác về sau (ví dụ "fork-like" hay "JWT
access token") chỉ là thêm một file, không sửa harness.

## 4. Bố cục

```
bench/
  run.js                   CLI: --scenario, --runner http|inproc, --compare <rev>,
                           --profile, --smoke, --cpu-prof
  rep.js                   chạy MỘT rep trong tiến trình con, in JSON ra stdout
  self-test.js             kiểm tra stats + fixture
  lib/
    provider.js            dựng provider từ profile, import lib/index.js theo đường dẫn
    fixtures.js            đúc account/client/session/grant/code/refresh token
    runner-http.js         node:http + undici Pool, có concurrency
    runner-inproc.js       gọi provider.callback() với req/res giả
    stats.js               p50/p95/p99, RPS, trim outlier
    report.js              bảng console + JSON
    compare.js             worktree, chạy xen kẽ, bảng lệch
  profiles/upstream-compatible.js
  scenarios/01-auth-new.js … 10-discovery.js
  results/                 gitignored
  .worktrees/              gitignored
```

Không sửa gì trong `lib/` và `test/`. `package.json` đã khai `files: ["lib"]`
nên `bench/` không lên npm. Thêm hai script: `bench`, `bench:smoke`. Biome lint
phủ `bench/` theo cấu hình sẵn có.

## 5. Hai quyết định kiến trúc cốt lõi

### 5.1 Driver nhận đường dẫn `lib/`, không import cứng

Driver **không** `import '../lib/index.js'`. Nó nhận `--lib <path>` và
`import(pathToFileURL(path))`. Nhờ vậy code đo (luôn ở `HEAD`) tách rời hẳn code
bị đo, và cùng một driver đo được `lib/` của bất kỳ revision nào đã checkout.

### 5.2 Một rep = một tiến trình con

`rep.js` chạy đúng một tổ hợp (scenario × runner × lib) rồi chết. Ba lý do, cả
ba đều làm số sai nếu không tách:

- `memory_adapter` là `Map` trong tiến trình. Chạy liên tục vài phút thì store
  phình lên hàng trăm nghìn bản ghi; GC và áp lực bộ nhớ làm số trôi dần *trong
  lúc* đo.
- Không thể tin việc nạp hai bản `lib/` khác nhau vào cùng một tiến trình —
  module state, weak cache, và JIT đã tối ưu theo shape của bản kia.
- Trạng thái JIT của revision A làm nóng hoặc nguội revision B, đúng thứ thiên
  lệch mà việc chạy xen kẽ đang cố loại bỏ.

Phần thưởng kèm theo: chế độ profiling (§8) chỉ là thêm cờ vào lệnh spawn.

## 6. Hợp đồng scenario

Mỗi scenario là một module:

```js
export default {
  name: 'token-authorization-code',
  mode: 'fixed-iterations',            // hoặc 'fixed-duration'
  async prepare({ provider, fixtures, count }) { /* đúc pool → mảng descriptor */ },
  request(item) { return { method: 'POST', path: '/token', headers, body }; },
  check(res) { /* 200 + có access_token; sai thì abort rep */ },
};
```

`request` trả về **dữ liệu thuần**, nên `runner-http` và `runner-inproc` dùng
chung một định nghĩa scenario.

`check` là bắt buộc, không phải trang trí. Benchmark đo nhầm đường lỗi là dạng
sai phổ biến nhất và khó phát hiện nhất, vì đường lỗi *nhanh hơn* nhiều (401 do
client auth sai rẻ hơn hẳn 200 có cấp token) nên kết quả trông rất đẹp. `check`
fail một lần là abort rep, exit khác 0, in ra response đã nhận.

Việc đúc pool nằm **ngoài** vùng đo, dùng đúng API công khai mà
`test/test_helper.js:188-250` đang dùng: `new provider.Session(...)`,
`new provider.Grant(...)`, `new provider.AuthorizationCode(...).save()`.

## 7. One-shot vs repeatable

Phân loại này quyết định số đúng hay sai:

| Scenario | Loại | Lý do |
|---|---|---|
| 2, 3, 9 | one-shot, `fixed-iterations`, cần pool đúc trước | code và interaction dùng một lần rồi bị thu hồi |
| 4 | repeatable, `fixed-duration` | client confidential + `rotateRefreshToken` mặc định ⇒ không rotate, dùng lại được cùng một refresh token |
| 5, 6, 8, 10 | repeatable, `fixed-duration` | không tiêu thụ artifact đầu vào |
| 1, 7 | `fixed-iterations` | không cần pool, nhưng *sinh* bản ghi mới mỗi vòng ⇒ phải chặn số vòng để store tăng có kiểm soát |

Cho mục đích B, runner `http` quét concurrency 1 / 8 / 32 / 128 trên nhóm
repeatable. Nhóm one-shot bị chặn bởi kích thước pool nên chỉ chạy một mức
concurrency cố định; báo cáo ghi rõ giới hạn này thay vì đưa ra một con số
ngưỡng không có cơ sở.

Tham số mặc định (đều override được qua CLI):

- `fixed-iterations`: N = 20 000 vòng đo, warmup 2 000 vòng. Scenario one-shot đúc
  pool cỡ N + warmup, mint một lần cho mỗi rep, ngoài vùng đo.
- `fixed-duration`: 10 giây đo, warmup 2 giây.
- 5 rep mỗi revision.

Mỗi rep có warmup riêng; số vòng warmup bị loại khỏi thống kê.

## 8. So hai revision và báo cáo

`compare.js` nhận `--compare <rev>`, mặc định `origin/main`:

1. `git worktree add --detach bench/.worktrees/<sha> <rev>`. Bắt buộc `--detach`:
   không có nó thì `--compare HEAD` (bài tự kiểm tra ở §10.2) và `--compare` tới
   một nhánh đang checkout sẽ bị git từ chối. Đặt worktree **bên trong**
   repo là có chủ ý: Node resolve `koa`/`jose`/`debug` bằng cách đi ngược lên cây
   thư mục, nên `bench/.worktrees/<sha>/lib/index.js` tìm thấy `node_modules` của
   repo chính và khỏi phải `npm install` lại.
2. Trước khi chạy, so khối `dependencies` của hai `package.json`. Lệch thì **dừng**
   và báo phải `npm install` trong worktree — không âm thầm đo với version
   dependency sai.
3. Chạy xen kẽ `A,B,A,B,…`, mặc định 5 rep mỗi bên, mỗi rep một tiến trình con.
4. Báo cáo in: median mỗi bên, **độ phân tán giữa các rep của chính bên đó**, rồi
   mới tới delta%. "Độ phân tán" định nghĩa cụ thể là khoảng liên tứ phân vị (IQR)
   của tập median-các-rep của bên đó, in kèm min–max.

Cột phân tán là thứ duy nhất cho phép đọc delta. Quy tắc ghi trong báo cáo:
**delta nhỏ hơn độ phân tán nội bộ thì không gọi là hồi quy.** Không có gate tự
động — chưa biết độ nhiễu thực tế của từng scenario thì đặt ngưỡng là đoán bừa.
Sau vài tuần có dữ liệu nhiễu mới bàn tới gate.

JSON ghi ra `bench/results/` giữ **mẫu thô**, không chỉ số tổng hợp, kèm
metadata: sha hai revision, phiên bản Node, model CPU, tên profile. Thiếu
metadata thì file kết quả cũ vô giá trị sau vài tháng.

Xử lý lỗi: `check` fail hoặc rep crash → abort, exit khác 0. Worktree dọn trong
`finally`. HTTP server bind port 0.

## 9. Chế độ profiling (mục đích C)

`--cpu-prof` thêm cờ vào lệnh spawn `rep.js`:
`node --cpu-prof --cpu-prof-dir bench/results/prof`. File `.cpuprofile` mở bằng
Chrome DevTools hoặc speedscope.

Mặc định của chế độ này là runner `inproc`, concurrency 1, một rep — bỏ socket
và HTTP parse ra khỏi flamegraph thì phần `lib/` mới nổi lên rõ.

## 10. Tự kiểm tra harness

Một benchmark sai âm thầm tệ hơn không có benchmark. Bốn cơ chế:

1. **`npm run bench:smoke`** — chạy cả 10 scenario với N=5, khẳng định mọi
   `check` pass. Vài giây. Đây là lá chắn chính chống đo nhầm đường lỗi.
2. **`npm run bench -- --compare HEAD`** — so HEAD với chính nó, delta phải ≈ 0. Kiểm tra toàn bộ
   đường ống worktree + xen kẽ + gộp số: nếu ra 8% thì cơ chế so sánh sai, không
   phải code chậm.
3. **Bất biến thứ tự** — scenario 10 phải nhanh nhất trong tất cả. Endpoint giao
   thức nào đo ra nhanh hơn discovery là dấu hiệu short-circuit hoặc đo sai;
   report in cảnh báo.
4. **`node bench/self-test.js`** — assert `stats.js` trên input đã biết (p95 của
   1..100 = 95) và assert pool fixture đúc ra artifact dùng được. Không nhét vào
   `test/run.js`: bộ đó là suite OIDC, thêm vào chỉ làm `npm test` chậm mà không
   liên quan.

## 11. Tiêu chí hoàn thành

- `npm run bench:smoke` xanh: 10/10 scenario, mọi `check` pass.
- `node bench/self-test.js` xanh.
- `bench/run.js --compare HEAD` cho delta trong khoảng nhiễu (≈0%) trên cả 10
  scenario.
- `bench/run.js --compare origin/main` chạy trọn và in bảng so sánh
  fork vs upstream.
- Một `.cpuprofile` sinh ra được và mở được cho scenario 7.
- `npm run lint` không thêm cảnh báo mới.
- `npm test` không bị ảnh hưởng.
