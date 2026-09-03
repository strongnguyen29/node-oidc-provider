import { expect } from 'chai';

import bootstrap from '../test_helper.js';

/*
 * Cổng xác minh cho quyết định BỎ patch client_schema của fork (spec §4.1).
 *
 * Patch v7 nới một `invalidate()` để client khai response_types ['id_token'|'token']
 * với grant type ngoài chuẩn không bị từ chối. v9 đổi hẳn cơ chế: không invalidate
 * nữa mà tự `grant_types.push('implicit')` (lib/helpers/client_schema.js:313-315).
 *
 * Câu hỏi chặn: việc `implicit` bị tự thêm có mở luồng implicit mà fork không muốn?
 *
 * ĐÃ ĐO trên cả hai nhánh (2026-09-03) — câu trả lời là KHÔNG:
 *
 *   v7 (có patch): grantTypes ["password"],                      /auth -> 303 + id_token
 *   v9 (bỏ patch): grantTypes ["urn:fork:password","implicit"],  /auth -> 303 + id_token
 *
 * Hành vi đầu-cuối giống nhau. Lý do: cả hai phiên bản gác authorization endpoint
 * bằng `client.responseTypeAllowed(...)` trong check_response_type.js — tức bằng
 * `response_types`, KHÔNG bằng `grant_types`. `check_client_grant_type.js` chỉ áp
 * cho device_authorization và backchannel_authentication, không áp cho /auth.
 *
 * Việc `implicit` xuất hiện trong grantTypes là thay đổi HÌNH THỨC: `implicit`
 * không có handler ở token endpoint, nên `grantTypeAllowed('implicit')` không mở
 * thêm đường nào. Nó chỉ hiện ra trong metadata client đọc lại.
 *
 * Khác biệt duy nhất theo chiều nới lỏng: v7 chỉ chấp nhận đúng năm tên nguyên văn
 * trong allow-list của patch (implicit/password/social/telco/fast_login), nên client
 * khai 'urn:fork:password' + id_token bị v7 TỪ CHỐI mà v9 chấp nhận. Với các cấu
 * hình fork thực dùng (năm tên trên) thì hành vi trùng khớp.
 *
 * Test này tồn tại lâu dài: nếu lần sync upstream sau đổi hành vi trên, nó đỏ.
 */
describe('fork: dropping the client_schema grant_types patch', () => {
  before(bootstrap(import.meta.url));

  before(function () {
    this.provider.registerGrantType(
      'urn:fork:password',
      async (ctx) => { ctx.body = { ok: true }; },
    );
  });

  it('auto-adds implicit to grant_types instead of rejecting the client', async function () {
    const client = await this.provider.Client.find('client-nonstandard-grant');
    expect(client).to.exist;
    expect(client.grantTypes).to.include('urn:fork:password');
    expect(client.grantTypes).to.include('implicit');
    expect(client.responseTypes).to.deep.equal(['id_token']);
  });

  it('issues an id_token for that client, exactly as the v7 fork did', async function () {
    await this.login();

    const auth = new this.AuthorizationRequest({
      client_id: 'client-nonstandard-grant',
      response_type: 'id_token',
      scope: 'openid',
    });

    await this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect(303)
      .expect((response) => {
        expect(response.headers.location).to.match(/#.*id_token=/);
      });
  });

  it('does not make implicit usable at the token endpoint', async function () {
    await this.agent.post('/token')
      .auth('client-nonstandard-grant', 'secret')
      .send({ grant_type: 'implicit' })
      .type('form')
      .expect(400)
      .expect((response) => {
        expect(response.body).to.have.property('error', 'unsupported_grant_type');
      });
  });
});
