import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('fork: session picks up ctx.req.deviceId', () => {
  // Tham số thứ hai của bootstrap là object { config }, không phải string —
  // truyền string sẽ lặng lẽ nạp sai config. Xem kết luận Task 8 Step 1.
  before(bootstrap(import.meta.url, { config: 'fork_session_device' }));

  before(function () {
    // Phải là provider.use(), KHÔNG phải app.use(). provider.use() splice
    // middleware vào TRƯỚC middleware nội bộ nên ctx.req.deviceId được đặt
    // trước khi Session.get(ctx) đọc; app.use() append vào cuối stack nên chạy
    // sau session middleware và patch sẽ không thấy gì. Đã kiểm bằng thực
    // nghiệm trên v7 (Task 3): app.use() làm test này đỏ.
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
