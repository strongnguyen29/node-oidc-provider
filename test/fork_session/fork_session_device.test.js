const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('fork: session picks up ctx.req.deviceId', () => {
  // Tham số thứ hai của bootstrap là object { config }, KHÔNG phải string.
  // Truyền string thì destructuring rơi về default path.basename(dir) và nạp
  // lặng lẽ sai config (fork_session thay vì fork_session_device).
  before(bootstrap(__dirname, { config: 'fork_session_device' }));

  before(function () {
    // Phải là provider.use(), KHÔNG phải provider.app.use(). provider.use()
    // splice middleware vào TRƯỚC middleware nội bộ (lib/provider.js:347, mốc
    // firstInternal ở initialize_app.js:242), nên ctx.req.deviceId được đặt
    // trước khi Session.get(ctx) đọc. app.use() append vào cuối stack nên chạy
    // sau session middleware — quá muộn, patch sẽ không thấy gì.
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
