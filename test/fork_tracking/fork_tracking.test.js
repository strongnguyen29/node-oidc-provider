import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('fork: trackingAction and the refresh_token event', () => {
  before(bootstrap(import.meta.url));

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

  // Bắt ctx qua event thay vì assertOnce: event là thứ đang cần kiểm.
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

  it('falls through to "login" concatenated with amr for any other string amr', async function () {
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
