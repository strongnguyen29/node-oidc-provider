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

  cases.forEach(([kind, hint, active]) => {
    const label = hint === undefined ? 'no hint' : `hint "${hint}"`;
    it(`${kind} with ${label} -> active ${active}`, async function () {
      const token = await mint(this, kind);
      await introspect(this.agent, token, hint)
        .expect((response) => {
          expect(response.body).to.have.property('active', active);
        });
    });
  });
});
