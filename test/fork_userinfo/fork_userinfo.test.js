import { expect } from 'chai';

import bootstrap from '../test_helper.js';

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

describe('fork: userinfo accepts api_profile_get as well as openid', () => {
  before(bootstrap(import.meta.url));

  it('accepts a token scoped openid only', async function () {
    const token = await mintAccessToken(this, 'openid');
    await this.agent.get('/me')
      .auth(token, { type: 'bearer' })
      .expect(200)
      .expect((response) => { expect(response.body).to.have.property('sub', 'accountId'); });
  });

  // Hành vi thật, chốt ở Task 5 trên nhánh v7: token chỉ có api_profile_get ĐI
  // QUA được cửa scope (200) nhưng body rỗng. Cửa scope là afterFind, còn claims
  // vẫn bị `mask.scope(scope)` lọc theo OIDC scope, mà api_profile_get không mang
  // claim OIDC nào — nên Claims.result() trả {}. Kể cả `sub` cũng không có, vì
  // `sub` chỉ đi kèm scope openid.
  //
  // Nói cách khác: config này mở cửa nhưng không làm /me trả profile. Đây là
  // hành vi production đang chạy, không phải lỗi để sửa ở bước port.
  it('lets an api_profile_get-only token through but responds with an empty body', async function () {
    const token = await mintAccessToken(this, 'api_profile_get');
    await this.agent.get('/me')
      .auth(token, { type: 'bearer' })
      .expect(200)
      .expect((response) => {
        expect(response.body).to.deep.equal({});
      });
  });

  it('returns sub when the token also carries openid', async function () {
    const token = await mintAccessToken(this, 'openid api_profile_get');
    await this.agent.get('/me')
      .auth(token, { type: 'bearer' })
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('sub', 'accountId');
      });
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

// Nhánh mặc định — mọi deployment upstream chạy nhánh này, phải giống upstream
// từng chữ. Config phụ cùng thư mục, xem kết luận Task 8 Step 1.
describe('fork: userinfoRequiredScopes left at its default', () => {
  before(bootstrap(import.meta.url, { config: 'fork_userinfo_default' }));

  it('accepts openid', async function () {
    const token = await mintAccessToken(this, 'openid');
    await this.agent.get('/me').auth(token, { type: 'bearer' }).expect(200);
  });

  it('rejects api_profile_get, unlike the configured suite above', async function () {
    const token = await mintAccessToken(this, 'api_profile_get');
    await this.agent.get('/me')
      .auth(token, { type: 'bearer' })
      .expect(403)
      .expect((response) => {
        expect(response.body).to.have.property('error', 'insufficient_scope');
      });
  });

  it('reproduces the upstream error message and scope hint verbatim', async function () {
    const token = await mintAccessToken(this, 'other_scope');
    await this.agent.get('/me')
      .auth(token, { type: 'bearer' })
      .expect(403)
      .expect((response) => {
        expect(response.body.error_description).to.equal('access token missing openid scope');
        expect(response.headers['www-authenticate']).to.match(/scope="openid"/);
      });
  });
});
