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

  // Hành vi thật, và là điều đáng chú ý nhất của patch này: token chỉ có
  // api_profile_get ĐI QUA được cửa scope (200), nhưng body rỗng.
  //
  // Patch chỉ nới điều kiện ở lib/actions/userinfo.js:27. Xuống tới hàm respond,
  // `mask.scope(scope)` lọc claims theo OIDC scope, mà scope ở đây là
  // grant.getOIDCScopeFiltered(...) trên 'api_profile_get' — một scope không
  // mang claim OIDC nào — nên cho ra chuỗi rỗng và Claims.result() trả {}.
  // Ngay cả `sub` cũng không có, vì `sub` chỉ đi kèm scope openid.
  //
  // Nói cách khác: patch mở cửa nhưng không làm /me trả profile. Task 13 phải
  // reproduce đúng điều này, không được "sửa" thành trả sub.
  it('lets an api_profile_get-only token through but responds with an empty body', async function () {
    const token = await mintAccessToken(this, 'api_profile_get');
    await this.agent.get('/me')
      .auth(token, { type: 'bearer' })
      .expect(200)
      .expect((response) => {
        expect(response.body).to.deep.equal({});
      });
  });

  // Tương phản với test trên: chỉ khi có openid thì claims mới ra.
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
