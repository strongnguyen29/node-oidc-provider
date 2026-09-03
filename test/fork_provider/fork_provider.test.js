const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('fork: grantTypeParamsDefault', () => {
  before(bootstrap(__dirname));

  // Cả hai grant type phải đăng ký TRƯỚC request đầu tiên, không phải trong it().
  // client_schema validate client.grant_types theo tập grant đã đăng ký, và
  // client ở config khai cả hai. Đăng ký lẻ tẻ trong it() thì request đầu gặp
  // 400 invalid_client_metadata vì grant type thứ hai còn chưa biết.
  const seen = { test: [], bare: [] };

  before(function () {
    this.provider.registerGrantType(
      'urn:fork:test-grant',
      async (ctx) => { seen.test.push({ ...ctx.oidc.params }); ctx.body = { ok: true }; },
      ['own_param'],
    );
    this.provider.registerGrantType(
      'urn:fork:bare-grant',
      async (ctx) => { seen.bare.push({ ...ctx.oidc.params }); ctx.body = { ok: true }; },
    );
  });

  it('injects the default params into a newly registered grant type', function () {
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
        expect(seen.test).to.have.lengthOf(1);
        expect(seen.test[0]).to.include({ own_param: 'a', partner: 'vtvlive', device_id: 'd1' });
      });
  });

  it('injects them even when the grant type declares no params of its own', function () {
    return this.agent.post('/token')
      .auth('client', 'secret')
      .send({ grant_type: 'urn:fork:bare-grant', partner: 'vtvlive' })
      .type('form')
      .expect(200)
      .expect(() => {
        expect(seen.bare[0]).to.include({ partner: 'vtvlive' });
      });
  });
});

describe('fork: cookies.prefix', () => {
  before(bootstrap(__dirname, { config: 'fork_provider_cookies' }));

  it('prefixes every configured cookie name with "<prefix>."', function () {
    expect(this.provider.cookieName('session')).to.equal('vlive._session');
    expect(this.provider.cookieName('interaction')).to.equal('vlive._interaction');
    expect(this.provider.cookieName('resume')).to.equal('vlive._interaction_resume');
  });

  // Test đáng giá nhất của nhóm này: prefix phải ra tới Set-Cookie thật, không
  // chỉ đúng ở cookieName().
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
