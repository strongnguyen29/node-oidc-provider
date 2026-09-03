import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('fork: cookies.prefix', () => {
  // Config riêng, KHÔNG dùng chung fork_provider.config.js như kế hoạch ghi:
  // config đó khai hai grant type ngoài chuẩn mà suite này không đăng ký, nên
  // client_schema làm client invalid và /auth lỗi trước khi kịp set cookie —
  // test Set-Cookie sẽ thấy header rỗng.
  before(bootstrap(import.meta.url, { config: 'fork_provider_prefix' }));

  it('prefixes every configured cookie name with "<prefix>."', function () {
    expect(this.provider.cookieName('session')).to.equal('vlive._session');
    expect(this.provider.cookieName('interaction')).to.equal('vlive._interaction');
    expect(this.provider.cookieName('resume')).to.equal('vlive._interaction_resume');
  });

  // Test đáng giá nhất của nhóm: prefix phải ra tới Set-Cookie thật, không chỉ
  // đúng ở cookieName().
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
