import { expect } from 'chai';

import bootstrap from '../test_helper.js';

// Nhánh mặc định — mọi deployment upstream đang chạy nhánh này, nên nó phải
// không hồi quy. Config phụ đặt cùng thư mục, nạp qua { config: ... }:
// xem kết luận Task 8 Step 1 về chữ ký bootstrap.
describe('fork: cookies.prefix left unset', () => {
  before(bootstrap(import.meta.url, { config: 'fork_provider_noprefix' }));

  it('uses the names in cookies.names verbatim', function () {
    expect(this.provider.cookieName('session')).to.equal('_session');
    expect(this.provider.cookieName('interaction')).to.equal('_interaction');
    expect(this.provider.cookieName('resume')).to.equal('_interaction_resume');
  });

  it('sets an unprefixed cookie on the wire', function () {
    return this.agent.get('/auth')
      .query({
        client_id: 'client',
        response_type: 'code',
        scope: 'openid',
        redirect_uri: 'https://client.example.com/cb',
      })
      .expect((response) => {
        const cookies = [].concat(response.headers['set-cookie'] || []).join('\n');
        expect(cookies).to.match(/(^|\n)_interaction=/);
        expect(cookies).not.to.match(/vlive\./);
      });
  });
});
