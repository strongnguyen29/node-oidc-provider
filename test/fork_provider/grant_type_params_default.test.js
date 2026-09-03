import { expect } from 'chai';

import bootstrap from '../test_helper.js';

// Chữ ký helper trên v9 (test/test_helper.js:126): bootstrap(importMetaUrl, { config,
// protocol, mountVia, mountTo }) — tham số thứ hai là OBJECT, không phải string, y
// như trên v7. Và `base ??= path.basename(dir)` nên file trong test/fork_provider/
// tự nạp fork_provider.config.js mà không cần truyền gì. Kết luận này áp cho cả
// Task 9, 12, 13, 14: config phụ đặt CÙNG thư mục được, nạp bằng { config: '<tên>' }.
describe('fork: grantTypeParamsDefault', () => {
  before(bootstrap(import.meta.url));

  // Cả hai grant type phải đăng ký TRƯỚC request đầu tiên. client_schema validate
  // client.grant_types theo tập grant đã đăng ký, và client ở config khai cả hai;
  // đăng ký lẻ tẻ trong it() thì request đầu gặp 400 invalid_client_metadata.
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
