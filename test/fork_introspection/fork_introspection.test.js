import { expect } from 'chai';

import bootstrap from '../test_helper.js';

const route = '/token/introspection';

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

function runMatrix(cases) {
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
}

describe('fork: introspection with strictTokenTypeHint enabled', () => {
  before(bootstrap(import.meta.url));

  // Ma trận đối chiếu với Task 6 trên nhánh v7. Mười một ô giữ nguyên giá trị;
  // BA ô đổi, đều do cấu trúc nhóm hint của v9 chứ không do chế độ strict:
  //
  //   ClientCredentials + 'access_token'      : v7 false -> v9 true
  //       ClientCredentials nằm CÙNG nhóm với AccessToken cho hint này, vì theo
  //       RFC 7662 cả hai đều LÀ access token. strict chỉ chặn fallback RA
  //       NGOÀI nhóm, không chia nhỏ trong nhóm.
  //   AccessToken + 'client_credentials'      : v7 false -> v9 true
  //   ClientCredentials + 'client_credentials': v7 true  -> v9 true, nhưng vì
  //       rơi vào nhánh default chứ không phải vì hint được nhận.
  //       ('client_credentials' không còn là hint hợp lệ ở v9.)
  runMatrix([
    // [loại token, hint, mong đợi active]
    ['AccessToken', undefined, true],
    ['AccessToken', 'access_token', true],
    ['AccessToken', 'urn:ietf:params:oauth:token-type:access_token', true],
    ['AccessToken', 'refresh_token', false],
    ['AccessToken', 'client_credentials', true],
    ['AccessToken', 'foobar', true],

    ['RefreshToken', undefined, true],
    ['RefreshToken', 'refresh_token', true],
    ['RefreshToken', 'urn:ietf:params:oauth:token-type:refresh_token', true],
    ['RefreshToken', 'access_token', false],
    ['RefreshToken', 'foobar', true],

    ['ClientCredentials', undefined, true],
    ['ClientCredentials', 'access_token', true],
    ['ClientCredentials', 'refresh_token', false],
    ['ClientCredentials', 'client_credentials', true],
    ['ClientCredentials', 'foobar', true],
  ]);
});

// Nhánh mặc định — mọi deployment upstream chạy nhánh này. Với strict tắt,
// một hint sai KHÔNG được làm token thành inactive, đúng khuyến nghị RFC 7662.
describe('fork: strictTokenTypeHint left at its default', () => {
  before(bootstrap(import.meta.url, { config: 'fork_introspection_lax' }));

  runMatrix([
    ['AccessToken', 'refresh_token', true],
    ['RefreshToken', 'access_token', true],
    ['ClientCredentials', 'refresh_token', true],
    ['AccessToken', 'access_token', true],
    ['RefreshToken', 'refresh_token', true],
  ]);
});
