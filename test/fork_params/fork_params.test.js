import { parse as parseUrl } from 'node:url';

import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('fork: partner and ui_mode in the authorization response', () => {
  before(bootstrap(import.meta.url));
  before(function () { return this.login(); });

  function fragmentQuery(response) {
    const { hash } = parseUrl(response.headers.location);
    expect(hash).to.exist;
    return parseUrl(response.headers.location.replace('#', '?'), true).query;
  }

  it('echoes both params back when both are sent', function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'id_token',
      scope: 'openid',
      partner: 'vtvlive',
      ui_mode: 'popup',
    });

    return this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect((response) => {
        const query = fragmentQuery(response);
        expect(query).to.have.property('partner', 'vtvlive');
        expect(query).to.have.property('ui_mode', 'popup');
      });
  });

  it('echoes only the param that was sent', function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'id_token',
      scope: 'openid',
      partner: 'vtvlive',
    });

    return this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect((response) => {
        const query = fragmentQuery(response);
        expect(query).to.have.property('partner', 'vtvlive');
        expect(query).not.to.have.property('ui_mode');
      });
  });

  it('omits both when neither is sent', function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'id_token',
      scope: 'openid',
    });

    return this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect((response) => {
        const query = fragmentQuery(response);
        expect(query).not.to.have.property('partner');
        expect(query).not.to.have.property('ui_mode');
      });
  });

  // Hành vi thật, đã chốt ở Task 1 trên nhánh v7: chuỗi rỗng KHÔNG được echo.
  // respond.js gác bằng `!== undefined`, nhưng lib/helpers/params.js chạy
  // `params[prop] || undefined` từ trước nên mọi giá trị falsy đã thành undefined
  // trước khi respond.js nhìn thấy. v9 giữ y hệt dòng đó, nên khẳng định không đổi.
  it('drops an empty string value instead of echoing it', function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'id_token',
      scope: 'openid',
      partner: '',
    });

    return this.wrap({ auth, verb: 'get', route: '/auth' })
      .expect((response) => {
        const query = fragmentQuery(response);
        expect(query).not.to.have.property('partner');
      });
  });
});
