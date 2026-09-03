const { parse: parseUrl } = require('url');

const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('fork: partner and ui_mode in the authorization response', () => {
  before(bootstrap(__dirname));
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

  // Hành vi thật, khác với dự đoán ban đầu của kế hoạch: chuỗi rỗng KHÔNG được
  // echo. respond.js gác bằng `params.partner !== undefined`, nhưng lớp Params
  // (lib/helpers/params.js) đã chạy `params[prop] || undefined` từ trước, nên mọi
  // giá trị falsy — với query string thì chỉ có chuỗi rỗng — thành undefined
  // trước khi respond.js nhìn thấy. Nghĩa là nhánh `!== undefined` không bao giờ
  // gặp chuỗi rỗng.
  //
  // Chốt lại điều này để người port không "sửa" guard đó thành thứ cho chuỗi rỗng
  // đi qua. v9 giữ y hệt `params[prop] || undefined`, nên khẳng định này mang
  // sang v9 không đổi.
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
