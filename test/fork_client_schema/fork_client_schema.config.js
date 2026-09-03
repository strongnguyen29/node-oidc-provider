import getConfig from '../default.config.js';

const config = getConfig();

// Grant type ngoài chuẩn phải được registerGrantType TRƯỚC khi Client.find
// validate client. v9 validate client.grant_types bằng enum trên tập grant đã
// đăng ký (lib/helpers/client_schema.js:561-589), nên một tên như 'password'
// chưa đăng ký sẽ bị từ chối ngay — đó là khả năng (a) ở Task 15 Step 3.
export default {
  config,
  clients: [{
    client_id: 'client-nonstandard-grant',
    client_secret: 'secret',
    grant_types: ['urn:fork:password'],
    response_types: ['id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
