import getConfig from '../default.config.js';

const config = getConfig();

config.cookies = { ...config.cookies, prefix: 'vlive' };

// Không khai grant type ngoài chuẩn ở đây: suite cookie không đăng ký grant type
// nào, mà client_schema validate client.grant_types theo tập grant đã đăng ký —
// khai vào sẽ làm client invalid và /auth lỗi trước khi kịp set cookie.
export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
