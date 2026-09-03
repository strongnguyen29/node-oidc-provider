import getConfig from '../default.config.js';

const config = getConfig();

// partner và ui_mode chỉ vào được ctx.oidc.params khi đăng ký qua extraParams
config.extraParams = ['partner', 'ui_mode'];

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
