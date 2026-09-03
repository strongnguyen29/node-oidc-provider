const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

// partner và ui_mode chỉ vào được ctx.oidc.params khi đăng ký qua extraParams
config.extraParams = ['partner', 'ui_mode'];

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
