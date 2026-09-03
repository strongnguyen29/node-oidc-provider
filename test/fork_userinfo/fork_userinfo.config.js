const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, { userinfo: { enabled: true } });

config.scopes = ['openid', 'api_profile_get', 'other_scope'];
config.findAccount = (ctx, id) => ({
  accountId: id,
  claims() { return { sub: id }; },
});

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
