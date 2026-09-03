import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, { userinfo: { enabled: true } });

config.scopes = ['openid', 'api_profile_get', 'other_scope'];
config.userinfoRequiredScopes = ['openid', 'api_profile_get'];
config.findAccount = (_ctx, id) => ({
  accountId: id,
  claims() { return { sub: id }; },
});

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
