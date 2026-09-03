const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

config.grantTypeParamsDefault = ['partner', 'device_id'];
config.cookies = { ...config.cookies, prefix: 'vlive' };

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'urn:fork:test-grant', 'urn:fork:bare-grant'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
