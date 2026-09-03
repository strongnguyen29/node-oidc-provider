import getConfig from '../default.config.js';

const config = getConfig();

config.grantTypeParamsDefault = ['partner', 'device_id'];
config.cookies = { ...config.cookies, prefix: 'vlive' };

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'urn:fork:test-grant', 'urn:fork:bare-grant'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
