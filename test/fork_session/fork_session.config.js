import getConfig from '../default.config.js';

export default {
  config: getConfig(),
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
