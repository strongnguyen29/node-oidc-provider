import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('fork: session loginFrom and deviceId', () => {
  before(bootstrap(import.meta.url));

  describe('loginAccount', () => {
    it('defaults loginFrom to "web" when not given', function () {
      const session = new this.provider.Session({});
      session.loginAccount({ accountId: 'accountId', amr: 'pwd' });
      expect(session.loginFrom).to.equal('web');
    });

    it('keeps the loginFrom that was passed in', function () {
      const session = new this.provider.Session({});
      session.loginAccount({ accountId: 'accountId', amr: 'pwd', loginFrom: 'sdk' });
      expect(session.loginFrom).to.equal('sdk');
    });

    it('does not treat an empty string as absent', function () {
      const session = new this.provider.Session({});
      session.loginAccount({ accountId: 'accountId', loginFrom: '' });
      expect(session.loginFrom).to.equal('');
    });
  });

  describe('IN_PAYLOAD', () => {
    it('includes loginFrom and deviceId', function () {
      expect(this.provider.Session.IN_PAYLOAD).to.include('loginFrom');
      expect(this.provider.Session.IN_PAYLOAD).to.include('deviceId');
    });

    it('round-trips both through the adapter', async function () {
      const session = new this.provider.Session({});
      session.loginAccount({ accountId: 'accountId', loginFrom: 'sdk' });
      session.deviceId = 'device-1';
      const id = await session.save(60);

      const loaded = await this.provider.Session.find(id);
      expect(loaded.loginFrom).to.equal('sdk');
      expect(loaded.deviceId).to.equal('device-1');
    });
  });
});
