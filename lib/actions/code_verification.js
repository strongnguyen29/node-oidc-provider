const crypto = require('crypto');
const util = require('util');

const sessionMiddleware = require('../shared/session');
const paramsMiddleware = require('../shared/assemble_params');
const bodyParser = require('../shared/conditional_body');
const rejectDupes = require('../shared/reject_dupes');
const instance = require('../helpers/weak_cache');
const {
  InvalidClient, InvalidRequest, InvalidToken, InsufficientScope,
} = require('../helpers/errors');
const {
  NoCodeError, NotFoundError, ExpiredError, AlreadyUsedError, AbortedError,
} = require('../helpers/re_render_errors');
const formHtml = require('../helpers/user_code_form');
const formPost = require('../response_modes/form_post');
const { normalize, denormalize } = require('../helpers/user_codes');
const noCache = require('../shared/no_cache');
const presence = require('../helpers/validate_presence');

const parseBody = bodyParser.bind(undefined, 'application/x-www-form-urlencoded');
const randomFill = util.promisify(crypto.randomFill);

async function accessTokenAuth(ctx, next) {
  const regexTest = /^Bearer\s+[A-Za-z0-9-._~+/]+$/;
  if (!ctx.req.headers.authorization || !regexTest.test(ctx.req.headers.authorization)) {
    throw new InvalidToken();
  }

  const token = await ctx.oidc.provider.AccessToken.find(ctx.req.headers.authorization.split(' ')[1]);
  if (!token || !token.isValid) {
    throw new InvalidToken('Invalid token');
  }

  if (token.grantId) {
    const grant = await ctx.oidc.provider.Grant.find(token.grantId, {
      ignoreExpiration: true,
    });

    if (!grant) {
      throw new InvalidToken('Grant not found');
    }
    if (grant.isExpired) {
      throw new InvalidToken('Grant is expired');
    }
    if (grant.clientId !== token.clientId) {
      throw new InvalidToken('Grant client not match');
    }
    if (grant.accountId !== token.accountId) {
      throw new InvalidToken('Grant account not match');
    }

    ctx.oidc.entity('Grant', grant);
  }

  const session = await ctx.oidc.provider.Session.findByUid(token.sessionUid);

  if (!session) {
    throw new InvalidToken('Session not found');
  }

  ctx.oidc.entity('Session', session);

  ctx.oidc.entity('AccessToken', token);

  await next();
}

async function codeVerificationCSRF(ctx, next) {
  if (!ctx.oidc.session.state) {
    throw new InvalidRequest('could not find device form details');
  }
  if (ctx.oidc.session.state.secret !== ctx.oidc.params.xsrf) {
    throw new InvalidRequest('xsrf token invalid');
  }
  await next();
}

async function loadDeviceCodeByUserCodeInput(ctx, next) {
  const { approvalScopeValidate } = instance(ctx.oidc.provider).configuration('features.deviceFlow');
  const { user_code: userCode } = ctx.oidc.params;

  const normalized = normalize(userCode);
  const code = await ctx.oidc.provider.DeviceCode.findByUserCode(
    normalized,
    { ignoreExpiration: true },
  );

  if (!code) {
    throw new NotFoundError(userCode);
  }

  if (code.isExpired) {
    throw new ExpiredError(userCode);
  }

  if (code.error || code.accountId || code.inFlight) {
    throw new AlreadyUsedError(userCode);
  }

  if (!approvalScopeValidate(ctx, ctx.oidc.entities.AccessToken, code)) {
    throw new InsufficientScope();
  }

  ctx.oidc.entity('DeviceCode', code);
  await next();
}

function cleanup(ctx, next) {
  ctx.oidc.session.state = undefined;
  return next();
}

module.exports = {
  get: [
    sessionMiddleware,
    paramsMiddleware.bind(undefined, new Set(['user_code'])),
    async function renderCodeVerification(ctx, next) {
      const {
        features: { deviceFlow: { charset, userCodeInputSource } },
      } = instance(ctx.oidc.provider).configuration();

      // TODO: generic xsrf middleware to remove this
      let secret = Buffer.allocUnsafe(24);
      await randomFill(secret);
      secret = secret.toString('hex');
      ctx.oidc.session.state = { secret };

      const action = ctx.oidc.urlFor('code_verification');
      if (ctx.oidc.params.user_code) {
        await formPost(ctx, action, {
          xsrf: secret,
          user_code: ctx.oidc.params.user_code,
        });
      } else {
        await userCodeInputSource(ctx, formHtml.input(action, secret, undefined, charset));
      }

      await next();
    },
  ],
  post: [
    sessionMiddleware,
    parseBody,
    paramsMiddleware.bind(undefined, new Set(['xsrf', 'user_code', 'confirm', 'abort'])),
    rejectDupes.bind(undefined, {}),

    codeVerificationCSRF,

    async function loadDeviceCodeByUserInput(ctx, next) {
      const { userCodeConfirmSource, mask } = instance(ctx.oidc.provider).configuration('features.deviceFlow');
      const { user_code: userCode, confirm, abort } = ctx.oidc.params;

      if (!userCode) {
        throw new NoCodeError();
      }

      const normalized = normalize(userCode);
      const code = await ctx.oidc.provider.DeviceCode.findByUserCode(
        normalized,
        { ignoreExpiration: true },
      );

      if (!code) {
        throw new NotFoundError(userCode);
      }

      if (code.isExpired) {
        throw new ExpiredError(userCode);
      }

      if (code.error || code.accountId || code.inFlight) {
        throw new AlreadyUsedError(userCode);
      }

      ctx.oidc.entity('DeviceCode', code);

      if (abort) {
        Object.assign(code, {
          error: 'access_denied',
          errorDescription: 'End-User aborted interaction',
        });

        await code.save();
        throw new AbortedError();
      }

      if (!confirm) {
        const client = await ctx.oidc.provider.Client.find(code.clientId);
        if (!client) {
          throw new InvalidClient('client is invalid', 'client not found');
        }
        ctx.oidc.entity('Client', client);

        const action = ctx.oidc.urlFor('code_verification');
        await userCodeConfirmSource(
          ctx,
          formHtml.confirm(action, ctx.oidc.session.state.secret, userCode),
          client,
          code.deviceInfo,
          denormalize(normalized, mask),
        );
        return;
      }

      code.inFlight = true;
      await code.save();

      await next();
    },

    cleanup,
  ],
  checkUserCode: [
    noCache,
    parseBody,
    paramsMiddleware.bind(undefined, new Set(['user_code'])),
    rejectDupes.bind(undefined, {}),
    async function validateUserCodePresence(ctx, next) {
      presence(ctx, 'user_code');
      await next();
    },
    accessTokenAuth,
    sessionMiddleware,
    loadDeviceCodeByUserCodeInput,
    async function checkUserCodeResponse(ctx, next) {
      const { userCodeConfirmSource, mask } = instance(ctx.oidc.provider).configuration('features.deviceFlow');
      const { user_code: userCode } = ctx.oidc.params;
      const code = ctx.oidc.entities.DeviceCode;
      const client = await ctx.oidc.provider.Client.find(code.clientId);
      if (!client) {
        throw new InvalidClient('client is invalid', 'client not found');
      }

      ctx.oidc.entity('Client', client);

      let secret = Buffer.allocUnsafe(24);
      await randomFill(secret);
      secret = secret.toString('hex');
      ctx.oidc.session.state = { secret };

      const action = ctx.oidc.urlFor('code_verification');
      await userCodeConfirmSource(
        ctx,
        formHtml.confirm(action, secret, userCode),
        client,
        code.deviceInfo,
        userCode,
      );
      await next();
    },
  ],
  approvalUserCode: [
    noCache,
    parseBody,
    paramsMiddleware.bind(undefined, new Set(['xsrf', 'user_code', 'confirm'])),
    rejectDupes.bind(undefined, {}),
    async function validateInputPresence(ctx, next) {
      presence(ctx, 'xsrf', 'user_code', 'confirm');
      await next();
    },
    accessTokenAuth,
    sessionMiddleware,
    codeVerificationCSRF,
    loadDeviceCodeByUserCodeInput,
    async function confirmUserCode(ctx, next) {
      const { confirm } = ctx.oidc.params;
      const code = ctx.oidc.entities.DeviceCode;

      if (confirm === 'no') {
        Object.assign(code, {
          error: 'access_denied',
          errorDescription: 'End-User aborted interaction',
        });

        await code.save();
        throw new AbortedError();
      }

      code.inFlight = true;
      await code.save();
      await next();
    },
  ],
};
