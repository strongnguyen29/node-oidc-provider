# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository

This is a **fork** of [panva/node-oidc-provider](https://github.com/panva/node-oidc-provider) published as `@strongnguyen/oidc-provider` on npm. Active development happens on the `v7.x` branch (the upstream Node 12/14/16/18 line). Fork-specific changes layered on top of upstream:

- `provider.registerGrantType(name, handler, params, dupes)` — runtime registration of custom grant types (see `lib/provider.js`).
- `grantTypeParamsDefault` configuration option (default `[]`) — extra params injected into every grant type (see `lib/helpers/defaults.js:2806`).
- `partner` and `ui_mode` params propagated from the authorization request into the response (see `lib/actions/authorization/respond.js`).
- `ctx.trackingAction` set inside the `refresh_token` grant for downstream consumers (`login`, `loginfast`, `login{amr}`).
- Cookie tweaks: configurable cookie prefix, root-domain session sharing, `expires` appended to `_SID` when `remember=true`.

When upstreaming, fixing, or reviewing changes, **diff against `panva/v7.x`** to avoid accidentally reverting fork-specific features.

## Common commands

```bash
# Install (Node 12 || 14 || 16 || 18 only — see package.json engines)
npm install

# Lint + auto-fix (airbnb-base + babel-eslint)
npm run format

# Full test suite (Mocha via custom runner test/run.js)
npm test

# Single test file — pass through MOCHA_FILE or run mocha directly:
npx mocha --timeout 3000 test/path/to/foo.test.js
# Filter by name:
npx mocha --timeout 3000 --grep "issues a refresh token" test/core/basic/code.test.js

# Multi-framework CI (also runs the suite mounted in connect/express/koa/hapi/fastify)
npm run ci

# Manual mounted run, equivalent to one CI matrix cell:
MOUNT_VIA=express MOUNT_TO=/oidc npm test
```

`test/run.js` is **not** a plain `mocha` invocation — it boots a shared HTTP server and a global `jose2` JWKS keystore (`global.keystore`, `global.server`) before mocha picks up `test/**/*.test.js`. Tests assume those globals exist; never run individual test files via `node` directly.

CI sets `CI=true`, which makes `test/run.js` use the `min` reporter and call `forbidOnly` / `forbidPending` — keep `.only` and `.skip` out of committed tests.

## Architecture (big picture)

oidc-provider is a Koa application factory. `new Provider(issuer, configuration)` returns an `EventEmitter` whose `.app` is the underlying Koa instance and `.callback()` is a Node-style `(req, res)` handler suitable for express/connect/fastify/hapi/standalone use.

The flow when constructing a Provider (see `lib/provider.js` + `lib/helpers/initialize_app.js`):

1. **Configuration** (`lib/helpers/configuration.js` + `lib/helpers/defaults.js`) — merges user options with defaults, validates feature flags, wires per-instance state into a WeakMap via `lib/helpers/weak_cache.js` (the `instance(this)` accessor used throughout the codebase). **Never** add a public field to `Provider` for per-instance config — store it through `instance()`.
2. **Keystore / Adapter / Clients** are initialized in `lib/helpers/initialize_keystore.js`, `initialize_adapter.js`, `initialize_clients.js`.
3. **Router** (`lib/router/`) is built in `initialize_app.js`: every protocol endpoint (authorize, token, userinfo, jwks, registration, revocation, introspection, discovery, end_session, code_verification, ciba, par) is mounted with a stack of small middlewares from `lib/actions/` and `lib/shared/`.
4. **Models** (`lib/models/`) are class factories — `getAccessToken(provider)`, `getAuthorizationCode(provider)`, etc. — composed from `mixins/` (`consumable`, `has_grant_id`, `is_sender_constrained`, `stores_pkce`, …) and persistence formats in `lib/models/formats/` (`opaque`, `jwt`, `paseto`, `dynamic`).
5. **Grants** (`lib/actions/grants/index.js`) is a static map of grant-type name → handler. It is the *initial* set; additional grants may be registered at runtime via `provider.registerGrantType(...)`.
6. **Adapter contract** — persistence is pluggable. `lib/adapters/memory_adapter.js` is the in-memory reference; production deployments supply their own (Redis/Mongo/SQL). Any model goes through the adapter; do not bypass it.

### Authorization pipeline

`lib/actions/authorization/index.js` composes the request lifecycle as an ordered list of middleware modules in the same directory (`check_*`, `process_*`, `load_*`, `interactions`, `respond`, …). Adding/removing a step means editing that array — order matters because each step assumes invariants established by earlier ones.

The pipeline can pause for user interaction. When a prompt is required, the request is suspended into an **Interaction** model and the UA is redirected to `interactions.url`. The host application calls `provider.interactionDetails(req, res)` and `provider.interactionFinished(req, res, result)` (`lib/provider.js`) to resume. The interaction policy is composable (`lib/helpers/interaction_policy/`).

### Token endpoint

`lib/actions/token.js` resolves the grant from the registered map (built-in + `registerGrantType` extensions) and dispatches to `lib/actions/grants/<name>.js`. Custom-grant tests live under `test/custom_grants/`.

### Response modes

`lib/response_modes/` holds `query`, `fragment`, `form_post`, `web_message`, and `jwt` (JARM). Custom modes can be registered (`test/custom_response_modes/`).

### Models & token formats

`lib/models/` defines the persistent objects (Session, Grant, AccessToken, AuthorizationCode, RefreshToken, ClientCredentials, DeviceCode, BackchannelAuthenticationRequest, PushedAuthorizationRequest, RegistrationAccessToken, InitialAccessToken, Interaction, ReplayDetection, Client, IdToken, BaseToken, BaseModel). Each token model picks a `format` from `lib/models/formats/index.js`. `dynamic.js` lets the configuration choose per-token format at runtime — relevant when adding a new token type.

### Helpers worth knowing about

- `lib/helpers/weak_cache.js` — per-instance state; ubiquitous.
- `lib/helpers/_/` — minimal lodash-like primitives (`get`, `set`, `merge`, `pick`, `omit_by`, …) intentionally kept dependency-free.
- `lib/helpers/errors.js` — every protocol error subclass; throw these (not `Error`) so the error handler middleware can render the spec-mandated response.
- `lib/helpers/features.js` — feature toggle resolution; many code paths gate on `instance(provider).features.<name>.enabled`.

## Conventions specific to this codebase

- **CommonJS only** (`require` / `module.exports`). The package targets Node 12+ runtimes — no ESM, no TypeScript, no transpile step. ESLint config is `airbnb-base` with `babel-eslint` parser purely to allow class-fields syntax (`#privateField`) like in `lib/provider.js`.
- **Snake_case** is used for grant names, params, claim keys, and any value that ends up on the wire (per the OAuth/OIDC specs). Internal JS identifiers are camelCase.
- **Allowed dangling-underscore identifiers** are limited to `_claim_names`, `_claim_sources`, `_matchedRouteName` (see `.eslintrc`).
- **Throw OIDC errors, not generic ones.** `lib/helpers/errors.js` exposes `InvalidRequest`, `InvalidGrant`, `AccessDenied`, etc. — they map to the correct HTTP status, error code, and (where relevant) `WWW-Authenticate` header.
- **Don't mutate `defaults.js`.** When adding configuration options, register a default + document it with a JSDoc-style comment block — `docs/update-configuration.js` parses those blocks to regenerate `docs/README.md`. Run `node docs/update-configuration.js` after touching defaults.
- **Spec compliance > ergonomics.** Per `CONTRIBUTING.md`, contributions that diverge from the implemented RFCs/OIDC specs are typically rejected upstream. For fork-specific extensions, isolate them so they remain easy to rebase on top of upstream `v7.x`.

## Tests

- Framework: **Mocha + Chai + Sinon + supertest + nock**. Test files end in `.test.js`.
- Layout mirrors features, not source: `test/core/`, `test/configuration/`, `test/<feature_name>/` (e.g. `test/dpop/`, `test/par/`, `test/ciba/`, `test/fapi/`). Each feature directory typically contains a `*.config.js` (provider config for the suite) plus one or more `*.test.js`.
- Use `test/default.config.js` as the baseline when authoring a new suite config.
- The CI matrix (`test/ci.js`) re-runs the whole suite mounted via connect/express/koa/hapi/fastify on Linux. If you add tests that hardcode a path, parameterize on `process.env.MOUNT_TO` or they will fail in mounted mode.
