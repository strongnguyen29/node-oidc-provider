# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository

This is a **fork** of [panva/node-oidc-provider](https://github.com/panva/node-oidc-provider) published as `@strongnguyen/oidc-provider` on npm. Active development happens on the `vlive/oidc-provider-v9` branch, layered on top of upstream `9.11.5`. The `main` branch is an untouched mirror of `panva/main`.

When upstreaming, fixing, or reviewing changes, **diff against `origin/main`** to avoid accidentally reverting fork-specific features:

```bash
git diff origin/main...HEAD -- lib/
```

Fork-specific changes on top of upstream — seven patches, all in `lib/`:

- `grantTypeParamsDefault` — params injected into every grant type registered through `registerGrantType` (`lib/provider.js`, `lib/helpers/defaults.js`).
- `cookies.prefix` — prefix prepended to every cookie name (`lib/provider.js`).
- `partner` / `ui_mode` — echoed from the authorization request into the response (`lib/actions/authorization/respond.js`).
- `ctx.trackingAction` + a `refresh_token` event in the refresh_token grant (`lib/actions/grants/refresh_token.js`).
- Session `loginFrom` (defaults to `web`) and `deviceId` (read from `ctx.req.deviceId`) (`lib/models/session.js`).
- `userinfoRequiredScopes` — which scopes are accepted at the userinfo endpoint (`lib/actions/userinfo.js`, `lib/helpers/defaults.js`).
- `features.introspection.strictTokenTypeHint` — treat `token_type_hint` as binding (`lib/helpers/token_find.js`, `lib/actions/introspection.js`).

Every fork config defaults to upstream behaviour, so an unconfigured provider behaves exactly like upstream. Each patch has its own test suite under `test/fork_*/`.

**Not in the library:** the root-domain shared `_SID` cookie. The integrating app sets it through a `provider.use()` middleware — see §4.4 of `docs/superpowers/specs/2026-08-27-v9-migration-design.md`. Note that `provider.use()` is required there, not `app.use()`: `use()` splices the middleware in *before* the internal ones.

**Dropped when moving to v9, deliberately not ported:** the two access-token device flow endpoints (`/device/code-check`, `/device/code-verification`) and the `features.deviceFlow.approvalScopeValidate` config. The v7 fork registered three routes under the same name `code_verification`, which made `urlFor('code_verification')` resolve to the wrong URL and broke `verification_uri`; dropping the patch removes that bug by construction. Do not reintroduce it.

## Common commands

```bash
# Install (Node 22+ — v9 dropped Node 18 and 20; package.json declares no engines)
npm install

# Lint (biome, configured in biome.json)
npm run lint

# Full test suite (Mocha via the custom runner test/run.js)
npm test

# Regenerate docs/README.md after touching lib/helpers/defaults.js
node docs/update-configuration.js

# Build the dist/ bundle (gitignored)
npm run build
npm run test-dist

# Multi-framework CI (runs the suite mounted in express/koa/hapi/fastify)
npm run test-ci

# Manual mounted run, equivalent to one CI matrix cell:
MOUNT_VIA=express MOUNT_TO=/oidc npm test
```

`test/run.js` is **not** a plain `mocha` invocation — it starts a shared HTTP server at `globalThis.server` before mocha loads `test/**/*.test.js`. Tests assume that global exists.

**Running a single test file:** `npx mocha test/path/to/foo.test.js` **does not work** — `test/test_helper.js` reads `globalThis.server.address()`, and there is no `.mocharc` to bootstrap it. Either run `npm test` and read the suite you care about, or write a small runner that creates `globalThis.server` the way `test/run.js` does and then sets `mocha.files` plus `await mocha.loadFilesAsync()`.

`CI=true` makes `test/run.js` use the `min` reporter and call `forbidOnly()` — keep `.only` out of committed tests. Unlike the v7 line it does **not** call `forbidPending()`, and the upstream suite ships 6 pending tests.

## Architecture (big picture)

oidc-provider is a Koa application factory. `new Provider(issuer, configuration)` returns an `EventEmitter` whose `.callback()` is a Node-style `(req, res)` handler suitable for express/fastify/hapi/standalone use.

The flow when constructing a Provider (see `lib/provider.js` + `lib/helpers/initialize_app.js`):

1. **Configuration** (`lib/helpers/configuration.js` + `lib/helpers/defaults.js`) — merges user options with defaults and validates feature flags.
2. **Keystore / Adapter / Clients** are initialized in `lib/helpers/initialize_keystore.js`, `initialize_adapter.js`, `initialize_clients.js`.
3. **Router** (`lib/router/`) is built in `initialize_app.js`: every protocol endpoint is mounted with a stack of small middlewares from `lib/actions/` and `lib/shared/`.
4. **Models** (`lib/models/`) are class factories composed from `mixins/` and persistence formats in `lib/models/formats/` (`opaque`, `jwt`, `dynamic` — PASETO was removed in v8).
5. **Grants** (`lib/actions/grants/index.js`) is the *initial* set; more may be registered at runtime via `provider.registerGrantType(...)`.
6. **Adapter contract** — persistence is pluggable. `lib/adapters/memory_adapter.js` is the in-memory reference; production supplies its own. Any model goes through the adapter; do not bypass it.

### Things that changed from the v7 line — read before editing

**Config access is a property, not a call.** `instance(provider).configuration.a.b`, **not** `instance(provider).configuration('a.b')`. Feature flags have a shortcut: `instance(provider).features.<name>`. Inside `lib/provider.js` use the private field: `this.#int.configuration.a.b`.

**A new config key must be declared in `lib/helpers/defaults.js`.** `lib/helpers/configuration.js` runs `pick(config, ...Object.keys(defaults))`, so a top-level key absent from defaults is **silently dropped** from the user's config. Nested keys under an existing top-level object survive via deep merge, but declare them anyway — the declaration is what `docs/update-configuration.js` reads.

**`Provider` *is* the Koa app** (`class Provider extends Koa`); the `.app` getter is deprecated. `provider.use(fn)` is overridden to splice the middleware in *before* the router, so anything added with it always sits upstream of every route. `provider.app.use(fn)` appends to the end of the stack instead, which runs *after* the internal middleware — usually not what you want.

**Every route ends the request.** Koa middleware placed "downstream" of the provider will not run. The provider also no longer installs a catch-all 404 handler.

### Authorization pipeline

`lib/actions/authorization/index.js` composes the request lifecycle as an ordered list of middleware modules in the same directory. Adding or removing a step means editing that array — order matters, because each step assumes invariants established by earlier ones.

The pipeline can pause for user interaction. When a prompt is required the request is suspended into an **Interaction** model and the UA is redirected to `interactions.url`. The host application calls `provider.interactionDetails(req, res)` and `provider.interactionFinished(req, res, result)` to resume. The interaction policy is composable (`lib/helpers/interaction_policy/`).

Note which gate does what: `check_response_type.js` gates the authorization endpoint on `client.responseTypeAllowed(...)`, i.e. on `response_types`. `check_client_grant_type.js` applies only to `device_authorization` and `backchannel_authentication`, never to `/auth`.

### Token endpoint

`lib/actions/token.js` resolves the grant from the registered map (built-in + `registerGrantType` extensions) and dispatches to `lib/actions/grants/<name>.js`. Note that `client_schema` validates `client.grant_types` against the set of **registered** grant types, so a client may only declare a non-standard grant type after `registerGrantType` has been called for it.

### Response modes

`lib/response_modes/` holds `query`, `fragment`, `form_post`, `web_message`, and `jwt` (JARM). Custom modes can be registered.

## Conventions specific to this codebase

- **ESM only** (`import` / `export`), `"type": "module"`. Node 22+. No CommonJS, no TypeScript, no transpile step for `lib/`.
- **Snake_case** for grant names, params, claim keys, and any value that ends up on the wire (per the OAuth/OIDC specs). Internal JS identifiers are camelCase.
- **Throw OIDC errors, not generic ones.** `lib/helpers/errors.js` exposes `InvalidRequest`, `InvalidGrant`, `AccessDenied`, etc. — they map to the correct HTTP status, error code, and where relevant the `WWW-Authenticate` header.
- **Don't mutate `defaults.js` casually.** When adding a configuration option, register a default plus a JSDoc-style comment block (`* <name>` / `* title:` / `* description:`), then run `node docs/update-configuration.js` to regenerate `docs/README.md`.
- **Linting is biome** (`biome.json`); there is no `.eslintrc`. Note that `npm test` stays green even when `npm run lint` reports warnings, so read the lint output rather than only its exit code. Two rules bite often: `noUnusedFunctionParameters` (prefix with `_`) and unused imports.
- **Spec compliance > ergonomics.** Contributions that diverge from the implemented RFCs/OIDC specs are typically rejected upstream. For fork-specific extensions, isolate them behind a config option that defaults to upstream behaviour, so they stay easy to rebase.

## Tests

- Framework: **Mocha 11 + Chai 6 + Sinon + supertest + undici** (`nock` is gone; so is `jose2`). Test files end in `.test.js`.
- Layout mirrors features, not source: `test/core/`, `test/configuration/`, `test/<feature_name>/`. Each feature directory typically contains a `*.config.js` (provider config for the suite) plus one or more `*.test.js`.
- Use `test/default.config.js` as the baseline — it exports a **factory**: `import getConfig from '../default.config.js'; const config = getConfig();`.
- `bootstrap(import.meta.url, { config, protocol, mountVia, mountTo })`. The second argument is an **object**; passing a string silently falls back to `path.basename(dir)` and loads the wrong config. Because the default is the directory name, several configs can live in one directory and be selected with `{ config: '<name>' }`.
- Fork test suites: `test/fork_params/`, `test/fork_tracking/`, `test/fork_session/`, `test/fork_provider/`, `test/fork_userinfo/`, `test/fork_introspection/`, `test/fork_client_schema/`. Each fork config that deviates from upstream has a companion suite asserting the **default** branch too, so an upstream regression is caught.
- The CI matrix (`test/ci.js`) re-runs the whole suite mounted via express/koa/hapi/fastify. If you add tests that hardcode a path, parameterize on `process.env.MOUNT_TO` or they will fail in mounted mode.
