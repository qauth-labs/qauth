# @qauth-labs/plugin-sdk

> **Experimental.** This package is QAuth's plugin API, the experimental item
> [`plugin-api`](https://docs.qauth.dev/reference/experimental-features/#plugin-api).
> It is public and documented, so you can write plugins against it, but it is
> outside QAuth's 1.0 stability promise: it may change in a minor release,
> without a deprecation window. It becomes stable in 1.x.

Write, test and release a sign-in method for
**[QAuth](https://github.com/qauth-labs/qauth)** in your own repository. A
plugin is an npm package that exports one **AuthMethod**: a sign-in method that
plugs into QAuth's engine, such as an upstream OAuth 2.0 or OpenID Connect
provider. A plugin for an OpenID Connect provider may export a **preset**
instead: the provider's facts and claim rules, whose method the server builds on
its own OpenID Connect client. This package is the contract both are written
against, `qauth-auth-method/1-rc.0`:

- the `AuthMethod` interface and the types it uses: the context and the egress
  client as a method sees them, and the `CredentialProvider` half it extends;
- the contract's constants: `AUTH_METHOD_CONTRACT`, the plugin export
  `AUTH_METHOD_PLUGIN_EXPORT`, the upstream step `UPSTREAM_STEP_URN`, the
  patterns and the caps;
- its errors, and the static checks QAuth's registry runs on a method;
- the preset's shape: `defineUpstreamOidcPreset`, the export name
  `UPSTREAM_OIDC_PRESET_EXPORT` (`upstreamOidcPreset`), the types of its members
  and of the provider config it makes, and its limits;
- the contract test kit, `checkAuthMethod`, and the preset kit,
  `checkUpstreamOidcPreset`, under `@qauth-labs/plugin-sdk/testing`.

The contract is documented at
[docs.qauth.dev/extend/auth-method-contract](https://docs.qauth.dev/extend/auth-method-contract/).

## Install

```bash
npm install @qauth-labs/plugin-sdk@0.2.0-rc.1 zod
```

Install the version of the QAuth release your plugin is for: the SDK carries
QAuth's own version, and a server refuses a plugin written against another
contract version ([Versions](#versions)). A release candidate is on npm's
`next` dist-tag and a release on `latest`; until QAuth's first SDK release,
`latest` holds only a deprecated `0.0.0` placeholder. `zod` is a peer dependency: a method's config schema is a Zod 4 schema, and the
server reads it (its JSON Schema, its `writeOnly` marks) with its own copy.

## Write the method

The package exports its method as `authMethod`:

```ts
import { AUTH_METHOD_CONTRACT, type AuthMethod, UPSTREAM_STEP_URN } from '@qauth-labs/plugin-sdk';
import { z } from 'zod';

const configSchema = z.object({
  clientId: z.string().min(1),
  // A secret member: the server keeps it write-only and encrypted at rest.
  clientSecret: z.string().min(1).meta({ writeOnly: true }),
});

export const authMethod: AuthMethod<z.output<typeof configSchema>, MyTransaction> = {
  contract: AUTH_METHOD_CONTRACT,
  type: 'corp_sso', // its route segment: /upstream/corp_sso/…
  id: 'corp-sso', // the name the admin API gives the plugin
  display: { name: 'Corp SSO' },
  configSchema,
  steps: [UPSTREAM_STEP_URN],
  routes: [/* the callback the provider sends the browser back to */],
  async start(request, context) {
    /* where the browser goes */
  },
  async verify(result) {
    /* only results of its own callback, once each */
  },
  extractAttributes(identity) {
    /* attributes under its own type */
  },
};
```

A method is handed only its context: its config for the realm, the egress
client (every outbound call goes through it, never `fetch`), the signer (for a
client assertion; no key) and a logger. It never sees a database, a cookie or a
request header.

Some names are taken. A method's `type` may not be one QAuth writes itself
(`RESERVED_AUTH_METHOD_TYPES`), which the kit checks. Its `type` may not start
with `oidc_`, and its `id` may not be `oidc`: both belong to QAuth's generic
OpenID Connect client. The kit, which checks that client too, lets those two
pass, and the server refuses them at boot.

[`examples/minimal-plugin`](./examples/minimal-plugin) is a complete method
for an OAuth 2.0 provider with PKCE and a userinfo endpoint, with its test.

## Test it with the kit

```ts
import { checkAuthMethod } from '@qauth-labs/plugin-sdk/testing';

await checkAuthMethod(authMethod, {
  config: { clientId: 'kit-client', clientSecret: 'kit-client-secret-0123' },
  egress: (request) => fakeProvider.answer(request),
  callback: (authorizationRequest) => fakeProvider.signIn(authorizationRequest),
  declined: (authorizationRequest) => fakeProvider.decline(authorizationRequest),
});
```

You play the provider. The kit runs the method the way the server does, with
the server's own checks, and rejects with an `AuthMethodContractError` that
lists every check the method failed: the static checks, a fresh transaction and
binding for each start, the binding carried back, PKCE with S256, `verify()`
refusing what its callback did not produce, no `fetch`, and no secret in a log
line. It works in any test runner, and refuses to run with
`NODE_ENV=production`, because it replaces the global `fetch` while it runs.

## Or write a preset

For an OpenID Connect provider, export a preset as `upstreamOidcPreset` and let
the server run the protocol: discovery, PKCE with S256, `state` and `nonce`, the
ID token checks and the token request are its own.

```ts
import { defineUpstreamOidcPreset } from '@qauth-labs/plugin-sdk';
import { z } from 'zod';

export const upstreamOidcPreset = defineUpstreamOidcPreset({
  id: 'example-idp',
  type: 'example_idp',
  display: { name: 'Example IdP' },
  origins: ['https://idp.example.com'],
  configSchema: z.strictObject({
    clientId: z.string().min(1).max(255),
    clientSecret: z.string().min(1).max(1024).meta({ writeOnly: true }),
  }),
  upstreamConfig: (config) => ({
    issuer: 'https://idp.example.com',
    clientId: config.clientId,
    clientAuthentication: { method: 'client_secret_basic', clientSecret: config.clientSecret },
  }),
});
```

`checkUpstreamOidcPreset(upstreamOidcPreset, { configs: [...] })` of
`@qauth-labs/plugin-sdk/testing` checks it without the server. The guide is
[docs.qauth.dev/extend/preset-plugins](https://docs.qauth.dev/extend/preset-plugins/).

## Publish it, and what the operator does

Publish the package's compiled JavaScript (Node does not strip TypeScript types
under `node_modules`). List `@qauth-labs/plugin-sdk` under `dependencies`: the
contract's constants are part of your method at run time. List `zod` under
`peerDependencies`, so the method's schema is built with the server's Zod. Then
an operator:

1. installs the package with the deployment, as any other dependency of the
   auth server;
2. lists it by package name in `AUTH_METHOD_PLUGINS`;
3. turns on `PLUGIN_API_ENABLED=true`: a plugin outside QAuth's first-party list
   loads only while it is on, and the boot says so when it is off;
4. enables and configures it per realm through the admin API.

A plugin is trusted code that runs in-process. The server imports a package
only by its npm name, never a path or a URL.

## Entry points

| Entry point                      | What it holds                                                             |
| -------------------------------- | ------------------------------------------------------------------------- |
| `@qauth-labs/plugin-sdk`         | What a plugin imports: types, constants, errors, static checks.           |
| `@qauth-labs/plugin-sdk/testing` | The contract test kit, for a plugin's own tests.                          |
| `@qauth-labs/plugin-sdk/host`    | The host's half, which QAuth's server imports. A plugin does not need it. |

[`api-report.md`](./api-report.md) lists every name each one exports.

## Versions

The package carries QAuth's own version, from QAuth's release tag: a release
candidate `0.Y.Z-rc.N` is on the `next` dist-tag, a release on `latest`. The
contract it implements has a version of its own, `AUTH_METHOD_CONTRACT_VERSION`
(`1-rc.0`), a release candidate until QAuth 1.0.0. A breaking change to anything
this package exports raises it, and a server refuses a plugin written against
another version, so the boot fails instead of running a plugin against a
contract it does not know.

## License

Apache-2.0
