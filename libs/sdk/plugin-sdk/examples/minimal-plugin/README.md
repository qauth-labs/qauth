# A minimal QAuth plugin

A sign-in method for an OAuth 2.0 provider with an authorization-code flow,
PKCE and a userinfo endpoint, written against `@qauth-labs/plugin-sdk` alone:
the shape of a plugin in its own repository. It exports its method as
`authMethod` and passes the contract test kit.

| File                   | What it is                                                      |
| ---------------------- | --------------------------------------------------------------- |
| `src/index.ts`         | The plugin: its config schema and `authMethod`.                 |
| `src/fake-provider.ts` | The provider, as the kit's scenario plays it. Test support.     |
| `src/index.test.ts`    | `checkAuthMethod`, under Node's own test runner.                |
| `tsconfig.json`        | The build: Node's ESM and declarations, from `src/` to `dist/`. |

QAuth's release workflow builds and runs this example against the packed SDK in
an empty project on every pull request (`scripts/sdk-release/smoke.mjs`), so it
stays a plugin that installs, type-checks and passes the kit.

## In your own repository

Copy `src/` and `tsconfig.json`, and add a `package.json` like this one:

```json
{
  "name": "@example/qauth-plugin-example-oauth",
  "version": "0.1.0",
  "type": "module",
  "exports": {
    ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js" }
  },
  "files": ["dist/index.js", "dist/index.d.ts"],
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "test": "npm run build && node --test dist/index.test.js"
  },
  "dependencies": {
    "@qauth-labs/plugin-sdk": "0.2.0-rc.1"
  },
  "peerDependencies": {
    "zod": "^4.6.7"
  },
  "devDependencies": {
    "@types/node": "^22",
    "typescript": "^6.0.3",
    "zod": "^4.6.7"
  }
}
```

Pin the SDK to the QAuth release you build against: the contract version it
carries (`AUTH_METHOD_CONTRACT`, `qauth-auth-method/1-rc.0`) is the one your
plugin declares, and a server refuses a plugin written against another. `zod`
is a peer dependency, so the method's schema is built with the server's Zod.

Then `npm test` builds the plugin and runs the kit, and `npm publish` ships
`dist/index.js` and its declarations.

## Installing it in a deployment

The operator installs the package with the deployment, lists it in
`AUTH_METHOD_PLUGINS`, and turns on `PLUGIN_API_ENABLED=true`:

```sh
AUTH_METHOD_PLUGINS=@example/qauth-plugin-example-oauth
PLUGIN_API_ENABLED=true
```

Each realm then enables the plugin and gives it a config (`issuer`, the three
endpoints, `clientId`, and `clientSecret`, sealed first) through the admin
API. See the
[AuthMethod contract](https://docs.qauth.dev/extend/auth-method-contract/#write-a-plugin-in-your-own-repository).
