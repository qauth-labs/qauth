import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

/**
 * TEST SUPPORT — an upstream OpenID Connect preset package written as a
 * provider plugin in its own repository writes one (#671): plain JavaScript
 * that imports the published plugin SDK, `@qauth-labs/plugin-sdk`, and its
 * peer Zod, and nothing of the server. Its `upstreamOidcPreset` export is
 * the SDK's `defineUpstreamOidcPreset`; the server builds the method on its
 * own OpenID Connect client.
 *
 * The package is written into a directory of its own outside the workspace,
 * with a `node_modules` that links the two packages it depends on: the SDK
 * this workspace builds, and the Zod the server imports, so the preset's
 * schema is built with the server's Zod, the peer a deployment installs
 * once. The test's importer imports it from there, through the test runner,
 * which compiles the SDK's TypeScript source as a published build would
 * ship it compiled.
 *
 * The preset is a multi-tenant provider on one origin, as the plugins of
 * #1074–#1076 are: `tenant` shapes the issuer's path, and the multi-tenant
 * endpoint `organizations` takes a token of any tenant whose issuer is the
 * template with the token's `tid`. With `formPost` the provider answers by
 * `form_post`, and the response member `profile` the callback reads rides
 * the bounce; its `name` becomes the `nickname` claim.
 */

/** The workspace root, from `apps/auth-server/src/testing`. */
const WORKSPACE_ROOT = resolve(__dirname, '../../../..');

/** The package's npm name, the value `AUTH_METHOD_PLUGINS` lists. */
export const SDK_PRESET_PACKAGE = '@example/qauth-plugin-sdk-idp';

/** The preset's AuthMethod id, the admin API's name for it. */
export const SDK_PRESET_ID = 'sdk-idp';

/** The preset's AuthMethod type: its callback is `/upstream/sdk_idp/callback`. */
export const SDK_PRESET_TYPE = 'sdk_idp';

/** The provider's one origin. */
export const SDK_PRESET_ORIGIN = 'https://login.sdk-idp.example';

/** The multi-tenant endpoint's tenant segment. */
export const SDK_PRESET_MULTI_TENANT = 'organizations';

/** The provider's issuer for `tenant`. */
export function sdkPresetIssuer(tenant: string): string {
  return `${SDK_PRESET_ORIGIN}/${tenant}/v2`;
}

/** The issuer template of the multi-tenant endpoint. */
export const SDK_PRESET_ISSUER_TEMPLATE = sdkPresetIssuer('{tenantid}');

/** The response member the preset's callback reads. */
export const SDK_PRESET_MEMBER = 'profile';

/** The package's entry point: what its `dist/index.js` is. */
export const SDK_PRESET_SOURCE = `import { defineUpstreamOidcPreset, upstreamClaimIsTrue } from '@qauth-labs/plugin-sdk';
import { z } from 'zod';

const ORIGIN = ${JSON.stringify(SDK_PRESET_ORIGIN)};
const MULTI_TENANT = ${JSON.stringify(SDK_PRESET_MULTI_TENANT)};
const issuer = (tenant) => \`\${ORIGIN}/\${tenant}/v2\`;

/** The name of a profile member, or undefined. */
function profileName(value) {
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    return undefined;
  }
  const name = typeof parsed === 'object' && parsed !== null && Object.hasOwn(parsed, 'name') ? parsed.name : undefined;
  return typeof name === 'string' && name.length > 0 ? name : undefined;
}

export const upstreamOidcPreset = defineUpstreamOidcPreset({
  id: ${JSON.stringify(SDK_PRESET_ID)},
  type: ${JSON.stringify(SDK_PRESET_TYPE)},
  display: { name: 'SDK IdP' },
  origins: [ORIGIN],
  configSchema: z.strictObject({
    tenant: z.string().regex(/^[a-z0-9-]{1,64}$/),
    clientId: z.string().min(1).max(255),
    clientSecret: z.string().min(1).max(1024).meta({ writeOnly: true }),
    formPost: z.boolean().default(false),
  }),
  upstreamConfig: (config) => ({
    issuer: issuer(config.tenant),
    ...(config.tenant === MULTI_TENANT
      ? { tenantIssuer: { template: issuer('{tenantid}'), tenantClaim: 'tid' } }
      : {}),
    clientId: config.clientId,
    clientAuthentication: { method: 'client_secret_post', clientSecret: config.clientSecret },
    ...(config.formPost ? { responseMode: 'form_post' } : {}),
    idTokenSigningAlgorithms: ['RS256'],
  }),
  // Keeps the name and drops the rest, such as an address: what the bounce
  // carries on in the callback's URL. Given its own output, it gives it back.
  responseMembers: {
    ${SDK_PRESET_MEMBER}: (value) => {
      const name = profileName(value);
      return name === undefined ? undefined : JSON.stringify({ name });
    },
  },
  // The member's name as a nickname, and an address the member says is
  // verified: the client never takes the second, as the provider vouches for
  // an email, not a preset.
  identityClaims: ({ response }) => {
    const value = Object.hasOwn(response, ${JSON.stringify(SDK_PRESET_MEMBER)}) ? response[${JSON.stringify(SDK_PRESET_MEMBER)}] : undefined;
    const name = value === undefined ? undefined : profileName(value);
    return name === undefined
      ? {}
      : { nickname: name, email: 'made-up@sdk-idp.example', email_verified: true };
  },
  attributes: [
    { claim: 'email', verified: (claims) => upstreamClaimIsTrue(claims, 'email_verified') },
    { claim: 'name' },
    { claim: 'nickname' },
    { claim: 'tid' },
  ],
});
`;

/** The preset package, written on disk. */
export interface WrittenSdkPresetPackage {
  /** Its npm name, {@link SDK_PRESET_PACKAGE}. */
  readonly packageName: string;
  /** An importer for the loader's test support: the package, by its name. */
  readonly importPackage: (name: string) => Promise<unknown>;
  /** Deletes the package. */
  remove(): Promise<void>;
}

/** Write the preset package into a directory of its own. */
export async function writeSdkPresetPackage(): Promise<WrittenSdkPresetPackage> {
  const directory = await mkdtemp(join(tmpdir(), 'qauth-sdk-preset-'));
  const modules = join(directory, 'node_modules');
  await mkdir(join(modules, '@qauth-labs'), { recursive: true });
  await symlink(
    await realpath(join(WORKSPACE_ROOT, 'libs/sdk/plugin-sdk')),
    join(modules, '@qauth-labs', 'plugin-sdk'),
    'dir'
  );
  // The Zod the server itself imports.
  await symlink(
    await realpath(join(WORKSPACE_ROOT, 'libs/server/federation/node_modules/zod')),
    join(modules, 'zod'),
    'dir'
  );
  await writeFile(
    join(directory, 'package.json'),
    `${JSON.stringify(
      {
        name: SDK_PRESET_PACKAGE,
        version: '0.1.0',
        type: 'module',
        exports: { '.': { import: './index.js' } },
        peerDependencies: { '@qauth-labs/plugin-sdk': '*', zod: '^4.6.7' },
      },
      null,
      2
    )}\n`
  );
  const entry = join(directory, 'index.js');
  await writeFile(entry, SDK_PRESET_SOURCE);
  const url = pathToFileURL(entry).href;

  return {
    packageName: SDK_PRESET_PACKAGE,
    async importPackage(name: string) {
      if (name !== SDK_PRESET_PACKAGE) {
        const error = new Error(`Cannot find package '${name}' imported from the test`);
        (error as NodeJS.ErrnoException).code = 'ERR_MODULE_NOT_FOUND';
        throw error;
      }
      return import(/* @vite-ignore */ url);
    },
    remove: () => rm(directory, { recursive: true, force: true }),
  };
}

/** The bare specifiers `source` imports, in its order. */
export function importedPackages(source: string): string[] {
  return [...source.matchAll(/^import\s[^'"]*from\s+['"]([^'"]+)['"];?$/gm)].map(
    (match) => match[1]
  );
}
