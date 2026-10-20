import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import { createLocalKekProvider, LOCAL_KEK_PROVIDER } from './default-kek-provider';
import type { KekProvider, KekProviderContext, KekProviderModule } from './kek-provider';

/** The `KEK_PROVIDER` default: the KEK from `KEK` or `KEK_PATH`. */
export const DEFAULT_KEK_PROVIDER = LOCAL_KEK_PROVIDER;

/** A provider name: lowercase letters, digits and inner hyphens, such as `cloud-kms`. */
export const KEK_PROVIDER_NAME = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;

/**
 * The optional package that holds the adapter named `name`:
 * `@qauth-labs/keys-<name>`. The auth server does not depend on any of them;
 * an operator installs the one they select.
 */
export function kekProviderPackage(name: string): string {
  return `@qauth-labs/keys-${name}`;
}

/** Imports an adapter package. Replaceable for tests. */
export type ImportKekProviderModule = (specifier: string) => Promise<unknown>;

const importModule: ImportKekProviderModule = (specifier) => import(specifier);

/**
 * Whether `error` says that `specifier` itself is missing, rather than a
 * package the adapter imports. Node quotes the missing name on the first line
 * of the message, and a stack of requiring files follows it unquoted.
 */
function isMissingPackage(error: unknown, specifier: string): boolean {
  if (!(error instanceof Error)) return false;
  const code = (error as NodeJS.ErrnoException).code;
  if (code !== 'ERR_MODULE_NOT_FOUND' && code !== 'MODULE_NOT_FOUND') return false;
  const firstLine = error.message.split('\n', 1)[0];
  return firstLine.includes(`'${specifier}'`) || firstLine.includes(`"${specifier}"`);
}

function isKekProvider(value: unknown): value is KekProvider {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate['name'] === 'string' &&
    typeof candidate['wrap'] === 'function' &&
    typeof candidate['unwrap'] === 'function' &&
    typeof candidate['health'] === 'function'
  );
}

function factoryOf(module: unknown): KekProviderModule['createKekProvider'] | undefined {
  if (typeof module !== 'object' || module === null) return undefined;
  const direct = (module as Partial<KekProviderModule>).createKekProvider;
  if (typeof direct === 'function') return direct;
  // A CommonJS adapter imported from ESM arrives under `default`.
  const fallback = (module as { default?: Partial<KekProviderModule> }).default?.createKekProvider;
  return typeof fallback === 'function' ? fallback : undefined;
}

/**
 * Create the KEK provider that `KEK_PROVIDER` selects (ADR-019 Decision 9).
 *
 * - Unset or blank selects `local`, the KEK from `KEK` or `KEK_PATH`.
 * - Any other name loads `@qauth-labs/keys-<name>` and calls its
 *   `createKekProvider(context)`. The package is imported only when selected,
 *   so a deployment that does not use an adapter never loads it.
 *
 * Only the signer role creates a provider: it is the one role that holds the
 * KEK.
 *
 * @param importAdapter - replaces the dynamic `import()`, for tests
 * @throws InvalidConfigurationError for a malformed name, a package that is
 *   not installed or does not export `createKekProvider`, or an adapter that
 *   returns no provider or one under another name. The adapter's own settings
 *   errors pass through.
 */
export async function loadKekProvider(
  context: KekProviderContext,
  importAdapter: ImportKekProviderModule = importModule
): Promise<KekProvider> {
  const name = context.env['KEK_PROVIDER']?.trim() || DEFAULT_KEK_PROVIDER;
  if (!KEK_PROVIDER_NAME.test(name)) {
    throw new InvalidConfigurationError(
      'KEK_PROVIDER must be a provider name of lowercase letters, digits and hyphens, such as `local`. See this error\'s "details" for the value.',
      { variable: 'KEK_PROVIDER', value: name }
    );
  }
  if (name === LOCAL_KEK_PROVIDER) return createLocalKekProvider(context);

  const specifier = kekProviderPackage(name);
  let module: unknown;
  try {
    module = await importAdapter(specifier);
  } catch (error) {
    if (isMissingPackage(error, specifier)) {
      throw new InvalidConfigurationError(
        'KEK_PROVIDER names a KEK provider whose package is not installed. Install the package or set KEK_PROVIDER=local. See this error\'s "details" for the package.',
        { variable: 'KEK_PROVIDER', value: name, package: specifier }
      );
    }
    throw error;
  }

  const createKekProvider = factoryOf(module);
  if (createKekProvider === undefined) {
    throw new InvalidConfigurationError(
      'The package KEK_PROVIDER selects does not export createKekProvider. See this error\'s "details" for the package.',
      { variable: 'KEK_PROVIDER', value: name, package: specifier }
    );
  }

  const provider = await createKekProvider(context);
  if (!isKekProvider(provider)) {
    throw new InvalidConfigurationError(
      'The package KEK_PROVIDER selects returned something that is not a KEK provider. See this error\'s "details" for the package.',
      { variable: 'KEK_PROVIDER', value: name, package: specifier }
    );
  }
  if (provider.name !== name) {
    throw new InvalidConfigurationError(
      'The package KEK_PROVIDER selects returned a provider under another name. See this error\'s "details" for both names.',
      { variable: 'KEK_PROVIDER', value: name, package: specifier, provider: provider.name }
    );
  }
  return provider;
}
