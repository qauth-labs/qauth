import { LOCAL_KEK_PROVIDER } from './default-kek-provider';
import type { KekProvider } from './kek-provider';
import { computeKekRef, DEV_KEK_DEFAULT } from './kek-sources';

/** The `kekRef` of the published development KEK. */
export const DEVELOPMENT_KEK_REF = computeKekRef(Buffer.from(DEV_KEK_DEFAULT, 'base64'));

/**
 * Whether the provider wraps with the published development KEK. A key that
 * came from outside the deployment (a configured variable, a provider-issued
 * key) is never stored under it: wrapped with a published key, it would be as
 * good as plaintext.
 */
export async function usesDevelopmentKek(provider: KekProvider): Promise<boolean> {
  if (provider.name !== LOCAL_KEK_PROVIDER) return false;
  return (await provider.health()).kekRef === DEVELOPMENT_KEK_REF;
}
