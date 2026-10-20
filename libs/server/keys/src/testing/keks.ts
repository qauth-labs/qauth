import { createLocalKekProvider } from '../lib/default-kek-provider';
import type { KekEnv, KekProvider, KekWarning } from '../lib/kek-provider';

/**
 * KEKs and providers for this library's tests. Never exported from the
 * package entry point.
 */

/** A KEK whose 32 bytes are all `fill`, as `KEK` takes it. */
export function testKek(fill: number): string {
  return Buffer.alloc(32, fill).toString('base64');
}

export const KEK_A = testKek(0xa1);
export const KEK_B = testKek(0xb2);

/** A default provider over `env`, outside production unless `env` says otherwise. */
export function localProvider(env: KekEnv, warnings: KekWarning[] = []): KekProvider {
  return createLocalKekProvider({
    env: { NODE_ENV: 'test', ...env },
    warn: (warning) => warnings.push(warning),
  });
}
