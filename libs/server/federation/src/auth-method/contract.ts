import {
  AUTH_METHOD_DISPLAY_NAME_PATTERN,
  RESERVED_AUTH_METHOD_TYPES,
  UPSTREAM_STEP_URN,
} from '@qauth-labs/plugin-sdk';
import { DISPLAY_TEXT_PATTERN, stepUrn } from '@qauth-labs/shared-interaction-contract';
import type { ExperimentalItemId } from '@qauth-labs/shared-stability';

import { PASSWORD_PROVIDER_TYPE, SELF_REPORTED_SOURCE } from '../providers/password.provider';
import { WALLET_PROVIDER_TYPE } from '../providers/wallet.provider';
import { WEBAUTHN_PROVIDER_TYPE } from '../providers/webauthn.provider';

/**
 * The server's own values around the AuthMethod contract (#599, #600).
 *
 * The contract itself (its types, its constants, its errors, its checks and
 * the test kit) is declared once, in `@qauth-labs/plugin-sdk` (#1009), the
 * package a plugin is written against in its own repository; this library
 * re-exports it and declares none of it again
 * (`single-copy.test.ts`). What stays here is the server's: where the contract
 * stands in the experimental-feature registry.
 *
 * EXPERIMENTAL, like the contract.
 *
 * @packageDocumentation
 */

/**
 * Where the contract stands: experimental, under the experimental-feature
 * registry's item `plugin-api` (ADR-018 §4 and §5). The item id is typed
 * against the registry, so renaming the item there fails the typecheck here.
 *
 * @experimental
 */
export const AUTH_METHOD_STABILITY = Object.freeze({
  stability: 'experimental',
  experimentalItem: 'plugin-api' satisfies ExperimentalItemId,
} as const);

/**
 * The SDK imports no other QAuth package, so it writes out the three values
 * it shares with the server's other contracts. Each must still equal its
 * source here, or the server would hold plugins to a rule its own contracts
 * no longer state: the boot fails instead.
 */
function sharedValueDrift(): string[] {
  const drift: string[] = [];
  if (UPSTREAM_STEP_URN !== stepUrn('upstream')) {
    drift.push('UPSTREAM_STEP_URN does not match the Interaction API step name rule');
  }
  if (
    AUTH_METHOD_DISPLAY_NAME_PATTERN.source !== DISPLAY_TEXT_PATTERN ||
    AUTH_METHOD_DISPLAY_NAME_PATTERN.flags !== 'u'
  ) {
    drift.push("AUTH_METHOD_DISPLAY_NAME_PATTERN is not the Interaction API's display rule");
  }
  const builtIn = [
    PASSWORD_PROVIDER_TYPE,
    WALLET_PROVIDER_TYPE,
    WEBAUTHN_PROVIDER_TYPE,
    SELF_REPORTED_SOURCE,
  ];
  if (!builtIn.every((type) => RESERVED_AUTH_METHOD_TYPES.includes(type))) {
    drift.push('RESERVED_AUTH_METHOD_TYPES does not reserve every credential type QAuth writes');
  }
  return drift;
}

const drift = sharedValueDrift();
if (drift.length > 0) {
  throw new Error(`@qauth-labs/plugin-sdk has drifted from the server:\n- ${drift.join('\n- ')}`);
}
