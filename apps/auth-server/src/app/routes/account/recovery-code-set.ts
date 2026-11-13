import { RECOVERY_CODE_COUNT } from '@qauth-labs/fastify-plugin-sign-in-engine';
import { z } from 'zod';

import { rfc3339 } from '../../api-conventions/time';
import type { IssuedRecoveryCodes } from '../../helpers/account-factors';

/**
 * A set of recovery codes as the account contract's `RecoveryCodeSet` states
 * it (#1109): the ten codes, shown once, and when the set was issued. The
 * engine draws a code in lowercase base32; the contract shows it in
 * uppercase, and a code is typed back in either case.
 */
export const recoveryCodeSetSchema = z.strictObject({
  codes: z
    .array(
      z
        .string()
        .regex(/^[A-Z2-7]{4}(?:-[A-Z2-7]{4}){3}$/)
        .meta({ description: 'One code. It works once.' })
    )
    .length(RECOVERY_CODE_COUNT)
    .meta({ description: 'The ten codes. Shown once: the server keeps only their hashes.' }),
  issuedAt: z.iso.datetime().meta({ description: 'When the set was issued.' }),
});

/** A set, as the API answers it once. */
export function toRecoveryCodeSet(set: IssuedRecoveryCodes): z.infer<typeof recoveryCodeSetSchema> {
  return {
    codes: set.codes.map((code) => code.toUpperCase()),
    issuedAt: rfc3339(set.issuedAt),
  };
}
