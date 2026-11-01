import { publicJwkProblem } from '@qauth-labs/shared-validation';
import { z } from 'zod';

/**
 * One public JWK an operator writes for a client that authenticates with
 * `private_key_jwt`: the system client's keys (`provision.ts`) and a seed
 * manifest entry's `jwks` (`seed-manifest.ts`). The server only ever needs a
 * client's public key, so a key carrying private material is an operator
 * mistake refused loudly rather than stored. A key of a known type must carry
 * the public members its type needs, or the token endpoint would refuse
 * every assertion it signs while the provisioner reported success. Any other
 * member, and a key type the server may not use, is left to the verifier.
 *
 * The rule is `publicJwkProblem` (`@qauth-labs/shared-validation`), which the
 * auth server applies to the key sets clients publish (#935). The module
 * reaches only `zod` and the shared validation rules the provisioner already
 * imports, so the migration runner bundles it with the provisioner.
 */
export const publicJwkSchema = z
  .object({ kty: z.string().min(1) })
  .catchall(z.unknown())
  .superRefine((jwk, ctx) => {
    const problem = publicJwkProblem(jwk);
    if (problem !== undefined) {
      ctx.addIssue({ code: 'custom', message: problem.message });
    }
  });
