import { JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyRequest } from 'fastify';

/**
 * The token's `sub`: a user of the request's realm once the account API's
 * guard passed. A missing one is an invariant broken, refused as a bad token
 * rather than trusted.
 */
export function tokenUserIdOf(request: FastifyRequest): string {
  const sub = request.jwtPayload?.sub;
  if (!sub) throw new JWTInvalidError('Missing JWT payload');
  return sub;
}
