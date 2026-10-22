import { z } from 'zod';

import { extensibleEnum } from '../envelope';

/**
 * Field schemas the event types share. Each carries its description, so the
 * published schema and the docs page explain it.
 */

/** The release the event contract first ships in. Every type defined with it has this `since`. */
export const FIRST_RELEASE = 'v0.2.0' as const;

/** A machine-readable `snake_case` code, such as an OAuth `error` or a refusal reason. */
const snakeCode = () =>
  z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z][a-z0-9_]*$/);

/** The OAuth or OpenID Connect `error` code of a refused request. */
export const oauthError = () =>
  snakeCode().describe(
    'The OAuth or OpenID Connect `error` code the request was refused with, such as `invalid_grant`.'
  );

/** Why something was refused, as a `snake_case` code. Never an exception message. */
export const reason = () =>
  snakeCode().describe(
    'Why, as a `snake_case` code such as `invalid_credentials`. The set may grow in a minor release.'
  );

/** A list of OAuth scope values. */
export const scopeList = (description: string) =>
  z.array(z.string().min(1).max(255)).max(256).describe(description);

/**
 * A keyed HMAC of an identifier that must stay hidden (payload rule 3):
 * HMAC-SHA-256 under a server-side key, base64url without padding.
 */
export const identifierHmac = () =>
  z
    .string()
    .regex(/^[A-Za-z0-9_-]{43}$/)
    .describe(
      'A keyed HMAC (HMAC-SHA-256, base64url) of the identifier the person typed, so repeated attempts at one identifier can be correlated without revealing it. Absent when the attempt named a known user, who is then the subject.'
    );

/** How a person proved who they are. */
export const SIGN_IN_METHODS = ['password', 'wallet'] as const;
export const signInMethod = () =>
  extensibleEnum(SIGN_IN_METHODS).describe(
    '`password`: an identifier and a password. `wallet`: a credential presented from a wallet (OpenID4VP). The set may grow in a minor release.'
  );

/** The verifier profile of a wallet presentation (ADR-009), such as `haip-1.0`. */
export const verifierProfile = () =>
  z
    .string()
    .min(1)
    .max(64)
    .describe(
      'The verifier profile the wallet presentation was checked under, such as `haip-1.0`.'
    );

/** The agent scope modes (ADR-007 §2). */
export const SCOPE_MODES = ['readonly', 'admin', 'exec'] as const;
export const scopeMode = () =>
  extensibleEnum(SCOPE_MODES).describe(
    'The agent scope mode (ADR-007 §2) the request was granted: `readonly`, `admin` or `exec`.'
  );

/** A database id, such as a refresh family's or a consent's. */
export const recordId = (description: string) => z.uuid().describe(description);

/** A count of something. */
export const count = (description: string) => z.int().min(0).max(1_000_000).describe(description);
