import { randomBytes } from 'node:crypto';

import { isUniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

import { AUTHORIZATION_CODE_TTL_MS } from '../constants';

type CodeRepository = FastifyInstance['repositories']['authorizationCodes'];

/**
 * A transaction the code is written in: the caller's, when the mint is one
 * step of a larger unit (the consent re-check at `/oauth/authorize`).
 */
export type AuthorizationCodeTransaction = NonNullable<Parameters<CodeRepository['create']>[1]>;

/**
 * What an authorization code binds, as the mint site knows it.
 *
 * Every binding is listed, `null` where the request has none, so a new mint
 * site cannot drop one by leaving a key out: a missing `sessionExpiresAt`
 * would let the refresh family outlive the session (ADR-019 Decision 3), a
 * missing `dpopJkt` would unbind the code from its DPoP key (RFC 9449 §10).
 */
export interface AuthorizationCodeGrant {
  readonly oauthClientId: string;
  readonly userId: string;
  /** The redirect URI as requested; the token request must present it again. */
  readonly redirectUri: string;
  /** RFC 7636 §4.2 `code_challenge`; {@link mintAuthorizationCode} refuses a code without one. */
  readonly codeChallenge: string;
  /** RFC 7636 §4.3 `code_challenge_method`; only `S256` is minted. */
  readonly codeChallengeMethod: string;
  readonly scopes: string[];
  /** RFC 8707 resource indicators, the access token's `aud` at the token endpoint. */
  readonly resource: string[];
  /** OIDC Core §3.1.2.1 `nonce`, echoed into the ID token. */
  readonly nonce: string | null;
  /** RFC 6749 §4.1.1 `state`. */
  readonly state: string | null;
  /** When the end user authenticated (epoch ms), for the ID token's `auth_time`. */
  readonly authTime: number | null;
  /** The stored assurance level (`toStoredAssuranceLevel`), for the ID token's `acr`. */
  readonly assuranceLevel: string | null;
  /** The browser session's absolute end (epoch ms), which caps the refresh family. */
  readonly sessionExpiresAt: number | null;
  /** RFC 9449 §10 `dpop_jkt`: the key the token request must prove. */
  readonly dpopJkt: string | null;
}

/**
 * Refused before any code is written: the grant has no S256 PKCE challenge
 * QAuth would mint a code for. A mint site validates the request first, so
 * reaching this is a defect in the caller, answered as a server error.
 */
export class PkceChallengeRequiredError extends Error {
  constructor() {
    super(
      'an authorization code is minted only for an S256 PKCE challenge of 43 to 128 characters'
    );
    this.name = 'PkceChallengeRequiredError';
    Object.setPrototypeOf(this, PkceChallengeRequiredError.prototype);
  }
}

/**
 * RFC 7636 §4.2: `code-challenge = 43*128unreserved`, unreserved being
 * `ALPHA / DIGIT / "-" / "." / "_" / "~"` — the bounds the authorize schema
 * applies to the request.
 */
const CODE_CHALLENGE = /^[A-Za-z0-9._~-]{43,128}$/;

/** Collisions of a 256-bit random code are retried this many times in all. */
const MAX_MINT_ATTEMPTS = 3;

/**
 * Whether QAuth mints a code for this challenge: an S256 challenge of 43 to
 * 128 unreserved characters (RFC 7636 §4.2, §4.3), in every environment.
 */
export function isMintableCodeChallenge(challenge: unknown, method: unknown): boolean {
  return method === 'S256' && typeof challenge === 'string' && CODE_CHALLENGE.test(challenge);
}

/**
 * Mint an authorization code: the one place every code is created (ADR-017
 * Decision 10). `/oauth/authorize` and the consent screen call it today, and
 * every later issuer of codes calls it too.
 *
 * It refuses to write a code without an S256 PKCE challenge of 43 to 128
 * characters, whatever the environment policy, so every code is PKCE-bound by
 * construction (OAuth 2.1 §4.1.1; QAuth's profile is stricter than RFC 7636,
 * which leaves PKCE optional). The code is 32 random bytes in base64url and
 * lives `AUTHORIZATION_CODE_TTL_MS`.
 *
 * With `tx` the code is written in the caller's transaction, under a
 * savepoint, so the retry after a code collision leaves that transaction
 * usable; without it, each attempt is its own statement.
 *
 * @returns the code to send to the client
 * @throws PkceChallengeRequiredError when the grant has no mintable challenge
 */
export async function mintAuthorizationCode(
  fastify: Pick<FastifyInstance, 'repositories'>,
  grant: AuthorizationCodeGrant,
  tx?: AuthorizationCodeTransaction
): Promise<string> {
  if (!isMintableCodeChallenge(grant.codeChallenge, grant.codeChallengeMethod)) {
    throw new PkceChallengeRequiredError();
  }
  const codes = fastify.repositories.authorizationCodes;
  const expiresAt = Date.now() + AUTHORIZATION_CODE_TTL_MS;

  for (let attempt = 1; ; attempt++) {
    const code = randomBytes(32).toString('base64url');
    const row = {
      code,
      oauthClientId: grant.oauthClientId,
      userId: grant.userId,
      redirectUri: grant.redirectUri,
      codeChallenge: grant.codeChallenge,
      codeChallengeMethod: 'S256' as const,
      nonce: grant.nonce,
      authTime: grant.authTime,
      assuranceLevel: grant.assuranceLevel,
      sessionExpiresAt: grant.sessionExpiresAt,
      scopes: grant.scopes,
      resource: grant.resource,
      state: grant.state,
      dpopJkt: grant.dpopJkt,
      expiresAt,
    };
    try {
      if (tx === undefined) {
        await codes.create(row);
      } else {
        await tx.transaction((savepoint) => codes.create(row, savepoint));
      }
      return code;
    } catch (err) {
      if (!isUniqueConstraintError(err) || attempt === MAX_MINT_ATTEMPTS) throw err;
    }
  }
}
