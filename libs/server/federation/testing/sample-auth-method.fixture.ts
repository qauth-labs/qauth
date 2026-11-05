import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import { z } from 'zod';

import {
  AUTH_METHOD_CONTRACT,
  type AuthMethod,
  type AuthMethodEgressResponse,
  type AuthMethodParameters,
  UPSTREAM_STEP_URN,
  type UpstreamCallbackOutcome,
  type UserAttribute,
  type VerifiedIdentity,
} from '../src';

/**
 * A sample AuthMethod for the registry's and the plugin loader's tests (#599,
 * #600): a small authorization-code method against a fake provider, written
 * the way a plugin author would write one. It is not OpenID Connect; the
 * generic OIDC upstream client is #601. The contract's own tests, and the
 * kit's, run the same method in `@qauth-labs/plugin-sdk`
 * (`libs/sdk/plugin-sdk/testing/sample-auth-method.fixture.ts`).
 *
 * What it shows:
 *
 * - `start()` makes a fresh `state`, sends it to the provider and answers it
 *   as the binding, so the host refuses a callback that does not carry it
 *   back before the method runs;
 * - the callback compares `state` with its transaction too, in constant
 *   time, before it spends the code: belt and braces, at no cost;
 * - the authorization request uses PKCE with S256 (RFC 7636; QAuth requires
 *   it): `start()` keeps the verifier in the transaction and sends its
 *   challenge, and the callback sends the verifier with the code;
 * - the code is redeemed through `context.egress`, never `fetch`;
 * - an answer that is not JSON is an `invalid_response`, not a throw;
 * - `verify()` accepts only results its own callback produced (a `WeakSet`
 *   of them), so nothing else can sign anyone in through it;
 * - a `form_post` answer arrives at a bounce route, which sends the browser
 *   on to the `GET` callback on the same origin.
 */

/** The provider's endpoints in the kit's scenario. */
const PROVIDER = 'https://provider.example';

const sampleConfigSchema = z.object({
  authorizationEndpoint: z.url(),
  tokenEndpoint: z.url(),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).meta({ writeOnly: true }),
});

type SampleConfig = z.output<typeof sampleConfigSchema>;

interface SampleTransaction {
  readonly state: string;
  /** The PKCE verifier (RFC 7636 §4.1): 32 random bytes, base64url. */
  readonly codeVerifier: string;
}

interface SampleResult {
  readonly sub: string;
  readonly email: string;
  readonly emailVerified: boolean;
}

/** One parameter's single value; a missing or repeated one is `undefined`. */
function single(parameters: AuthMethodParameters, name: string): string | undefined {
  const value = parameters[name];
  return typeof value === 'string' ? value : undefined;
}

/** The S256 code challenge of a PKCE verifier (RFC 7636 §4.2). */
function s256(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

function sameState(expected: string, presented: string | undefined): boolean {
  if (presented === undefined) return false;
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(presented, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Options of {@link createSampleAuthMethod}. */
export interface SampleAuthMethodOptions {
  /** The method's type. Default `oidc_sample`. */
  readonly type?: string;
}

/** The sample method. Each call makes a method with its own set of results. */
export function createSampleAuthMethod(
  options: SampleAuthMethodOptions = {}
): AuthMethod<SampleConfig, SampleTransaction> {
  const type = options.type ?? 'oidc_sample';
  const issued = new WeakSet<object>();

  return {
    contract: AUTH_METHOD_CONTRACT,
    type,
    id: 'sample',
    display: { name: 'Sample provider' },
    configSchema: sampleConfigSchema,
    steps: [UPSTREAM_STEP_URN],

    async start(_request, context) {
      const state = randomBytes(16).toString('base64url');
      const codeVerifier = randomBytes(32).toString('base64url');
      const url = new URL(context.config.authorizationEndpoint);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', context.config.clientId);
      url.searchParams.set('redirect_uri', context.routeUrl('/callback'));
      url.searchParams.set('state', state);
      url.searchParams.set('code_challenge', s256(codeVerifier));
      url.searchParams.set('code_challenge_method', 'S256');
      return { redirectTo: url.href, transaction: { state, codeVerifier }, binding: state };
    },

    routes: [
      {
        kind: 'callback',
        method: 'GET',
        path: '/callback',
        async handle(request, context): Promise<UpstreamCallbackOutcome> {
          // State first, before anything is spent: a callback that does not
          // belong to this transaction never reaches the provider.
          if (!sameState(request.transaction.state, single(request.query, 'state'))) {
            return { kind: 'failed', reason: 'transaction_mismatch' };
          }
          const error = single(request.query, 'error');
          if (error === 'access_denied') return { kind: 'declined' };
          if (error !== undefined) return { kind: 'failed', reason: 'provider_error' };
          const code = single(request.query, 'code');
          if (code === undefined) return { kind: 'failed', reason: 'invalid_response' };

          let answer: AuthMethodEgressResponse;
          try {
            answer = await context.egress.request({
              method: 'POST',
              url: context.config.tokenEndpoint,
              headers: { 'content-type': 'application/x-www-form-urlencoded' },
              body: new URLSearchParams({
                grant_type: 'authorization_code',
                code,
                code_verifier: request.transaction.codeVerifier,
                client_id: context.config.clientId,
                client_secret: context.config.clientSecret,
                redirect_uri: context.routeUrl('/callback'),
              }).toString(),
              purpose: 'upstream-token',
              source: 'admin',
            });
          } catch {
            context.log.warn({ type }, 'the sample provider could not be reached');
            return { kind: 'failed', reason: 'upstream_unavailable' };
          }
          if (answer.status !== 200) return { kind: 'failed', reason: 'invalid_response' };
          let body: unknown;
          try {
            body = JSON.parse(Buffer.from(answer.body).toString('utf8'));
          } catch {
            return { kind: 'failed', reason: 'invalid_response' };
          }
          const parsed = z
            .object({
              sub: z.string().min(1).max(255),
              email: z.email(),
              email_verified: z.boolean(),
            })
            .safeParse(body);
          if (!parsed.success) return { kind: 'failed', reason: 'invalid_response' };

          const result: SampleResult = Object.freeze({
            sub: parsed.data.sub,
            email: parsed.data.email,
            emailVerified: parsed.data.email_verified,
          });
          issued.add(result);
          return { kind: 'result', result };
        },
      },
      {
        kind: 'bounce',
        method: 'POST',
        path: '/callback',
        async handle(request) {
          const query: Record<string, string> = {};
          for (const name of ['code', 'state', 'error']) {
            const value = single(request.form, name);
            if (value !== undefined) query[name] = value;
          }
          return { to: '/callback', query };
        },
      },
    ],

    async verify(input: unknown): Promise<VerifiedIdentity> {
      if (typeof input !== 'object' || input === null || !issued.has(input)) {
        throw new Error('not a result of this method');
      }
      // Single use: a result signs one person in once.
      issued.delete(input);
      const result = input as SampleResult;
      return {
        externalSub: result.sub,
        assuranceLevel: 'low',
        rawClaims: {
          iss: PROVIDER,
          sub: result.sub,
          email: result.email,
          email_verified: result.emailVerified,
        },
      };
    },

    extractAttributes(identity: VerifiedIdentity): UserAttribute[] {
      const email = identity.rawClaims['email'];
      if (typeof email !== 'string') return [];
      return [
        {
          source: type,
          attrKey: 'email',
          attrValue: email,
          verified: identity.rawClaims['email_verified'] === true,
        },
      ];
    },
  };
}
