/**
 * A minimal QAuth sign-in method plugin: an OAuth 2.0 provider with an
 * authorization-code flow, PKCE and a userinfo endpoint, written against
 * `@qauth-labs/plugin-sdk` alone, as a plugin in its own repository is.
 *
 * The package exports its method as `authMethod`; the operator installs the
 * package with the deployment and lists it in `AUTH_METHOD_PLUGINS`.
 *
 * What it shows:
 *
 * - `start()` makes a fresh `state` and PKCE verifier for each sign-in, keeps
 *   both in the transaction, sends the provider the state and the verifier's
 *   S256 challenge, and answers the state as the binding: the server refuses a
 *   callback that does not carry it back before the method runs;
 * - every outbound call goes through `context.egress`, never `fetch`, and a
 *   call that carries a credential (the code, the client secret, the access
 *   token) follows no redirect;
 * - the provider's answers are parsed and checked, and a bad one is an
 *   outcome (`invalid_response`), never a throw;
 * - `verify()` accepts only the results its own callback produced, each once,
 *   so nothing else can sign anyone in through the method;
 * - the client secret is a `writeOnly` member of the config, and nothing logs
 *   it.
 */
import { createHash, randomBytes } from 'node:crypto';

import {
  AUTH_METHOD_CONTRACT,
  type AuthMethod,
  type AuthMethodContext,
  type AuthMethodEgressResponse,
  type AuthMethodParameters,
  UPSTREAM_STEP_URN,
  type UpstreamCallbackOutcome,
  type UserAttribute,
  type VerifiedIdentity,
} from '@qauth-labs/plugin-sdk';
import { z } from 'zod';

/** The method's type: its route segment, `/upstream/example_oauth/…`. */
const TYPE = 'example_oauth';

/** The config an admin gives the method for one realm. */
export const configSchema = z.object({
  /** The provider's issuer identifier, the `iss` of every identity. */
  issuer: z.url(),
  authorizationEndpoint: z.url(),
  tokenEndpoint: z.url(),
  userinfoEndpoint: z.url(),
  clientId: z.string().min(1).max(255),
  /** Write-only: the server stores it encrypted and never shows it again. */
  clientSecret: z.string().min(1).max(1024).meta({ writeOnly: true }),
});

export type ExampleConfig = z.output<typeof configSchema>;

/** What the method keeps between `start()` and its callback. */
interface ExampleTransaction {
  readonly state: string;
  /** The PKCE verifier (RFC 7636 §4.1): 32 random bytes, base64url. */
  readonly codeVerifier: string;
}

/** What the callback hands `verify()`. */
interface ExampleResult {
  readonly issuer: string;
  readonly sub: string;
  readonly email: string | undefined;
  readonly emailVerified: boolean;
}

const userinfoSchema = z.object({
  sub: z.string().min(1).max(255),
  email: z.email().optional(),
  email_verified: z.boolean().optional(),
});

/** The results this method's callback produced and `verify()` has not used yet. */
const issued = new WeakSet<object>();

/** One parameter's single value; a missing or repeated one is `undefined`. */
function single(parameters: AuthMethodParameters, name: string): string | undefined {
  const value = parameters[name];
  return typeof value === 'string' ? value : undefined;
}

/** The S256 code challenge of a PKCE verifier (RFC 7636 §4.2). */
function s256(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/** A JSON body, or `undefined` when the answer is not a 200 with JSON. */
function json(answer: AuthMethodEgressResponse): unknown {
  if (answer.status !== 200) return undefined;
  try {
    return JSON.parse(Buffer.from(answer.body).toString('utf8')) as unknown;
  } catch {
    return undefined;
  }
}

/** Redeem the code at the token endpoint; the access token, or an outcome. */
async function redeem(
  code: string,
  transaction: ExampleTransaction,
  context: AuthMethodContext<ExampleConfig>
): Promise<string | UpstreamCallbackOutcome> {
  const { config } = context;
  let answer: AuthMethodEgressResponse;
  try {
    answer = await context.egress.request({
      method: 'POST',
      url: config.tokenEndpoint,
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        code_verifier: transaction.codeVerifier,
        redirect_uri: context.routeUrl('/callback'),
        client_id: config.clientId,
        client_secret: config.clientSecret,
      }).toString(),
      purpose: 'upstream-token',
      source: 'admin',
      // The body carries the code and the secret: a 307 must not send it on.
      redirect: 'error',
    });
  } catch {
    context.log.warn({ type: TYPE }, 'the token endpoint could not be reached');
    return { kind: 'failed', reason: 'upstream_unavailable' };
  }
  const token = z.object({ access_token: z.string().min(1) }).safeParse(json(answer));
  return token.success ? token.data.access_token : { kind: 'failed', reason: 'invalid_response' };
}

/** Read the person at the userinfo endpoint; their claims, or an outcome. */
async function userinfo(
  accessToken: string,
  context: AuthMethodContext<ExampleConfig>
): Promise<z.output<typeof userinfoSchema> | UpstreamCallbackOutcome> {
  let answer: AuthMethodEgressResponse;
  try {
    answer = await context.egress.request({
      method: 'GET',
      url: context.config.userinfoEndpoint,
      headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' },
      purpose: 'upstream-userinfo',
      source: 'admin',
      // The request carries the access token: follow no redirect with it.
      redirect: 'error',
    });
  } catch {
    context.log.warn({ type: TYPE }, 'the userinfo endpoint could not be reached');
    return { kind: 'failed', reason: 'upstream_unavailable' };
  }
  const claims = userinfoSchema.safeParse(json(answer));
  return claims.success ? claims.data : { kind: 'failed', reason: 'invalid_response' };
}

/** The plugin's method: what the package exports as `authMethod`. */
export const authMethod: AuthMethod<ExampleConfig, ExampleTransaction> = {
  contract: AUTH_METHOD_CONTRACT,
  type: TYPE,
  id: 'example-oauth',
  display: { name: 'Example provider' },
  configSchema,
  steps: [UPSTREAM_STEP_URN],

  async start(request, context) {
    const state = randomBytes(16).toString('base64url');
    const codeVerifier = randomBytes(32).toString('base64url');
    const url = new URL(context.config.authorizationEndpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', context.config.clientId);
    url.searchParams.set('redirect_uri', context.routeUrl('/callback'));
    url.searchParams.set('scope', 'openid email');
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', s256(codeVerifier));
    url.searchParams.set('code_challenge_method', 'S256');
    if (request.uiLocales.length > 0)
      url.searchParams.set('ui_locales', request.uiLocales.join(' '));
    return { redirectTo: url.href, transaction: { state, codeVerifier }, binding: state };
  },

  routes: [
    {
      kind: 'callback',
      method: 'GET',
      path: '/callback',
      // The server has already matched `state` with this transaction's binding.
      async handle(request, context): Promise<UpstreamCallbackOutcome> {
        const error = single(request.query, 'error');
        if (error === 'access_denied') return { kind: 'declined' };
        if (error !== undefined) return { kind: 'failed', reason: 'provider_error' };
        const code = single(request.query, 'code');
        if (code === undefined) return { kind: 'failed', reason: 'invalid_response' };

        const accessToken = await redeem(code, request.transaction, context);
        if (typeof accessToken !== 'string') return accessToken;
        const claims = await userinfo(accessToken, context);
        if ('kind' in claims) return claims;

        const result: ExampleResult = Object.freeze({
          issuer: context.config.issuer,
          sub: claims.sub,
          email: claims.email,
          emailVerified: claims.email_verified === true,
        });
        issued.add(result);
        return { kind: 'result', result };
      },
    },
  ],

  async verify(input: unknown): Promise<VerifiedIdentity> {
    if (typeof input !== 'object' || input === null || !issued.has(input)) {
      throw new Error('not a result of this method');
    }
    // Single use: a result signs one person in once.
    issued.delete(input);
    const result = input as ExampleResult;
    return {
      externalSub: result.sub,
      assuranceLevel: 'low',
      rawClaims: {
        // The issuer that assigned `sub`: a subject is unique only within it.
        iss: result.issuer,
        sub: result.sub,
        ...(result.email === undefined
          ? {}
          : { email: result.email, email_verified: result.emailVerified }),
      },
    };
  },

  extractAttributes(identity: VerifiedIdentity): UserAttribute[] {
    const email = identity.rawClaims['email'];
    if (typeof email !== 'string') return [];
    return [
      {
        source: TYPE,
        attrKey: 'email',
        attrValue: email,
        verified: identity.rawClaims['email_verified'] === true,
      },
    ];
  },
};
