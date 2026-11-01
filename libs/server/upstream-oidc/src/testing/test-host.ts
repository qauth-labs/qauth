import {
  type AuthMethod,
  type AuthMethodContext,
  type AuthMethodEgressResponse,
  type AuthMethodHostEgress,
  type AuthMethodHostSigner,
  createAuthMethodContext,
} from '@qauth-labs/server-federation';
import { exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';

import type { FakeProvider } from './fake-provider';

/**
 * TEST SUPPORT — the host side of a method's context for unit tests (#601):
 * an egress client that answers from a {@link FakeProvider} (or a test's own
 * handler), a signer role that holds its own key and signs client
 * assertions, and a logger that records every line. The method only ever
 * sees them through `createAuthMethodContext`, as in production.
 */

/** A call as the host's egress client received it, after the context's adapter. */
export type HostEgressCall = Parameters<AuthMethodHostEgress['request']>[0];

/** A signer call, as the host's signer received it. */
export interface HostSignerCall {
  readonly operation: 'signClientAssertion' | 'getUpstreamJwks';
  readonly caller: string;
  readonly realmId: string;
  readonly providerId: string;
  readonly request?: Readonly<Record<string, unknown>>;
}

export interface TestHost<TConfig> {
  readonly context: AuthMethodContext<TConfig>;
  readonly egressCalls: HostEgressCall[];
  readonly signerCalls: HostSignerCall[];
  /** Every log line: level, message and fields. */
  readonly logLines: { level: string; message: string; fields: Record<string, unknown> }[];
  /** The assertions the signer returned, in order. */
  readonly signedAssertions: string[];
  /** The signer's public key set, as `getUpstreamJwks` answers it. */
  readonly upstreamJwks: { keys: JWK[] };
}

export interface TestHostOptions {
  readonly origin?: string;
  readonly realmId?: string;
  readonly realmName?: string;
  /** The client id the signer's upstream client record names. */
  readonly signerClientId?: string;
  /** Answers instead of the provider. */
  readonly egress?: (call: HostEgressCall) => Promise<AuthMethodEgressResponse>;
}

export const TEST_ORIGIN = 'https://auth.example.com';
export const TEST_REALM_ID = '0190a5c4-0000-7000-8000-000000000001';

/** The signer role's own key: created here, never handed to the method. */
const signerKey = generateKeyPair('RS256', { extractable: true }).then(async (pair) => ({
  ...pair,
  publicJwk: {
    ...(await exportJWK(pair.publicKey)),
    kid: 'upstream-assertion-1',
    alg: 'RS256',
    use: 'sig',
  } as JWK,
}));

export async function testHost<TConfig>(
  method: AuthMethod<TConfig>,
  config: unknown,
  provider: FakeProvider | undefined,
  options: TestHostOptions = {}
): Promise<TestHost<TConfig>> {
  const key = await signerKey;
  const egressCalls: HostEgressCall[] = [];
  const signerCalls: HostSignerCall[] = [];
  const logLines: TestHost<TConfig>['logLines'] = [];
  const signedAssertions: string[] = [];
  const upstreamJwks = { keys: [key.publicJwk] };
  const realmId = options.realmId ?? TEST_REALM_ID;

  const egress: AuthMethodHostEgress = {
    async request(call) {
      egressCalls.push(call);
      if (options.egress !== undefined) return options.egress(call);
      if (provider === undefined) throw new Error('egress refused: no provider');
      return provider.answer(call);
    },
  };
  const signer: AuthMethodHostSigner = {
    async signClientAssertion(caller, request) {
      signerCalls.push({
        operation: 'signClientAssertion',
        caller,
        realmId: request.realmId,
        providerId: request.providerId,
        request: { ...request },
      });
      const clientId = options.signerClientId ?? 'qauth-client';
      const assertion = await new SignJWT({ ...request.claims })
        .setProtectedHeader({
          alg: 'RS256',
          kid: key.publicJwk.kid as string,
          typ: 'client-authentication+jwt',
        })
        .setIssuer(clientId)
        .setSubject(clientId)
        .setAudience(request.audience)
        .sign(key.privateKey);
      signedAssertions.push(assertion);
      return assertion;
    },
    async getUpstreamJwks(caller, jwksRealmId, providerId) {
      signerCalls.push({ operation: 'getUpstreamJwks', caller, realmId: jwksRealmId, providerId });
      return upstreamJwks;
    },
  };
  const record =
    (level: string) =>
    (fields: Record<string, unknown>, message: string): void => {
      logLines.push({ level, message, fields });
    };
  const context = createAuthMethodContext(method, {
    config,
    origin: options.origin ?? TEST_ORIGIN,
    realmName: options.realmName ?? 'acme',
    realmId,
    providerId: method.type,
    signerCaller: 'api',
    egress,
    signer,
    log: {
      debug: record('debug'),
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
    },
  });
  return { context, egressCalls, signerCalls, logLines, signedAssertions, upstreamJwks };
}
