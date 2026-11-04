import {
  createHmac,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  timingSafeEqual,
} from 'node:crypto';

import {
  getSignatureBackend,
  importPublicSigningJwk,
  type JwsAlgorithm,
  MlDsaKey,
  type SignatureAlgorithm,
  verifyHybrid,
  verifyWithHeader,
} from '@qauth-labs/core-crypto';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { compactVerify, decodeJwt, decodeProtectedHeader, importJWK, type JWK } from 'jose';
import { describe, expect, it, type Mock, vi } from 'vitest';

import { KEK_A, KEK_B, localProvider } from '../testing/keks';
import { createMemoryKeyStore, type MemoryKeyStore } from '../testing/memory-key-store';
import { createMemorySignerStore, type MemorySignerStore } from '../testing/memory-signer-store';
import { testCertificateFor } from '../testing/test-certificate';
import { openKeyMaterial, sealKeyMaterial } from './envelope';
import { isKeyCustodyError } from './errors';
import { createInProcessSigner, type InProcessSignerOptions } from './in-process-signer';
import type { KekProvider } from './kek-provider';
import { createKeyFactory, type KeyFactory } from './key-factory';
import {
  type RealmJwks,
  type SignClientAssertionRequest,
  type Signer,
  SIGNER_OPERATIONS,
  type SignerOperation,
  type SignJwsRequest,
  type SignRequestObjectRequest,
  type SignWebhookRequest,
} from './signer';
import {
  DataDecryptionError,
  isSignerError,
  RealmIssuerNotFoundError,
  SignerAccessDeniedError,
  SignerKeyNotFoundError,
  type SignerRefusalReason,
  SignerRequestRefusedError,
  UpstreamClientNotFoundError,
} from './signer-errors';
import {
  OID4VP_RESPONSE_KEY_CONTEXT_PREFIX,
  SIGNER_CALLERS,
  SIGNER_POLICY,
  type SignerCaller,
} from './signer-policy';
import { JWS_TYP_BY_PURPOSE, OID4VP_REQUEST_OBJECT_TYP } from './signer-typ';

const REALM_A = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const REALM_B = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02';
const REALM_WITHOUT_KEYS = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e03';
const REALM_WITHOUT_ISSUER = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e04';
const ISSUER_A = 'https://a.example.test';
const ISSUER_B = 'https://b.example.test';
const NOW = 1_800_000_000_000;
const REFRESH_MS = 60_000;
const ED25519_ONLY: readonly SignatureAlgorithm[] = ['EdDSA'];
const HYBRID: readonly SignatureAlgorithm[] = ['EdDSA', 'ML-DSA-65'];
/** The webhook subscription and the upstream provider that `scoped` setups create keys for. */
const SUBSCRIPTION = 'subscription-1';
const PROVIDER = 'provider-1';

const CLAIMS = Object.freeze({
  sub: 'user-1',
  aud: 'client-1',
  iat: NOW / 1000,
  exp: NOW / 1000 + 300,
});

interface Setup {
  readonly signer: Signer;
  readonly store: MemorySignerStore;
  readonly keys: MemoryKeyStore;
  readonly factory: KeyFactory<unknown>;
  readonly kekProvider: KekProvider;
  readonly unwrap: Mock<KekProvider['unwrap']>;
  readonly enabled: readonly SignatureAlgorithm[];
  /** With `scoped`: each realm's webhook secret, as `createKey` showed it. */
  readonly webhookSecrets: ReadonlyMap<string, string>;
  /** With `scoped`: each realm's verifier certificate chain, naming its OID4VP request key. */
  readonly verifierChains: ReadonlyMap<string, readonly string[]>;
  advance(ms: number): void;
}

/** Each scoped setup's verifier chains, for {@link CALLS}, which gets the signer only. */
const VERIFIER_CHAINS = new WeakMap<Signer, ReadonlyMap<string, readonly string[]>>();

interface SetupOptions {
  /** Hybrid signing for both the factory and the signer. */
  readonly hybrid?: boolean;
  /** Realms whose standard keys are provisioned. Defaults to A and B. */
  readonly realms?: readonly string[];
  /** The KEK provider the signer unwraps with. Defaults to one holding the factory's KEK. */
  readonly signerKek?: KekProvider;
  readonly signer?: Partial<InProcessSignerOptions>;
  /**
   * Also give each realm a webhook secret for {@link SUBSCRIPTION}, an RS256
   * client-assertion key and a configuration for {@link PROVIDER}, and an
   * OID4VP request key with a certificate that names it.
   */
  readonly scoped?: boolean;
}

async function setup(options: SetupOptions = {}): Promise<Setup> {
  const hybrid = options.hybrid === true;
  const enabled = hybrid ? HYBRID : ED25519_ONLY;
  const keys = createMemoryKeyStore();
  const sealing = localProvider({ KEK: KEK_A });
  const factory = createKeyFactory({
    store: keys,
    kekProvider: sealing,
    enabledSignatureAlgorithms: enabled,
    hybridSigning: hybrid,
    now: () => NOW,
  });
  const realms = options.realms ?? [REALM_A, REALM_B];
  const webhookSecrets = new Map<string, string>();
  const verifierChains = new Map<string, readonly string[]>();
  for (const realmId of realms) {
    await factory.provisionRealmKeys(realmId);
    if (options.scoped === true) {
      const [webhook] = await factory.createKey({
        realmId,
        purpose: 'webhook_signing',
        scopeId: SUBSCRIPTION,
      });
      webhookSecrets.set(realmId, webhook.secret as string);
      await factory.createKey({
        realmId,
        purpose: 'upstream_client_assertion',
        scopeId: PROVIDER,
      });
      const [verifier] = await factory.createKey({ realmId, purpose: 'oid4vp_request_signing' });
      verifierChains.set(realmId, [testCertificateFor(publicKeyOf(verifier.publicJwk))]);
    }
  }

  const store = createMemorySignerStore(keys, {
    [REALM_A]: ISSUER_A,
    [REALM_B]: ISSUER_B,
    [REALM_WITHOUT_KEYS]: 'https://empty.example.test',
    [REALM_WITHOUT_ISSUER]: null,
  });
  if (options.scoped === true) {
    for (const realmId of realms) {
      store.upstreamClients.set(`${realmId}/${PROVIDER}`, { clientId: clientIdOf(realmId) });
    }
  }
  // The local provider is frozen, so the unwrap count comes from a delegate.
  const inner = options.signerKek ?? sealing;
  const unwrap = vi.fn(inner.unwrap);
  const kekProvider: KekProvider = { ...inner, unwrap };
  let clock = NOW;
  const signer = createInProcessSigner({
    store,
    kekProvider,
    enabledSignatureAlgorithms: enabled,
    hybridSigning: hybrid,
    refreshIntervalMs: REFRESH_MS,
    now: () => clock,
    ...options.signer,
  });
  VERIFIER_CHAINS.set(signer, verifierChains);
  return {
    signer,
    store,
    keys,
    factory: factory as KeyFactory<unknown>,
    kekProvider,
    unwrap,
    enabled,
    webhookSecrets,
    verifierChains,
    advance: (ms) => {
      clock += ms;
    },
  };
}

function publicKeyOf(jwk: JWK | undefined): KeyObject {
  if (jwk === undefined) throw new Error('no public JWK');
  return createPublicKey({ key: jwk as JsonWebKey, format: 'jwk' });
}

/** A request object for `realmId`, signed under the chain its setup made. */
function requestObject(
  chains: ReadonlyMap<string, readonly string[]> | undefined,
  overrides: Partial<SignRequestObjectRequest> = {}
): SignRequestObjectRequest {
  const realmId = overrides.realmId ?? REALM_A;
  return {
    realmId,
    certificateChain: chains?.get(realmId) ?? [],
    claims: {
      client_id: 'x509_hash:abc',
      response_type: 'vp_token',
      nonce: 'n-1',
      iat: NOW / 1000,
      exp: NOW / 1000 + 300,
    },
    ...overrides,
  };
}

/** The client id each realm is registered under at {@link PROVIDER}. */
function clientIdOf(realmId: string): string {
  return `qauth-${realmId.slice(-2)}`;
}

function accessToken(realmId = REALM_A, overrides: Partial<SignJwsRequest> = {}): SignJwsRequest {
  return { realmId, purpose: 'token_signing', typ: 'at+jwt', claims: CLAIMS, ...overrides };
}

/**
 * An event token the signer accepts for `typ` (#624): it holds each event
 * token to its kind, so access-token claims are refused. A logout token is a
 * `token_signing` type, signed with the ID tokens' key (Back-Channel Logout
 * 1.0 §2.4).
 */
function eventToken(
  realmId = REALM_A,
  typ: 'secevent+jwt' | 'logout+jwt' = 'logout+jwt'
): SignJwsRequest {
  const iat = Math.floor(NOW / 1000);
  const claims =
    typ === 'logout+jwt'
      ? {
          aud: 'rp',
          iat,
          exp: iat + 120,
          jti: 'logout-1',
          events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
          sid: 'session-1',
        }
      : { jti: 'set-1', iat, aud: 'receiver', events: { 'urn:example:event': {} } };
  return {
    realmId,
    purpose: typ === 'logout+jwt' ? 'token_signing' : 'event_signing',
    typ,
    claims,
  };
}

function webhook(overrides: Partial<SignWebhookRequest> = {}): SignWebhookRequest {
  return {
    realmId: REALM_A,
    subscriptionId: SUBSCRIPTION,
    id: 'msg_2KWPBgLlAfxdpx2AI54pPJ85f4W',
    timestamp: NOW / 1000,
    body: '{"type":"user.created","data":{"id":"u-1"}}',
    ...overrides,
  };
}

function assertion(
  overrides: Partial<SignClientAssertionRequest> = {}
): SignClientAssertionRequest {
  return {
    realmId: REALM_A,
    providerId: PROVIDER,
    audience: 'https://idp.example.test',
    claims: { jti: 'assertion-1', iat: NOW / 1000, exp: NOW / 1000 + 60 },
    ...overrides,
  };
}

/**
 * Verify a `webhook-signature` header as a Standard Webhooks receiver does:
 * strip `whsec_`, take the HMAC-SHA256 of `id.timestamp.body`, and accept
 * when any `v1` signature in the header matches, compared in constant time.
 */
function verifiesWebhook(
  header: string,
  secret: string,
  message: { id: string; timestamp: number; body: string | Uint8Array }
): boolean {
  const key = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
  const expected = createHmac('sha256', key)
    .update(`${message.id}.${message.timestamp}.`)
    .update(message.body)
    .digest();
  return header.split(' ').some((signature) => {
    const [version, value] = signature.split(',');
    const actual = Buffer.from(value ?? '', 'base64');
    return (
      version === 'v1' && actual.length === expected.length && timingSafeEqual(actual, expected)
    );
  });
}

/** Store `secret` as a webhook secret, sealed as the factory seals one. */
async function storeWebhookSecret(
  context: Setup,
  realmId: string,
  subscriptionId: string,
  secret: Buffer
): Promise<string> {
  const kid = `vector-${subscriptionId}`;
  const identity = {
    realmId,
    purpose: 'webhook_signing',
    scopeId: subscriptionId,
    kid,
    algorithm: 'HS256',
  };
  const sealed = await sealKeyMaterial(context.kekProvider, secret, identity);
  await context.keys.create(
    {
      key: {
        ...identity,
        status: 'active',
        pairId: null,
        ...sealed,
        publishAt: null,
        activateAt: NOW,
        createdAt: NOW,
      },
    },
    { id: 0 }
  );
  return kid;
}

/** Verify `token` with the key its `kid` names in `jwks`, as a relying party would. */
async function verifyWithJwks(token: string, jwks: RealmJwks, issuer: string) {
  const { kid, alg } = decodeProtectedHeader(token);
  const jwk = jwks.keys.find((key) => key.kid === kid);
  if (jwk === undefined) throw new Error(`no published key for kid ${String(kid)}`);
  const key = await importPublicSigningJwk(jwk, alg as JwsAlgorithm);
  return verifyWithHeader(token, key, {
    algorithms: [alg as JwsAlgorithm],
    issuer,
    currentDate: new Date(NOW),
  });
}

function activeKid(keys: MemoryKeyStore, realmId: string, purpose: string, algorithm = 'EdDSA') {
  const row = keys.rows.find(
    ({ key }) =>
      key.realmId === realmId &&
      key.purpose === purpose &&
      key.algorithm === algorithm &&
      key.status === 'active'
  );
  if (row === undefined) throw new Error(`no ${purpose} ${algorithm} key`);
  return row.key.kid;
}

async function refusal(promise: Promise<unknown>): Promise<SignerRefusalReason> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught
  );
  expect(error).toBeInstanceOf(SignerRequestRefusedError);
  return (error as SignerRequestRefusedError).reason;
}

describe('createInProcessSigner', () => {
  it('refuses hybrid signing when SIGNING_ALGORITHM_MODE does not enable ML-DSA-65', () => {
    const store = createMemorySignerStore(createMemoryKeyStore());
    expect(() =>
      createInProcessSigner({
        store,
        kekProvider: localProvider({ KEK: KEK_A }),
        enabledSignatureAlgorithms: ED25519_ONLY,
        hybridSigning: true,
      })
    ).toThrow(InvalidConfigurationError);
  });

  it.each([
    { keyCacheSize: 0 },
    { keyCacheSize: 1.5 },
    { refreshIntervalMs: -1 },
    { refreshIntervalMs: Number.NaN },
  ])('refuses the cache option %o', (option) => {
    const store = createMemorySignerStore(createMemoryKeyStore());
    expect(() =>
      createInProcessSigner({
        store,
        kekProvider: localProvider({ KEK: KEK_A }),
        enabledSignatureAlgorithms: ED25519_ONLY,
        hybridSigning: false,
        ...option,
      })
    ).toThrow(InvalidConfigurationError);
  });
});

describe('signJws', () => {
  it('signs a token that verifies against the key published for its kid', async () => {
    const { signer, keys } = await setup();

    const token = await signer.signJws('local', accessToken());
    const jwks = await signer.getJwks('local', REALM_A);
    const { claims, protectedHeader } = await verifyWithJwks(token, jwks, ISSUER_A);

    expect(protectedHeader).toEqual({
      alg: 'EdDSA',
      kid: activeKid(keys, REALM_A, 'token_signing'),
      typ: 'at+jwt',
    });
    expect(claims).toEqual({ iss: ISSUER_A, ...CLAIMS });
  });

  it('verifies against the verification keys of its purpose too', async () => {
    const { signer } = await setup();

    const token = await signer.signJws('local', accessToken());
    const verificationKeys = await signer.getVerificationKeys('local', REALM_A, 'token_signing');

    await expect(
      verifyWithJwks(token, { keys: verificationKeys.map((key) => key.publicJwk) }, ISSUER_A)
    ).resolves.toBeDefined();
  });

  it('takes iss from the realm row and kid from its active key', async () => {
    const { signer, keys } = await setup();

    const token = await signer.signJws('local', accessToken(REALM_B));
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));

    expect(payload.iss).toBe(ISSUER_B);
    expect(decodeProtectedHeader(token).kid).toBe(activeKid(keys, REALM_B, 'token_signing'));
  });

  // What the delivery role's handle asks for every SET (#540): the claims the
  // SSF route built, which carry no iss, signed with event_signing.
  it('RFC 8417 §2.2 — adds the realm issuer as iss to a SET the delivery role signs, and keeps its claims', async () => {
    const { signer, keys } = await setup();
    const set = {
      jti: '0192a000-0000-7000-8000-0000000000ee',
      iat: 1_800_000_000,
      aud: 'receiver',
      sub_id: { format: 'iss_sub', iss: ISSUER_A, sub: 'user-1' },
      events: {
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked': {
          event_timestamp: 1_800_000_000,
        },
      },
    };

    const token = await signer.signJws('delivery', {
      realmId: REALM_A,
      purpose: 'event_signing',
      typ: 'secevent+jwt',
      claims: set,
    });
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));

    expect(payload).toEqual({ iss: ISSUER_A, ...set });
    expect(decodeProtectedHeader(token)).toEqual({
      alg: 'EdDSA',
      kid: activeKid(keys, REALM_A, 'event_signing'),
      typ: 'secevent+jwt',
    });
  });

  describe('logout tokens and the event token kinds (OpenID Connect Back-Channel Logout 1.0, #624)', () => {
    const NOW_SECONDS = Math.floor(NOW / 1000);
    const logoutToken = {
      aud: 'rp',
      iat: NOW_SECONDS,
      exp: NOW_SECONDS + 120,
      jti: '0192a000-0000-7000-8000-0000000000dd',
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
      sub: 'user-1',
      sid: 'session-1',
    };
    // A logout token is signed with the ID tokens' key (§2.4), a SET with the
    // event key.
    const sign = (signer: Signer, claims: Record<string, unknown>, typ = 'logout+jwt') =>
      signer.signJws('delivery', {
        realmId: REALM_A,
        purpose: typ === 'logout+jwt' ? 'token_signing' : 'event_signing',
        typ,
        claims,
      } as SignJwsRequest);

    it('signs a logout token for the delivery role with the key the realm JWKS publishes for its ID tokens, the realm issuer as iss, typed logout+jwt (§2.4, §2.6)', async () => {
      const { signer, keys } = await setup();

      const token = await sign(signer, logoutToken);

      // The realm signs its ID tokens with its Ed25519 token key: it holds no
      // RS256 one. Signed with an asymmetric key, never alg none (§2.6), and
      // typed (§2.4).
      const kid = activeKid(keys, REALM_A, 'token_signing');
      expect(decodeProtectedHeader(token)).toEqual({ alg: 'EdDSA', kid, typ: 'logout+jwt' });
      const idToken = await signer.signJws(
        'local',
        accessToken(REALM_A, { typ: 'JWT', algorithm: 'EdDSA' })
      );
      expect(decodeProtectedHeader(idToken).kid).toBe(kid);
      // iss is the realm's issuer, which the delivery role cannot set (§2.4).
      expect(decodeJwt(token)).toEqual({ iss: ISSUER_A, ...logoutToken });
      const jwks = await signer.getJwks('local', REALM_A);
      const jwk = jwks.keys.find((key) => key.kid === kid);
      if (jwk === undefined) throw new Error('the realm JWKS lacks the ID token key');
      const verified = await compactVerify(token, await importJWK(jwk as JWK, 'EdDSA'));
      expect(verified.protectedHeader.typ).toBe('logout+jwt');
    });

    it("signs a logout token with the key and algorithm of the realm's ID tokens, RS256 once the realm holds an RS256 token key (§2.4)", async () => {
      const { signer, factory, keys, advance } = await setup();
      await factory.createKey({ realmId: REALM_A, purpose: 'token_signing', algorithm: 'RS256' });
      advance(REFRESH_MS);

      const token = await sign(signer, logoutToken);

      const kid = activeKid(keys, REALM_A, 'token_signing', 'RS256');
      expect(decodeProtectedHeader(token)).toEqual({ alg: 'RS256', kid, typ: 'logout+jwt' });
      // A caller that names the algorithm names the ID tokens' one.
      const named = (algorithm: string) =>
        signer.signJws('delivery', {
          realmId: REALM_A,
          purpose: 'token_signing',
          typ: 'logout+jwt',
          algorithm,
          claims: logoutToken,
        } as SignJwsRequest);
      expect(await refusal(named('EdDSA'))).toBe('ALGORITHM_NOT_ALLOWED');
      await expect(named('RS256')).resolves.toEqual(expect.any(String));
    });

    it('lets the delivery role sign SETs and logout tokens, and no other token of either key', async () => {
      const { signer, keys } = await setup();

      const set = await signer.signJws('delivery', eventToken(REALM_A, 'secevent+jwt'));
      expect(decodeProtectedHeader(set).kid).toBe(activeKid(keys, REALM_A, 'event_signing'));
      for (const typ of ['at+jwt', 'JWT', 'oauth-id-jag+jwt'] as const) {
        await expect(
          signer.signJws('delivery', accessToken(REALM_A, { typ }))
        ).rejects.toMatchObject({ code: 'SIGNER_ACCESS_DENIED', caller: 'delivery' });
      }
      await expect(signer.signJws('api', eventToken(REALM_A, 'logout+jwt'))).rejects.toMatchObject({
        code: 'SIGNER_ACCESS_DENIED',
        caller: 'api',
      });
    });

    it('signs no logout token as a hybrid carrier', async () => {
      const { signer } = await setup({ hybrid: true });

      expect(
        await refusal(
          signer.signHybrid('local', {
            realmId: REALM_A,
            typ: 'logout+jwt',
            claims: eventToken(REALM_A, 'logout+jwt').claims,
          })
        )
      ).toBe('TYP_NOT_ALLOWED');
    });

    it.each([
      ['an access token grant', { ...logoutToken, scope: 'admin' }],
      ['a client_id', { ...logoutToken, client_id: 'rp' }],
      ['a nonce', { ...logoutToken, nonce: 'n' }],
      ['no events', { ...logoutToken, events: undefined }],
      ['another event', { ...logoutToken, events: { 'urn:other': {} } }],
      ['a second event', { ...logoutToken, events: { ...logoutToken.events, 'urn:other': {} } }],
      ['no sub and no sid', { ...logoutToken, sub: undefined, sid: undefined }],
      ['an aud list', { ...logoutToken, aud: ['rp', 'api'] }],
      ['a lifetime over two minutes', { ...logoutToken, exp: NOW_SECONDS + 121 }],
      ['an exp before its iat', { ...logoutToken, exp: NOW_SECONDS - 1 }],
      [
        'an iat far from the signer clock',
        { ...logoutToken, iat: NOW_SECONDS - 3600, exp: NOW_SECONDS - 3500 },
      ],
    ])('refuses a logout token with %s', async (_label, claims) => {
      const { signer } = await setup();
      await expect(sign(signer, JSON.parse(JSON.stringify(claims)))).rejects.toMatchObject({
        reason: 'INVALID_CLAIMS',
      });
    });

    it.each([
      ['a sub', { sub: 'user-1' }],
      ['an exp', { exp: NOW_SECONDS + 60 }],
      ['a scope', { scope: 'admin' }],
    ])(
      'refuses a Security Event Token with %s, which an access token would carry',
      async (_label, extra) => {
        const { signer } = await setup();
        const set = {
          jti: 'j',
          iat: NOW_SECONDS,
          aud: 'receiver',
          events: { 'urn:e': {} },
          ...extra,
        };
        await expect(sign(signer, set, 'secevent+jwt')).rejects.toMatchObject({
          reason: 'INVALID_CLAIMS',
        });
      }
    );
  });

  it('accepts the realm id in any case', async () => {
    const { signer } = await setup();

    await expect(signer.signJws('local', accessToken(REALM_A.toUpperCase()))).resolves.toEqual(
      expect.any(String)
    );
  });

  describe('refuses a caller-supplied iss or kid', () => {
    it('refuses iss among the claims', async () => {
      const { signer } = await setup();
      const claims = { ...CLAIMS, iss: 'https://evil.example.test' };

      expect(await refusal(signer.signJws('local', accessToken(REALM_A, { claims })))).toBe(
        'RESERVED_CLAIM'
      );
    });

    it('refuses an iss that a toJSON method would add at signing time', async () => {
      const { signer } = await setup();
      const claims = { toJSON: () => ({ ...CLAIMS, iss: 'https://evil.example.test' }) };

      expect(await refusal(signer.signJws('local', accessToken(REALM_A, { claims })))).toBe(
        'RESERVED_CLAIM'
      );
    });

    it.each(['kid', 'iss', 'alg', 'header', 'issuer'])(
      'refuses a %s field on the request',
      async (field) => {
        const { signer } = await setup();
        const request = { ...accessToken(), [field]: 'chosen-by-caller' } as SignJwsRequest;

        expect(await refusal(signer.signJws('local', request))).toBe('UNEXPECTED_FIELD');
      }
    );
  });

  describe('binds each purpose to its typ values', () => {
    it.each([
      ['token_signing', 'at+jwt'],
      ['token_signing', 'JWT'],
      ['token_signing', 'logout+jwt'],
      ['event_signing', 'secevent+jwt'],
    ] as const)('%s signs %s', async (purpose, typ) => {
      const { signer } = await setup();

      const request =
        typ === 'logout+jwt' || typ === 'secevent+jwt'
          ? eventToken(REALM_A, typ)
          : accessToken(REALM_A, { purpose, typ });
      const token = await signer.signJws('local', request);

      expect(decodeProtectedHeader(token).typ).toBe(typ);
    });

    it.each([
      ['event_signing', 'logout+jwt'],
      ['token_signing', 'secevent+jwt'],
      ['event_signing', 'at+jwt'],
      ['event_signing', 'JWT'],
      ['token_signing', 'AT+JWT'],
      ['token_signing', 'jwt'],
      ['token_signing', ''],
    ] as const)('%s refuses %s', async (purpose, typ) => {
      const { signer, unwrap } = await setup();

      expect(await refusal(signer.signJws('local', accessToken(REALM_A, { purpose, typ })))).toBe(
        'TYP_NOT_ALLOWED'
      );
      expect(unwrap).not.toHaveBeenCalled();
    });

    it.each(['cookie_hmac', 'data_at_rest', 'federation_entity', 'oid4vp_request_signing', 'nope'])(
      'does not sign with %s',
      async (purpose) => {
        const { signer } = await setup();
        const request = accessToken(REALM_A, { purpose } as unknown as Partial<SignJwsRequest>);

        expect(await refusal(signer.signJws('local', request))).toBe('PURPOSE_NOT_ALLOWED');
      }
    );
  });

  it('signs with the RS256 key when asked for RS256', async () => {
    const { signer, factory } = await setup();
    const [rsa] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'token_signing',
      algorithm: 'RS256',
    });

    const token = await signer.signJws(
      'local',
      accessToken(REALM_A, { typ: 'JWT', algorithm: 'RS256' })
    );

    expect(decodeProtectedHeader(token)).toMatchObject({ alg: 'RS256', kid: rsa.kid });
    await expect(
      verifyWithJwks(token, await signer.getJwks('local', REALM_A), ISSUER_A)
    ).resolves.toBeDefined();
  });

  it.each([
    ['token_signing', 'ML-DSA-65'],
    ['token_signing', 'ES256'],
    ['event_signing', 'ES256'],
    ['token_signing', 'HS256'],
  ] as const)('refuses %s with %s', async (purpose, algorithm) => {
    const { signer } = await setup();
    const request = accessToken(REALM_A, {
      purpose,
      typ: JWS_TYP_BY_PURPOSE[purpose][0],
      algorithm,
    } as unknown as Partial<SignJwsRequest>);

    expect(await refusal(signer.signJws('local', request))).toBe('ALGORITHM_NOT_ALLOWED');
  });

  it('refuses a scope id for an unscoped purpose', async () => {
    const { signer } = await setup();

    expect(await refusal(signer.signJws('local', accessToken(REALM_A, { scopeId: 's' })))).toBe(
      'SCOPE_NOT_ALLOWED'
    );
  });

  it.each([
    ['an array', []],
    ['a string', 'claims'],
    ['null', null],
    ['a BigInt claim', { exp: BigInt(1) }],
  ])('refuses claims that are %s', async (_, claims) => {
    const { signer } = await setup();
    const request = accessToken(REALM_A, { claims } as unknown as Partial<SignJwsRequest>);

    expect(await refusal(signer.signJws('local', request))).toBe('INVALID_CLAIMS');
  });

  it('refuses a realm id that is not a UUID', async () => {
    const { signer } = await setup();

    expect(await refusal(signer.signJws('local', accessToken('realm-a')))).toBe('INVALID_REALM_ID');
  });

  it.each([REALM_WITHOUT_ISSUER, '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6eff'])(
    'refuses a realm without an issuer (%s)',
    async (realmId) => {
      const { signer } = await setup();

      await expect(signer.signJws('local', accessToken(realmId))).rejects.toBeInstanceOf(
        RealmIssuerNotFoundError
      );
    }
  );

  it('gives a typed error for a realm with no key and creates none', async () => {
    const { signer, keys, store } = await setup();
    const rowsBefore = keys.rows.length;
    const createsBefore = keys.calls.filter((call) => call.method === 'create').length;

    const error = await signer.signJws('local', accessToken(REALM_WITHOUT_KEYS)).catch((e) => e);

    expect(error).toBeInstanceOf(SignerKeyNotFoundError);
    expect(error).toMatchObject({
      code: 'SIGNER_KEY_NOT_FOUND',
      realmId: REALM_WITHOUT_KEYS,
      purpose: 'token_signing',
      algorithm: 'EdDSA',
    });
    expect(keys.rows).toHaveLength(rowsBefore);
    expect(keys.calls.filter((call) => call.method === 'create')).toHaveLength(createsBefore);
    expect(store.calls).not.toContain('getWrappedKey');
  });

  it('signs for two realms with their own keys', async () => {
    const { signer, keys } = await setup();

    const tokenA = await signer.signJws('local', accessToken(REALM_A));
    const tokenB = await signer.signJws('local', accessToken(REALM_B));
    const jwksA = await signer.getJwks('local', REALM_A);
    const jwksB = await signer.getJwks('local', REALM_B);

    expect(decodeProtectedHeader(tokenA).kid).toBe(activeKid(keys, REALM_A, 'token_signing'));
    expect(decodeProtectedHeader(tokenB).kid).toBe(activeKid(keys, REALM_B, 'token_signing'));
    expect(decodeProtectedHeader(tokenA).kid).not.toBe(decodeProtectedHeader(tokenB).kid);
    await expect(verifyWithJwks(tokenA, jwksA, ISSUER_A)).resolves.toBeDefined();
    await expect(verifyWithJwks(tokenB, jwksB, ISSUER_B)).resolves.toBeDefined();
    await expect(verifyWithJwks(tokenA, jwksB, ISSUER_A)).rejects.toThrow(/no published key/);
  });
});

describe('a key that does not unwrap', () => {
  it('gives the KEK provider typed error, and never signs with another key', async () => {
    const { signer, unwrap, store } = await setup({
      signerKek: localProvider({ KEK: KEK_B }),
    });

    const error = await signer.signJws('local', accessToken()).catch((e) => e);

    expect(isKeyCustodyError(error, 'KEK_UNKNOWN_REF')).toBe(true);
    expect(unwrap).toHaveBeenCalledTimes(1);
    expect(store.calls.filter((call) => call === 'getWrappedKey')).toHaveLength(1);
  });

  it('refuses a key whose sealed bytes were changed, with no fallback to another algorithm', async () => {
    const { signer, keys, store, factory, unwrap } = await setup();
    await factory.createKey({ realmId: REALM_A, purpose: 'token_signing', algorithm: 'RS256' });
    const kid = activeKid(keys, REALM_A, 'token_signing');
    const row = keys.rows.find(({ key }) => key.kid === kid);
    const ciphertext = Buffer.from(row?.key.ciphertext ?? []);
    ciphertext[0] ^= 0xff;
    store.replaceSealed(REALM_A, kid, { ciphertext });

    const error = await signer.signJws('local', accessToken()).catch((e) => e);

    expect(isKeyCustodyError(error, 'KEY_DECRYPTION_FAILED')).toBe(true);
    expect(unwrap).toHaveBeenCalledTimes(1);
    // The next call tries the same key again: a failure is not cached, and
    // nothing switches to the RS256 key.
    await expect(signer.signJws('local', accessToken())).rejects.toSatisfy((e: unknown) =>
      isKeyCustodyError(e, 'KEY_DECRYPTION_FAILED')
    );
    expect(unwrap).toHaveBeenCalledTimes(2);
  });

  it('refuses a key row moved to another purpose', async () => {
    const { signer, keys, store } = await setup();
    // The event signing key's sealed bytes under the token signing key's kid:
    // the associated data names the other purpose and kid, so it cannot open.
    const event = keys.rows.find(
      ({ key }) => key.realmId === REALM_A && key.purpose === 'event_signing'
    );
    store.replaceSealed(REALM_A, activeKid(keys, REALM_A, 'token_signing'), {
      ciphertext: event?.key.ciphertext,
      iv: event?.key.iv,
      wrappedDek: event?.key.wrappedDek,
    });

    await expect(signer.signJws('local', accessToken())).rejects.toSatisfy((e: unknown) =>
      isKeyCustodyError(e, 'KEY_DECRYPTION_FAILED')
    );
  });
});

describe('the key cache', () => {
  it('signs with a warm cache without reading the store', async () => {
    const { signer, store } = await setup();
    await signer.signJws('local', accessToken());
    store.calls.length = 0;

    await signer.signJws('local', accessToken());
    await signer.signJws('local', accessToken(REALM_A, { typ: 'JWT' }));

    expect(store.calls).toEqual([]);
  });

  it('reads only the key list again after the refresh interval, and keeps the unwrapped key', async () => {
    const { signer, store, unwrap, advance } = await setup();
    await signer.signJws('local', accessToken());
    store.calls.length = 0;

    advance(REFRESH_MS);
    await signer.signJws('local', accessToken());

    expect(store.calls).toEqual(['listKeys']);
    expect(unwrap).toHaveBeenCalledTimes(1);
  });

  it('follows a rotation within one refresh interval', async () => {
    const { signer, store, factory, keys, advance } = await setup();
    const oldKid = activeKid(keys, REALM_A, 'token_signing');
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'token_signing',
      status: 'next',
    });
    await signer.signJws('local', accessToken());

    store.update(REALM_A, oldKid, { status: 'retired', retireAt: NOW });
    store.update(REALM_A, next.kid, { status: 'active' });

    expect(decodeProtectedHeader(await signer.signJws('local', accessToken())).kid).toBe(oldKid);
    advance(REFRESH_MS);
    expect(decodeProtectedHeader(await signer.signJws('local', accessToken())).kid).toBe(next.kid);
  });

  it('reads and unwraps once for concurrent first calls', async () => {
    const { signer, unwrap, store } = await setup();

    await Promise.all([1, 2, 3].map(() => signer.signJws('local', accessToken())));
    await Promise.all([1, 2, 3].map(() => signer.getJwks('local', REALM_A)));

    expect(unwrap).toHaveBeenCalledTimes(1);
    expect(store.calls.filter((call) => call === 'listKeys')).toHaveLength(1);
    expect(store.calls.filter((call) => call === 'listPublicKeys')).toHaveLength(1);
  });

  it('never signs with a key its own verification keys leave out', async () => {
    const { signer, store, factory, keys, advance } = await setup();
    const oldKid = activeKid(keys, REALM_A, 'token_signing');
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'token_signing',
      status: 'next',
    });
    await signer.signJws('local', accessToken());
    // The published keys are read later than the key list, while the new key is still `next`.
    advance(REFRESH_MS / 3);
    const before = await signer.getVerificationKeys('local', REALM_A, 'token_signing');
    expect(before.map((key) => key.kid)).toEqual([oldKid]);

    store.update(REALM_A, oldKid, { status: 'retired', retireAt: NOW });
    store.update(REALM_A, next.kid, { status: 'active' });
    advance((REFRESH_MS * 2) / 3);
    const token = await signer.signJws('local', accessToken());
    const after = await signer.getVerificationKeys('local', REALM_A, 'token_signing');

    expect(decodeProtectedHeader(token).kid).toBe(next.kid);
    expect(after.map((key) => key.kid)).toContain(next.kid);
  });

  it('reads the published keys again after its first read of the key list', async () => {
    const { signer, store, factory, keys } = await setup();
    const oldKid = activeKid(keys, REALM_A, 'token_signing');
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'token_signing',
      status: 'next',
    });
    // The published keys are read before this node has read any key list.
    const before = await signer.getVerificationKeys('local', REALM_A, 'token_signing');
    expect(before.map((key) => key.kid)).toEqual([oldKid]);

    store.update(REALM_A, oldKid, { status: 'retired', retireAt: NOW });
    store.update(REALM_A, next.kid, { status: 'active' });
    const token = await signer.signJws('local', accessToken());
    const after = await signer.getVerificationKeys('local', REALM_A, 'token_signing');

    expect(decodeProtectedHeader(token).kid).toBe(next.kid);
    expect(after.map((key) => key.kid)).toContain(next.kid);
  });

  it('does not keep published keys whose read started before the key list changed', async () => {
    const { signer, store, factory, keys, advance } = await setup();
    const oldKid = activeKid(keys, REALM_A, 'token_signing');
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'token_signing',
      status: 'next',
    });
    await signer.signJws('local', accessToken());
    advance(REFRESH_MS);
    // A published-key read answers with the keys from before the rotation, but
    // only once the key-list read that sees the rotation has finished.
    const stale = await store.listPublicKeys(REALM_A);
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.spyOn(store, 'listPublicKeys').mockImplementationOnce(async () => {
      await held;
      return stale;
    });
    const slow = signer.getVerificationKeys('local', REALM_A, 'token_signing');

    store.update(REALM_A, oldKid, { status: 'retired', retireAt: NOW });
    store.update(REALM_A, next.kid, { status: 'active' });
    const token = await signer.signJws('local', accessToken());
    release();
    await slow;
    const after = await signer.getVerificationKeys('local', REALM_A, 'token_signing');

    expect(decodeProtectedHeader(token).kid).toBe(next.kid);
    expect(after.map((key) => key.kid)).toContain(next.kid);
  });

  it('holds no more keys than its size limit', async () => {
    const { signer, unwrap } = await setup({ signer: { keyCacheSize: 1 } });

    await signer.signJws('local', accessToken());
    await signer.signJws('local', eventToken(REALM_A, 'secevent+jwt'));
    await signer.signJws('local', accessToken());

    expect(unwrap).toHaveBeenCalledTimes(3);
  });
});

describe('signHybrid', () => {
  it('returns the detached-parallel carrier, which verifyHybrid accepts', async () => {
    const { signer, keys, enabled } = await setup({ hybrid: true });

    const hybrid = await signer.signHybrid('local', {
      realmId: REALM_A,
      typ: 'at+jwt',
      claims: CLAIMS,
    });
    const verification = await signer.getVerificationKeys('local', REALM_A, 'token_signing');
    const edJwk = verification.find((key) => key.algorithm === 'EdDSA')?.publicJwk as JWK;
    const mlDsaJwk = verification.find((key) => key.algorithm === 'ML-DSA-65')?.publicJwk as JWK;
    const backend = getSignatureBackend('ML-DSA-65', enabled);

    const claims = await verifyHybrid(
      hybrid,
      {
        ed: await importPublicSigningJwk(edJwk, 'EdDSA'),
        mlDsa: (pqcKid) =>
          pqcKid === mlDsaJwk.kid
            ? backend.importKey((mlDsaJwk as Record<string, unknown>)['pub'] as string, 'public')
            : undefined,
      },
      {
        algorithms: ['EdDSA'],
        issuer: ISSUER_A,
        currentDate: new Date(NOW),
        enabledSignatureAlgorithms: enabled,
        requirePqc: true,
      }
    );

    expect(claims).toEqual({ iss: ISSUER_A, ...CLAIMS });
    expect(hybrid.pqcAlg).toBe('ML-DSA-65');
    expect(decodeProtectedHeader(hybrid.token)).toEqual({
      alg: 'EdDSA',
      kid: activeKid(keys, REALM_A, 'token_signing'),
      typ: 'at+jwt',
      pqc_alg: 'ML-DSA-65',
      pqc_kid: activeKid(keys, REALM_A, 'token_signing', 'ML-DSA-65'),
    });
  });

  it('is refused while hybrid signing is off, and unwraps nothing', async () => {
    const { signer, unwrap } = await setup();

    expect(
      await refusal(signer.signHybrid('local', { realmId: REALM_A, typ: 'at+jwt', claims: CLAIMS }))
    ).toBe('HYBRID_SIGNING_DISABLED');
    expect(unwrap).not.toHaveBeenCalled();
  });

  it('gives a typed error for a realm without a complete pair', async () => {
    const { signer, keys, store } = await setup({ hybrid: true });
    store.update(REALM_A, activeKid(keys, REALM_A, 'token_signing', 'ML-DSA-65'), {
      status: 'retired',
    });

    await expect(
      signer.signHybrid('local', { realmId: REALM_A, typ: 'at+jwt', claims: CLAIMS })
    ).rejects.toBeInstanceOf(SignerKeyNotFoundError);
  });

  it('binds typ and refuses iss as signJws does', async () => {
    const { signer } = await setup({ hybrid: true });

    expect(
      await refusal(
        signer.signHybrid('local', { realmId: REALM_A, typ: 'logout+jwt', claims: CLAIMS })
      )
    ).toBe('TYP_NOT_ALLOWED');
    expect(
      await refusal(
        signer.signHybrid('local', {
          realmId: REALM_A,
          typ: 'at+jwt',
          claims: { ...CLAIMS, iss: ISSUER_B },
        })
      )
    ).toBe('RESERVED_CLAIM');
  });
});

describe('getCookieSecrets', () => {
  it('returns the active secret and no previous one before a rotation', async () => {
    const { signer, keys } = await setup();

    const secrets = await signer.getCookieSecrets('local', REALM_A);

    expect(secrets.current.kid).toBe(activeKid(keys, REALM_A, 'cookie_hmac', 'HS256'));
    expect(secrets.current.secret).toHaveLength(32);
    expect(secrets.previous).toBeNull();
  });

  it('returns the most recently retired secret as the previous one', async () => {
    const { signer, keys, factory, store, advance } = await setup();
    const first = activeKid(keys, REALM_A, 'cookie_hmac', 'HS256');
    const before = await signer.getCookieSecrets('local', REALM_A);
    const [second] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'cookie_hmac',
      status: 'next',
    });
    store.update(REALM_A, first, { status: 'retired', retireAt: NOW + 1 });
    store.update(REALM_A, second.kid, { status: 'active' });
    advance(REFRESH_MS);

    const after = await signer.getCookieSecrets('local', REALM_A);

    expect(after.current.kid).toBe(second.kid);
    expect(after.previous?.kid).toBe(first);
    expect(after.previous?.secret.equals(before.current.secret)).toBe(true);
    expect(after.current.secret.equals(before.current.secret)).toBe(false);
  });

  it('hands out copies: changing one does not change the next', async () => {
    const { signer } = await setup();
    const first = await signer.getCookieSecrets('local', REALM_A);
    const original = Buffer.from(first.current.secret);

    first.current.secret.fill(0);

    expect((await signer.getCookieSecrets('local', REALM_A)).current.secret.equals(original)).toBe(
      true
    );
  });

  it('hands out buffers that reach no other memory', async () => {
    const { signer } = await setup();

    const { current } = await signer.getCookieSecrets('local', REALM_A);

    expect(current.secret.byteOffset).toBe(0);
    expect(current.secret.buffer.byteLength).toBe(current.secret.length);
  });

  it('reads the store again for a kid its list lacks, as a cookie of another node names (#493)', async () => {
    const { signer, keys, factory, store, advance } = await setup();
    const first = activeKid(keys, REALM_A, 'cookie_hmac', 'HS256');
    await signer.getCookieSecrets('local', REALM_A);
    // Another node rotates; this one's list is a second old, well inside its interval.
    const [second] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'cookie_hmac',
      status: 'next',
    });
    store.update(REALM_A, first, { status: 'retired', retireAt: NOW + 1 });
    store.update(REALM_A, second.kid, { status: 'active' });
    advance(1_000);

    const cached = await signer.getCookieSecrets('local', REALM_A);
    const known = await signer.getCookieSecrets('local', REALM_A, { kid: first });
    const asked = await signer.getCookieSecrets('local', REALM_A, { kid: second.kid });

    expect(cached.current.kid).toBe(first);
    expect(known.current.kid).toBe(first);
    expect(asked.current.kid).toBe(second.kid);
    expect(asked.previous?.kid).toBe(first);
  });

  it('reads the store again for a kid its list lacks even when the list was read a moment ago (#493)', async () => {
    const { signer, keys, factory, store } = await setup();
    const first = activeKid(keys, REALM_A, 'cookie_hmac', 'HS256');
    await signer.getCookieSecrets('local', REALM_A);
    // Another node rotates and signs a cookie before this one's clock moves.
    const [second] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'cookie_hmac',
      status: 'next',
    });
    store.update(REALM_A, first, { status: 'retired', retireAt: NOW + 1 });
    store.update(REALM_A, second.kid, { status: 'active' });

    const asked = await signer.getCookieSecrets('local', REALM_A, { kid: second.kid });

    expect(asked.current.kid).toBe(second.kid);
    expect(asked.previous?.kid).toBe(first);
  });

  it('reads the store again for a kid its list holds only as the next key (#493)', async () => {
    const { signer, keys, factory, store, advance } = await setup();
    const first = activeKid(keys, REALM_A, 'cookie_hmac', 'HS256');
    // This node reads the list between the two steps of another node's rotation.
    const [second] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'cookie_hmac',
      status: 'next',
    });
    await signer.getCookieSecrets('local', REALM_A);
    store.update(REALM_A, first, { status: 'retired', retireAt: NOW + 1 });
    store.update(REALM_A, second.kid, { status: 'active' });
    advance(1);

    const asked = await signer.getCookieSecrets('local', REALM_A, { kid: second.kid });

    expect(asked.current.kid).toBe(second.kid);
    expect(asked.previous?.kid).toBe(first);
  });

  it('reads the store at most once a second for cookie kids no key has', async () => {
    const { signer, store, advance } = await setup();
    await signer.getCookieSecrets('local', REALM_A);
    store.calls.length = 0;

    for (let attempt = 0; attempt < 5; attempt++) {
      await signer.getCookieSecrets('local', REALM_A, { kid: `made-up-${attempt}` });
    }
    const listReads = () => store.calls.filter((call) => call === 'listKeys');
    expect(listReads()).toHaveLength(1);

    advance(1_000);
    await signer.getCookieSecrets('local', REALM_A, { kid: 'made-up-again' });
    expect(listReads()).toHaveLength(2);
  });

  it('refuses options that are not an object with a string kid', async () => {
    const { signer } = await setup();

    for (const options of [null, 'kid', { kid: 7 }, { kid: 'k', refresh: true }]) {
      await expect(
        signer.getCookieSecrets('local', REALM_A, options as never),
        JSON.stringify(options)
      ).rejects.toBeInstanceOf(SignerRequestRefusedError);
    }
  });

  it('gives a typed error for a realm with no cookie key', async () => {
    const { signer } = await setup();

    await expect(signer.getCookieSecrets('local', REALM_WITHOUT_KEYS)).rejects.toBeInstanceOf(
      SignerKeyNotFoundError
    );
  });
});

describe('encrypt and decrypt', () => {
  const plaintext = Buffer.from('an upstream refresh token');

  it('round-trips, and the ciphertext names the key kid', async () => {
    const { signer, keys } = await setup();

    const ciphertext = await signer.encrypt('local', {
      realmId: REALM_A,
      plaintext,
      context: 'row-1',
    });

    expect(ciphertext.split('.').slice(0, 2)).toEqual([
      'v1',
      activeKid(keys, REALM_A, 'data_at_rest', 'A256GCM'),
    ]);
    expect(ciphertext).not.toContain(plaintext.toString('base64url'));
    expect(
      await signer.decrypt('local', { realmId: REALM_A, ciphertext, context: 'row-1' })
    ).toEqual(plaintext);
  });

  it('never repeats a ciphertext', async () => {
    const { signer } = await setup();
    const request = { realmId: REALM_A, plaintext };

    expect(await signer.encrypt('local', request)).not.toBe(await signer.encrypt('local', request));
  });

  it('refuses another context', async () => {
    const { signer } = await setup();
    const ciphertext = await signer.encrypt('local', {
      realmId: REALM_A,
      plaintext,
      context: 'row-1',
    });

    await expect(
      signer.decrypt('local', { realmId: REALM_A, ciphertext, context: 'row-2' })
    ).rejects.toBeInstanceOf(DataDecryptionError);
    await expect(signer.decrypt('local', { realmId: REALM_A, ciphertext })).rejects.toBeInstanceOf(
      DataDecryptionError
    );
  });

  it('lets the delivery role decrypt only a delivery destination secret, without echoing the context', async () => {
    const { signer } = await setup();
    const destination = 'delivery:ssf_streams.authorization_header:s1';
    const stored = await signer.encrypt('api', {
      realmId: REALM_A,
      plaintext,
      context: destination,
    });
    expect(
      await signer.decrypt('delivery', {
        realmId: REALM_A,
        ciphertext: stored,
        context: destination,
      })
    ).toEqual(plaintext);

    const other = await signer.encrypt('api', {
      realmId: REALM_A,
      plaintext,
      context: 'secret-row',
    });
    const error = await signer
      .decrypt('delivery', { realmId: REALM_A, ciphertext: other, context: 'secret-row' })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerAccessDeniedError);
    expect((error as Error).message).not.toContain('secret-row');
    await expect(
      signer.decrypt('delivery', { realmId: REALM_A, ciphertext: other })
    ).rejects.toBeInstanceOf(SignerAccessDeniedError);
    await expect(
      signer.encrypt('delivery', { realmId: REALM_A, plaintext, context: destination })
    ).rejects.toBeInstanceOf(SignerAccessDeniedError);
  });

  it('lets web seal an OID4VP response key and api open it, and nothing else (#546)', async () => {
    const { signer } = await setup();
    const context = `${OID4VP_RESPONSE_KEY_CONTEXT_PREFIX}ephemeral-kid-1`;
    const sealed = await signer.encrypt('web', { realmId: REALM_A, plaintext, context });

    expect(await signer.decrypt('api', { realmId: REALM_A, ciphertext: sealed, context })).toEqual(
      plaintext
    );
    // The web role mints the key and never reads it back.
    await expect(
      signer.decrypt('web', { realmId: REALM_A, ciphertext: sealed, context })
    ).rejects.toBeInstanceOf(SignerAccessDeniedError);
    for (const other of [undefined, 'realm_secrets:mail.smtp.password', 'secret-row']) {
      const error = await signer
        .encrypt('web', { realmId: REALM_A, plaintext, context: other })
        .catch((e: unknown) => e);
      expect(error, String(other)).toBeInstanceOf(SignerAccessDeniedError);
      if (other !== undefined) expect((error as Error).message).not.toContain(other);
    }
  });

  it('checks the encrypt context before it reads any key', async () => {
    const { signer, unwrap } = await setup();

    await expect(
      signer.encrypt('web', { realmId: REALM_A, plaintext, context: 'secret-row' })
    ).rejects.toBeInstanceOf(SignerAccessDeniedError);
    expect(
      await refusal(signer.encrypt('web', { realmId: REALM_A, plaintext, context: 1 as never }))
    ).toBe('INVALID_CONTEXT');
    expect(unwrap).not.toHaveBeenCalled();
  });

  it("refuses another realm's ciphertext", async () => {
    const { signer } = await setup();
    const ciphertext = await signer.encrypt('local', { realmId: REALM_A, plaintext });

    await expect(signer.decrypt('local', { realmId: REALM_B, ciphertext })).rejects.toBeInstanceOf(
      SignerKeyNotFoundError
    );
  });

  /** `ciphertext` with one bit of part `index` flipped. */
  function flipBit(ciphertext: string, index: number): string {
    const parts = ciphertext.split('.');
    const bytes = Buffer.from(parts[index], 'base64url');
    bytes[0] ^= 0x01;
    parts[index] = bytes.toString('base64url');
    return parts.join('.');
  }

  it.each([
    ['a changed body', (c: string) => flipBit(c, 3)],
    ['a changed nonce', (c: string) => flipBit(c, 2)],
    ['another version', (c: string) => c.replace(/^v1/, 'v2')],
    ['a missing part', (c: string) => c.split('.').slice(0, 3).join('.')],
    [
      'a short nonce',
      (c: string) =>
        c
          .split('.')
          .map((p, i) => (i === 2 ? 'AAAA' : p))
          .join('.'),
    ],
    ['an empty string', () => ''],
  ])('refuses %s', async (_, change) => {
    const { signer } = await setup();
    const ciphertext = await signer.encrypt('local', { realmId: REALM_A, plaintext });

    const error = await signer
      .decrypt('local', { realmId: REALM_A, ciphertext: change(ciphertext) })
      .catch((e) => e);

    expect(error).toBeInstanceOf(DataDecryptionError);
    expect(isSignerError(error, 'DATA_DECRYPTION_FAILED')).toBe(true);
    expect(error.message).not.toContain(plaintext.toString());
  });

  it('decrypts with a retired key after a rotation, and refuses a compromised one', async () => {
    const { signer, keys, factory, store, advance } = await setup();
    const oldKid = activeKid(keys, REALM_A, 'data_at_rest', 'A256GCM');
    const old = await signer.encrypt('local', { realmId: REALM_A, plaintext });
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'data_at_rest',
      status: 'next',
    });
    store.update(REALM_A, oldKid, { status: 'retired', retireAt: NOW });
    store.update(REALM_A, next.kid, { status: 'active' });
    advance(REFRESH_MS);

    const fresh = await signer.encrypt('local', { realmId: REALM_A, plaintext });

    expect(fresh.split('.')[1]).toBe(next.kid);
    expect(await signer.decrypt('local', { realmId: REALM_A, ciphertext: old })).toEqual(plaintext);

    store.update(REALM_A, oldKid, { status: 'compromised' });
    advance(REFRESH_MS);
    await expect(
      signer.decrypt('local', { realmId: REALM_A, ciphertext: old })
    ).rejects.toBeInstanceOf(SignerKeyNotFoundError);
  });

  it('finds a key created after the key list was read', async () => {
    const { signer, keys, factory, store, advance } = await setup();
    const oldKid = activeKid(keys, REALM_A, 'data_at_rest', 'A256GCM');
    await signer.encrypt('local', { realmId: REALM_A, plaintext });
    // Another node rotated: this signer's list is still fresh and lacks the key.
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'data_at_rest',
      status: 'next',
    });
    store.update(REALM_A, oldKid, { status: 'retired', retireAt: NOW });
    store.update(REALM_A, next.kid, { status: 'active' });
    const other = createInProcessSigner({
      store,
      kekProvider: localProvider({ KEK: KEK_A }),
      enabledSignatureAlgorithms: ED25519_ONLY,
      hybridSigning: false,
      now: () => NOW,
    });
    const ciphertext = await other.encrypt('local', { realmId: REALM_A, plaintext });
    advance(1_000);

    expect(await signer.decrypt('local', { realmId: REALM_A, ciphertext })).toEqual(plaintext);
  });

  it('finds a key created a moment after the key list was read', async () => {
    const { signer, keys, factory, store } = await setup();
    const oldKid = activeKid(keys, REALM_A, 'data_at_rest', 'A256GCM');
    await signer.encrypt('local', { realmId: REALM_A, plaintext });
    // Another node rotates and encrypts before this signer's clock moves.
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'data_at_rest',
      status: 'next',
    });
    store.update(REALM_A, oldKid, { status: 'retired', retireAt: NOW });
    store.update(REALM_A, next.kid, { status: 'active' });
    const other = createInProcessSigner({
      store,
      kekProvider: localProvider({ KEK: KEK_A }),
      enabledSignatureAlgorithms: ED25519_ONLY,
      hybridSigning: false,
      now: () => NOW,
    });
    const ciphertext = await other.encrypt('local', { realmId: REALM_A, plaintext });

    expect(await signer.decrypt('local', { realmId: REALM_A, ciphertext })).toEqual(plaintext);
  });

  it('reads the key list at most once a second for ciphertexts naming unknown keys', async () => {
    const { signer, store, advance } = await setup();
    const ciphertext = await signer.encrypt('local', { realmId: REALM_A, plaintext });
    const unknown = ciphertext.replace(/^v1\.[^.]+\./, 'v1.unknown-kid.');
    advance(1_000);
    store.calls.length = 0;

    for (let attempt = 0; attempt < 5; attempt++) {
      await expect(
        signer.decrypt('local', { realmId: REALM_A, ciphertext: unknown })
      ).rejects.toBeInstanceOf(SignerKeyNotFoundError);
    }

    expect(store.calls).toEqual(['listKeys']);
  });

  it.each([
    ['a string plaintext', { plaintext: 'text' }, 'INVALID_PLAINTEXT'],
    ['a context that is not a string', { plaintext, context: 1 }, 'INVALID_CONTEXT'],
    ['a context that is too long', { plaintext, context: 'x'.repeat(1025) }, 'INVALID_CONTEXT'],
    ['a lone surrogate in the context', { plaintext, context: '\uD800' }, 'INVALID_CONTEXT'],
    ['a kid field', { plaintext, kid: 'k' }, 'UNEXPECTED_FIELD'],
  ])('refuses %s', async (_, fields, reason) => {
    const { signer } = await setup();
    const request = { realmId: REALM_A, ...fields } as unknown as Parameters<Signer['encrypt']>[1];

    expect(await refusal(signer.encrypt('local', request))).toBe(reason);
  });
});

describe('getVerificationKeys and getJwks', () => {
  it('publish the token keys in the JWKS and the event keys apart, never a symmetric key', async () => {
    const { signer, keys } = await setup();

    const jwks = await signer.getJwks('local', REALM_A);
    const events = await signer.getVerificationKeys('local', REALM_A, 'event_signing');

    // The event keys verify SETs at the SSF transmitter's own JWKS (d-1026-09).
    expect(jwks.keys.map((key) => key.kid)).toEqual([activeKid(keys, REALM_A, 'token_signing')]);
    expect(events.map((key) => key.kid)).toEqual([activeKid(keys, REALM_A, 'event_signing')]);
    for (const key of [...jwks.keys, ...events.map((event) => event.publicJwk)]) {
      expect(key).toMatchObject({ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', use: 'sig' });
      expect(key).not.toHaveProperty('d');
    }
  });

  it('list a next key in the JWKS but not among the verification keys', async () => {
    const { signer, factory } = await setup();
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'token_signing',
      status: 'next',
    });

    const jwks = await signer.getJwks('local', REALM_A);
    const verification = await signer.getVerificationKeys('local', REALM_A, 'token_signing');

    expect(jwks.keys.map((key) => key.kid)).toContain(next.kid);
    expect(verification.map((key) => key.kid)).not.toContain(next.kid);
  });

  it('keep a retired key until its window closes, and drop a compromised one at the next read', async () => {
    const { signer, keys, store, advance } = await setup();
    const kid = activeKid(keys, REALM_A, 'token_signing');
    store.update(REALM_A, kid, { status: 'retired', unpublishAt: NOW + 2 * REFRESH_MS });

    expect((await signer.getVerificationKeys('local', REALM_A, 'token_signing'))[0]).toMatchObject({
      kid,
      status: 'retired',
    });

    advance(2 * REFRESH_MS);
    expect(await signer.getVerificationKeys('local', REALM_A, 'token_signing')).toEqual([]);
    expect((await signer.getJwks('local', REALM_A)).keys.map((key) => key.kid)).not.toContain(kid);

    const event = activeKid(keys, REALM_A, 'event_signing');
    store.update(REALM_A, event, { status: 'compromised' });
    advance(REFRESH_MS);
    expect((await signer.getJwks('local', REALM_A)).keys).toEqual([]);
    expect(await signer.getVerificationKeys('local', REALM_A, 'event_signing')).toEqual([]);
  });

  it('return frozen copies', async () => {
    const { signer } = await setup();

    const jwks = await signer.getJwks('local', REALM_A);

    expect(Object.isFrozen(jwks.keys)).toBe(true);
    expect(Object.isFrozen(jwks.keys[0])).toBe(true);
  });

  it('refuse a published key that carries a private member', async () => {
    const { signer, keys } = await setup();
    const row = keys.rows.find(({ publicJwk }) => publicJwk !== undefined);
    if (row?.publicJwk === undefined) throw new Error('no published key');
    (row.publicJwk as Record<string, unknown>)['d'] = 'private';

    await expect(signer.getJwks('local', REALM_A)).rejects.toThrow(/private member/);
  });

  it.each(['cookie_hmac', 'data_at_rest', 'oid4vp_response_encryption'])(
    'have no verification keys for %s',
    async (purpose) => {
      const { signer } = await setup();

      expect(
        await refusal(signer.getVerificationKeys('local', REALM_A, purpose as 'token_signing'))
      ).toBe('PURPOSE_NOT_ALLOWED');
    }
  );
});

describe('signWebhook', () => {
  it('matches the Standard Webhooks test vector', async () => {
    // The sign test of the reference libraries (JavaScript, Python, Go, PHP,
    // C#): https://github.com/standard-webhooks/standard-webhooks, libraries/.
    const context = await setup();
    const secret = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
    await storeWebhookSecret(
      context,
      REALM_A,
      'vector',
      Buffer.from(secret.slice('whsec_'.length), 'base64')
    );

    const header = await context.signer.signWebhook('delivery', {
      realmId: REALM_A,
      subscriptionId: 'vector',
      id: 'msg_p5jXN8AQM9LWM0D4loKWxJek',
      timestamp: 1614265330,
      body: '{"test": 2432232314}',
    });

    expect(header).toBe('v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=');
  });

  it('signs with the secret createKey showed, which a receiver verifies', async () => {
    const { signer, webhookSecrets } = await setup({ scoped: true });
    const message = webhook();

    const header = await signer.signWebhook('delivery', message);

    expect(header).toMatch(/^v1,[A-Za-z0-9+/]{43}=$/);
    expect(verifiesWebhook(header, webhookSecrets.get(REALM_A) as string, message)).toBe(true);
    expect(
      verifiesWebhook(header, webhookSecrets.get(REALM_A) as string, {
        ...message,
        id: 'msg_other',
      })
    ).toBe(false);
  });

  it('signs the same bytes for a text body and its UTF-8 bytes', async () => {
    const { signer } = await setup({ scoped: true });
    const body = '{"name":"Zoë 名前"}';

    expect(await signer.signWebhook('local', webhook({ body: Buffer.from(body, 'utf8') }))).toBe(
      await signer.signWebhook('local', webhook({ body }))
    );
  });

  it("uses only the subscription's own secret, in its own realm", async () => {
    const { signer, factory, webhookSecrets } = await setup({ scoped: true });
    const [other] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'webhook_signing',
      scopeId: 'subscription-2',
    });
    const message = webhook();

    const header = await signer.signWebhook('local', message);

    expect(verifiesWebhook(header, other.secret as string, message)).toBe(false);
    expect(verifiesWebhook(header, webhookSecrets.get(REALM_B) as string, message)).toBe(false);
  });

  it('signs with the active and the next secret during a rotation, and the new one alone after it', async () => {
    const context = await setup({ scoped: true });
    const { signer, factory, keys, advance } = context;
    const oldSecret = context.webhookSecrets.get(REALM_A) as string;
    const scope = { realmId: REALM_A, purpose: 'webhook_signing', scopeId: SUBSCRIPTION } as const;
    const [next] = await factory.createKey({ ...scope, status: 'next' });
    const newSecret = next.secret as string;
    const message = webhook();

    const during = await signer.signWebhook('delivery', message);

    const [first, second, ...rest] = during.split(' ');
    expect(rest).toEqual([]);
    expect(verifiesWebhook(first, oldSecret, message)).toBe(true);
    expect(verifiesWebhook(second, newSecret, message)).toBe(true);

    // The switch, after the overlap window, as the rotation's owner runs it.
    await createKeyFactory({
      store: keys,
      kekProvider: context.kekProvider,
      enabledSignatureAlgorithms: context.enabled,
      hybridSigning: false,
      prepublishMs: 0,
      now: () => NOW,
    }).activateNextKey(scope);
    advance(REFRESH_MS);
    const after = await signer.signWebhook('delivery', message);

    expect(after.split(' ')).toHaveLength(1);
    expect(verifiesWebhook(after, newSecret, message)).toBe(true);
    expect(verifiesWebhook(after, oldSecret, message)).toBe(false);
  });

  it('gives a typed error for a subscription with no active secret, and creates none', async () => {
    const { signer, factory, keys } = await setup({ scoped: true });
    await factory.createKey({
      realmId: REALM_A,
      purpose: 'webhook_signing',
      scopeId: 'pending',
      status: 'next',
    });
    const rows = keys.rows.length;

    for (const subscriptionId of ['unknown', 'pending']) {
      await expect(signer.signWebhook('local', webhook({ subscriptionId }))).rejects.toMatchObject({
        code: 'SIGNER_KEY_NOT_FOUND',
        purpose: 'webhook_signing',
      });
    }
    expect(keys.rows).toHaveLength(rows);
  });

  it('refuses a secret row moved to another subscription', async () => {
    const context = await setup({ scoped: true });
    // Subscription 2's sealed secret under subscription 1: the associated data
    // names the other scope, so it cannot open.
    const [moved] = await context.factory.createKey({
      realmId: REALM_A,
      purpose: 'webhook_signing',
      scopeId: 'subscription-2',
    });
    const rows = context.keys.rows;
    rows.splice(
      rows.findIndex((row) => row.key.realmId === REALM_A && row.key.scopeId === SUBSCRIPTION),
      1
    );
    const index = rows.findIndex((row) => row.key.kid === moved.kid);
    rows[index] = { ...rows[index], key: { ...rows[index].key, scopeId: SUBSCRIPTION } };

    await expect(context.signer.signWebhook('local', webhook())).rejects.toSatisfy((e: unknown) =>
      isKeyCustodyError(e, 'KEY_DECRYPTION_FAILED')
    );
  });

  it.each([
    ['an id with a full stop', { id: 'msg.1' }, 'INVALID_WEBHOOK_ID'],
    ['an id with a space', { id: 'msg 1' }, 'INVALID_WEBHOOK_ID'],
    ['an empty id', { id: '' }, 'INVALID_WEBHOOK_ID'],
    ['an id outside printable ASCII', { id: 'msg_é' }, 'INVALID_WEBHOOK_ID'],
    ['an id too long for a header', { id: 'm'.repeat(256) }, 'INVALID_WEBHOOK_ID'],
    [
      'a timestamp in milliseconds with a fraction',
      { timestamp: 1614265330.5 },
      'INVALID_TIMESTAMP',
    ],
    ['a negative timestamp', { timestamp: -1 }, 'INVALID_TIMESTAMP'],
    ['a timestamp as text', { timestamp: '1614265330' }, 'INVALID_TIMESTAMP'],
    ['a body that is a number', { body: 42 }, 'INVALID_BODY'],
    ['a body with a lone surrogate', { body: 'a\ud800b' }, 'INVALID_BODY'],
    ['an empty subscription id', { subscriptionId: '' }, 'INVALID_SCOPE_ID'],
    ['a realm id that is not a UUID', { realmId: 'realm-a' }, 'INVALID_REALM_ID'],
    ['a caller-supplied key id', { kid: 'k' }, 'UNEXPECTED_FIELD'],
    ['a caller-supplied secret', { secret: 'whsec_x' }, 'UNEXPECTED_FIELD'],
  ] as const)('refuses %s', async (_case, change, reason) => {
    const { signer, unwrap } = await setup({ scoped: true });
    const request = { ...webhook(), ...change } as unknown as SignWebhookRequest;

    expect(await refusal(signer.signWebhook('local', request))).toBe(reason);
    expect(unwrap).not.toHaveBeenCalled();
  });
});

describe('signClientAssertion', () => {
  it('signs an RFC 7523 client assertion that the provider verifies with its JWKS', async () => {
    const { signer, keys } = await setup({ scoped: true });

    const token = await signer.signClientAssertion('api', assertion());

    const header = decodeProtectedHeader(token);
    const kid = keys.rows.find((row) => row.key.realmId === REALM_A && row.key.scopeId === PROVIDER)
      ?.key.kid;
    expect(header).toEqual({ alg: 'RS256', kid, typ: 'client-authentication+jwt' });
    const jwks = await signer.getUpstreamJwks('api', REALM_A, PROVIDER);
    const { claims } = await verifyWithJwks(token, jwks, clientIdOf(REALM_A));
    expect(claims).toEqual({
      iss: clientIdOf(REALM_A),
      sub: clientIdOf(REALM_A),
      aud: 'https://idp.example.test',
      jti: 'assertion-1',
      iat: NOW / 1000,
      exp: NOW / 1000 + 60,
    });
  });

  it('signs with the key of the algorithm asked for', async () => {
    const { signer, factory } = await setup({ scoped: true });
    const [es256] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'upstream_client_assertion',
      scopeId: PROVIDER,
      algorithm: 'ES256',
    });

    const token = await signer.signClientAssertion('local', assertion({ algorithm: 'ES256' }));

    expect(decodeProtectedHeader(token)).toMatchObject({ alg: 'ES256', kid: es256.kid });
    await verifyWithJwks(
      token,
      await signer.getUpstreamJwks('local', REALM_A, PROVIDER),
      clientIdOf(REALM_A)
    );
  });

  describe("cannot use another realm's or another provider's key", () => {
    it('verifies with its own provider JWKS only', async () => {
      const { signer, factory, store } = await setup({ scoped: true });
      await factory.createKey({
        realmId: REALM_A,
        purpose: 'upstream_client_assertion',
        scopeId: 'provider-q',
      });
      store.upstreamClients.set(`${REALM_A}/provider-q`, { clientId: 'qauth-q' });

      const token = await signer.signClientAssertion('local', assertion());

      const own = await signer.getUpstreamJwks('local', REALM_A, PROVIDER);
      await expect(verifyWithJwks(token, own, clientIdOf(REALM_A))).resolves.toBeDefined();
      for (const [realmId, providerId] of [
        [REALM_B, PROVIDER],
        [REALM_A, 'provider-q'],
      ]) {
        const other = await signer.getUpstreamJwks('local', realmId, providerId);
        expect(other.keys).toHaveLength(1);
        await expect(verifyWithJwks(token, other, clientIdOf(REALM_A))).rejects.toThrow(
          'no published key'
        );
      }
    });

    it('finds no key for a provider whose key only another realm holds', async () => {
      const { signer, factory, store, unwrap } = await setup({ scoped: true });
      await factory.createKey({
        realmId: REALM_B,
        purpose: 'upstream_client_assertion',
        scopeId: 'provider-q',
      });
      store.upstreamClients.set(`${REALM_A}/provider-q`, { clientId: 'qauth-q' });

      await expect(
        signer.signClientAssertion('local', assertion({ providerId: 'provider-q' }))
      ).rejects.toBeInstanceOf(SignerKeyNotFoundError);
      expect(unwrap).not.toHaveBeenCalled();
    });

    it.each([
      ['another provider', REALM_A, 'provider-q'],
      ['another realm', REALM_B, PROVIDER],
    ])('refuses a key row moved from %s', async (_case, fromRealm, fromProvider) => {
      const context = await setup({ scoped: true });
      const [foreign] = await context.factory.createKey({
        realmId: fromRealm,
        purpose: 'upstream_client_assertion',
        scopeId: fromProvider,
        status: fromRealm === REALM_A ? 'active' : 'next',
      });
      // The foreign row relabelled as realm A's provider key, in place of the
      // real one: its associated data names where it was sealed, so it cannot open.
      const rows = context.keys.rows;
      rows.splice(
        rows.findIndex((row) => row.key.realmId === REALM_A && row.key.scopeId === PROVIDER),
        1
      );
      const index = rows.findIndex((row) => row.key.kid === foreign.kid);
      rows[index] = {
        ...rows[index],
        key: { ...rows[index].key, realmId: REALM_A, scopeId: PROVIDER, status: 'active' },
      };

      await expect(context.signer.signClientAssertion('local', assertion())).rejects.toSatisfy(
        (e: unknown) => isKeyCustodyError(e, 'KEY_DECRYPTION_FAILED')
      );
    });
  });

  it('takes iss and sub from the provider configuration, and refuses a provider without one', async () => {
    const { signer, store, unwrap } = await setup({ scoped: true });
    store.upstreamClients.delete(`${REALM_A}/${PROVIDER}`);

    const error = await signer.signClientAssertion('local', assertion()).catch((e) => e);

    expect(error).toBeInstanceOf(UpstreamClientNotFoundError);
    expect(error.message).not.toContain(PROVIDER);
    expect(unwrap).not.toHaveBeenCalled();
  });

  it('reads the client id at most once per refresh interval, and a new configuration at once', async () => {
    const { signer, store, advance } = await setup({ scoped: true });
    const reads = () => store.calls.filter((call) => call === 'findUpstreamClient').length;
    store.upstreamClients.delete(`${REALM_A}/${PROVIDER}`);
    await expect(signer.signClientAssertion('local', assertion())).rejects.toBeInstanceOf(
      UpstreamClientNotFoundError
    );

    store.upstreamClients.set(`${REALM_A}/${PROVIDER}`, { clientId: 'first' });
    await signer.signClientAssertion('local', assertion());
    store.upstreamClients.set(`${REALM_A}/${PROVIDER}`, { clientId: 'second' });
    const cached = await signer.signClientAssertion('local', assertion());
    expect(reads()).toBe(2);
    advance(REFRESH_MS);
    const refreshed = await signer.signClientAssertion('local', assertion());

    expect(reads()).toBe(3);
    const subjectOf = (token: string) =>
      JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).sub;
    expect(subjectOf(cached)).toBe('first');
    expect(subjectOf(refreshed)).toBe('second');
  });

  it.each([
    ['iss among the claims', { claims: { iss: 'x', exp: 1, jti: 'j' } }, 'RESERVED_CLAIM'],
    ['sub among the claims', { claims: { sub: 'x', exp: 1, jti: 'j' } }, 'RESERVED_CLAIM'],
    ['aud among the claims', { claims: { aud: 'x', exp: 1, jti: 'j' } }, 'RESERVED_CLAIM'],
    ['claims without exp', { claims: { jti: 'j' } }, 'MISSING_CLAIM'],
    ['claims without jti', { claims: { exp: 1 } }, 'MISSING_CLAIM'],
    ['an exp that is not a number', { claims: { exp: '1', jti: 'j' } }, 'MISSING_CLAIM'],
    ['claims that are not an object', { claims: [] }, 'INVALID_CLAIMS'],
    ['several audiences', { audience: ['https://a.test', 'https://b.test'] }, 'INVALID_AUDIENCE'],
    ['an empty audience', { audience: '' }, 'INVALID_AUDIENCE'],
    ['an HMAC algorithm', { algorithm: 'HS256' }, 'ALGORITHM_NOT_ALLOWED'],
    ['ML-DSA-65', { algorithm: 'ML-DSA-65' }, 'ALGORITHM_NOT_ALLOWED'],
    ['an empty provider id', { providerId: '' }, 'INVALID_SCOPE_ID'],
    ['a realm id that is not a UUID', { realmId: 'realm-a' }, 'INVALID_REALM_ID'],
    ['a caller-supplied key id', { kid: 'k' }, 'UNEXPECTED_FIELD'],
    ['a caller-supplied client id', { clientId: 'evil' }, 'UNEXPECTED_FIELD'],
    ['a caller-supplied typ', { typ: 'JWT' }, 'UNEXPECTED_FIELD'],
  ] as const)('refuses %s', async (_case, change, reason) => {
    const { signer, unwrap } = await setup({ scoped: true });
    const request = { ...assertion(), ...change } as unknown as SignClientAssertionRequest;

    expect(await refusal(signer.signClientAssertion('local', request))).toBe(reason);
    expect(unwrap).not.toHaveBeenCalled();
  });

  it('refuses a sub that a toJSON method would add at signing time', async () => {
    const { signer } = await setup({ scoped: true });
    const claims = { exp: 1, jti: 'j', toJSON: () => ({ exp: 1, jti: 'j', sub: 'evil' }) };

    expect(await refusal(signer.signClientAssertion('local', assertion({ claims })))).toBe(
      'RESERVED_CLAIM'
    );
  });
});

describe('signRequestObject', () => {
  it('signs an ES256 request object with the typ and x5c, iss set to client_id (#546)', async () => {
    const { signer, verifierChains } = await setup({ scoped: true });
    const request = requestObject(verifierChains);

    const token = await signer.signRequestObject('web', request);

    expect(decodeProtectedHeader(token)).toEqual({
      alg: 'ES256',
      typ: OID4VP_REQUEST_OBJECT_TYP,
      x5c: verifierChains.get(REALM_A),
    });
    expect(decodeJwt(token)).toEqual({ iss: 'x509_hash:abc', ...request.claims });
    // It verifies under the certificate's key, which is the published one.
    const [published] = await signer.getVerificationKeys('web', REALM_A, 'oid4vp_request_signing');
    expect(published).toMatchObject({ algorithm: 'ES256', status: 'active' });
    expect(published.publicJwk).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256' });
    expect(published.publicJwk).not.toHaveProperty('d');
    await expect(
      compactVerify(token, await importJWK(published.publicJwk, 'ES256'))
    ).resolves.toBeDefined();
    // The realm JWKS never lists the verifier key.
    expect((await signer.getJwks('web', REALM_A)).keys.map((key) => key.kid)).not.toContain(
      published.kid
    );
  });

  it("refuses a chain whose leaf names another key: another realm's, or a stranger's", async () => {
    const { signer, verifierChains } = await setup({ scoped: true });
    const stranger = testCertificateFor(
      generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey
    );

    for (const certificateChain of [verifierChains.get(REALM_B) ?? [], [stranger]]) {
      expect(
        await refusal(
          signer.signRequestObject('web', requestObject(verifierChains, { certificateChain }))
        )
      ).toBe('CERTIFICATE_KEY_MISMATCH');
    }
    // An intermediate after a matching leaf is the caller's to choose.
    const chain = [...(verifierChains.get(REALM_A) ?? []), stranger];
    await expect(
      signer.signRequestObject('web', requestObject(verifierChains, { certificateChain: chain }))
    ).resolves.toEqual(expect.any(String));
  });

  it('refuses a leaf with a key of another type', async () => {
    const { signer, verifierChains } = await setup({ scoped: true });
    const ed25519 = generateKeyPairSync('ed25519').publicKey;
    // The helper signs with P-256 whatever key it certifies.
    const certificate = testCertificateFor(ed25519);

    expect(
      await refusal(
        signer.signRequestObject(
          'web',
          requestObject(verifierChains, { certificateChain: [certificate] })
        )
      )
    ).toBe('CERTIFICATE_KEY_MISMATCH');
  });

  it.each([
    ['an iss claim', { claims: { client_id: 'c', iss: 'evil' } }, 'RESERVED_CLAIM'],
    ['no client_id', { claims: { nonce: 'n' } }, 'MISSING_CLAIM'],
    ['a client_id that is not a string', { claims: { client_id: 1 } }, 'MISSING_CLAIM'],
    ['an empty client_id', { claims: { client_id: '' } }, 'MISSING_CLAIM'],
    ['claims that are not an object', { claims: [] }, 'INVALID_CLAIMS'],
    ['an empty chain', { certificateChain: [] }, 'INVALID_CERTIFICATE_CHAIN'],
    ['a chain that is not a list', { certificateChain: 'MIIB' }, 'INVALID_CERTIFICATE_CHAIN'],
    [
      'eleven certificates',
      { certificateChain: Array(11).fill('AAAA') },
      'INVALID_CERTIFICATE_CHAIN',
    ],
    ['a base64url member', { certificateChain: ['ab-_'] }, 'INVALID_CERTIFICATE_CHAIN'],
    ['an unpadded member', { certificateChain: ['abc'] }, 'INVALID_CERTIFICATE_CHAIN'],
    ['a member that is not a string', { certificateChain: [1] }, 'INVALID_CERTIFICATE_CHAIN'],
    ['an overlong member', { certificateChain: ['A'.repeat(16_388)] }, 'INVALID_CERTIFICATE_CHAIN'],
    ['a leaf that does not parse', { certificateChain: ['AAAA'] }, 'INVALID_CERTIFICATE_CHAIN'],
    ['a realm id that is not a UUID', { realmId: 'realm-a' }, 'INVALID_REALM_ID'],
    ['a caller-supplied key id', { kid: 'k' }, 'UNEXPECTED_FIELD'],
    ['a caller-supplied typ', { typ: 'JWT' }, 'UNEXPECTED_FIELD'],
    ['a caller-supplied header', { header: { alg: 'none' } }, 'UNEXPECTED_FIELD'],
  ] as const)('refuses %s, and unwraps nothing', async (_case, change, reason) => {
    const { signer, unwrap, verifierChains } = await setup({ scoped: true });
    const request = {
      ...requestObject(verifierChains),
      ...change,
    } as unknown as SignRequestObjectRequest;

    expect(await refusal(signer.signRequestObject('web', request))).toBe(reason);
    expect(unwrap).not.toHaveBeenCalled();
  });

  it('refuses a realm without the key', async () => {
    const { signer, verifierChains } = await setup({ scoped: true, realms: [REALM_A] });

    await expect(
      signer.signRequestObject(
        'web',
        requestObject(verifierChains, {
          realmId: REALM_B,
          certificateChain: verifierChains.get(REALM_A),
        })
      )
    ).rejects.toBeInstanceOf(SignerKeyNotFoundError);
  });

  it('is refused to every role but web and local', async () => {
    const { signer, verifierChains, unwrap } = await setup({ scoped: true });

    for (const caller of ['api', 'delivery', 'admin'] as const) {
      await expect(
        signer.signRequestObject(caller, requestObject(verifierChains))
      ).rejects.toMatchObject({ code: 'SIGNER_ACCESS_DENIED', caller });
    }
    expect(unwrap).not.toHaveBeenCalled();
    await expect(signer.signRequestObject('local', requestObject(verifierChains))).resolves.toEqual(
      expect.any(String)
    );
  });
});

describe('getUpstreamJwks', () => {
  it("lists one provider's published keys, next included, and nothing of the realm JWKS", async () => {
    const { signer, factory, keys } = await setup({ scoped: true });
    const [next] = await factory.createKey({
      realmId: REALM_A,
      purpose: 'upstream_client_assertion',
      scopeId: PROVIDER,
      status: 'next',
    });
    await factory.createKey({
      realmId: REALM_A,
      purpose: 'upstream_client_assertion',
      scopeId: 'provider-q',
    });
    const active = keys.rows.find(
      (row) =>
        row.key.realmId === REALM_A && row.key.scopeId === PROVIDER && row.key.status === 'active'
    )?.key.kid;

    const jwks = await signer.getUpstreamJwks('admin', REALM_A, PROVIDER);
    const realmJwks = await signer.getJwks('admin', REALM_A);

    // Both were published at NOW, so the fixed order falls back to the kid.
    expect(jwks.keys.map((key) => key.kid)).toEqual([active, next.kid].sort());
    for (const key of jwks.keys) {
      expect(key).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig' });
      expect(key).not.toHaveProperty('d');
    }
    expect(Object.isFrozen(jwks.keys)).toBe(true);
    expect(realmJwks.keys.map((key) => key.kid)).not.toContain(active);
  });

  it('keeps a retired key until its window closes, and drops a compromised one', async () => {
    const { signer, keys, store, advance } = await setup({ scoped: true });
    const kid = keys.rows.find((row) => row.key.realmId === REALM_A && row.key.scopeId === PROVIDER)
      ?.key.kid as string;
    store.update(REALM_A, kid, { status: 'retired', unpublishAt: NOW + 2 * REFRESH_MS });
    advance(REFRESH_MS);

    expect((await signer.getUpstreamJwks('local', REALM_A, PROVIDER)).keys).toHaveLength(1);
    advance(REFRESH_MS);
    expect((await signer.getUpstreamJwks('local', REALM_A, PROVIDER)).keys).toEqual([]);

    store.update(REALM_A, kid, { status: 'compromised', unpublishAt: null });
    advance(REFRESH_MS);
    expect((await signer.getUpstreamJwks('local', REALM_A, PROVIDER)).keys).toEqual([]);
  });

  it('is empty for a provider with no key, and refuses a malformed provider id', async () => {
    const { signer } = await setup({ scoped: true });

    await expect(signer.getUpstreamJwks('web', REALM_A, 'unknown')).resolves.toEqual({ keys: [] });
    expect(await refusal(signer.getUpstreamJwks('web', REALM_A, ''))).toBe('INVALID_SCOPE_ID');
  });
});

/** One call per operation, with a valid request. Typed so a new operation must be added. */
const CALLS: Record<SignerOperation, (signer: Signer, caller: SignerCaller) => Promise<unknown>> = {
  signJws: (signer, caller) => signer.signJws(caller, accessToken()),
  signHybrid: (signer, caller) =>
    signer.signHybrid(caller, { realmId: REALM_A, typ: 'at+jwt', claims: CLAIMS }),
  getCookieSecrets: (signer, caller) => signer.getCookieSecrets(caller, REALM_A),
  encrypt: (signer, caller) =>
    signer.encrypt(caller, { realmId: REALM_A, plaintext: Buffer.from('data') }),
  decrypt: async (signer, caller) =>
    signer.decrypt(caller, {
      realmId: REALM_A,
      ciphertext: await signer.encrypt('local', {
        realmId: REALM_A,
        plaintext: Buffer.from('data'),
      }),
    }),
  getVerificationKeys: (signer, caller) =>
    signer.getVerificationKeys(caller, REALM_A, 'token_signing'),
  getJwks: (signer, caller) => signer.getJwks(caller, REALM_A),
  signWebhook: (signer, caller) => signer.signWebhook(caller, webhook()),
  signClientAssertion: (signer, caller) => signer.signClientAssertion(caller, assertion()),
  signRequestObject: (signer, caller) =>
    signer.signRequestObject(caller, requestObject(VERIFIER_CHAINS.get(signer))),
  getUpstreamJwks: (signer, caller) => signer.getUpstreamJwks(caller, REALM_A, PROVIDER),
};

describe('caller policy', () => {
  const cases = SIGNER_CALLERS.flatMap((caller) =>
    SIGNER_OPERATIONS.map((operation) => [caller, operation] as const)
  );

  it.each(cases)('%s calling %s follows SIGNER_POLICY', async (caller, operation) => {
    const { signer } = await setup({ hybrid: true, scoped: true });
    const grant = SIGNER_POLICY[caller];
    // The table's encrypt and decrypt use no context, so a role whose grant is
    // a list of prefixes (web's encrypt, delivery's and api's decrypt) is
    // refused them; the encrypt and decrypt tests above cover a context inside
    // each list.
    const allowed =
      operation === 'signJws'
        ? grant.signJws.includes('at+jwt')
        : operation === 'decrypt' || operation === 'encrypt'
          ? grant[operation] === true
          : grant[operation];

    const result = CALLS[operation](signer, caller);

    if (allowed) {
      await expect(result).resolves.toBeDefined();
    } else {
      await expect(result).rejects.toBeInstanceOf(SignerAccessDeniedError);
    }
  });

  it('refuses getCookieSecrets to delivery', async () => {
    const { signer, unwrap } = await setup();

    await expect(signer.getCookieSecrets('delivery', REALM_A)).rejects.toMatchObject({
      code: 'SIGNER_ACCESS_DENIED',
      caller: 'delivery',
      operation: 'getCookieSecrets',
    });
    expect(unwrap).not.toHaveBeenCalled();
  });

  it.each(['token_signing', 'event_signing'] as const)(
    'refuses signJws for %s to web',
    async (purpose) => {
      const { signer } = await setup();
      const typ = JWS_TYP_BY_PURPOSE[purpose][0];

      await expect(
        signer.signJws('web', accessToken(REALM_A, { purpose, typ }))
      ).rejects.toMatchObject({ code: 'SIGNER_ACCESS_DENIED', caller: 'web', purpose });
    }
  );

  it('refuses signWebhook to web and signClientAssertion to delivery, and unwraps nothing', async () => {
    const { signer, unwrap } = await setup({ scoped: true });

    await expect(signer.signWebhook('web', webhook())).rejects.toMatchObject({
      code: 'SIGNER_ACCESS_DENIED',
      caller: 'web',
      operation: 'signWebhook',
    });
    await expect(signer.signClientAssertion('delivery', assertion())).rejects.toMatchObject({
      code: 'SIGNER_ACCESS_DENIED',
      caller: 'delivery',
      operation: 'signClientAssertion',
    });
    expect(unwrap).not.toHaveBeenCalled();
  });

  it('lets delivery sign webhooks and not client assertions; api the other way round', async () => {
    const { signer } = await setup({ scoped: true });

    await expect(signer.signWebhook('delivery', webhook())).resolves.toMatch(/^v1,/);
    await expect(signer.signClientAssertion('api', assertion())).resolves.toEqual(
      expect.any(String)
    );
    await expect(signer.signWebhook('api', webhook())).rejects.toBeInstanceOf(
      SignerAccessDeniedError
    );
    for (const caller of ['delivery', 'web', 'admin'] as const) {
      await expect(signer.signClientAssertion(caller, assertion())).rejects.toBeInstanceOf(
        SignerAccessDeniedError
      );
    }
  });

  it('lets delivery sign event tokens and not access tokens; api the other way round', async () => {
    const { signer } = await setup();
    const logout = eventToken(REALM_A, 'logout+jwt');

    await expect(signer.signJws('delivery', logout)).resolves.toEqual(expect.any(String));
    await expect(signer.signJws('delivery', accessToken())).rejects.toBeInstanceOf(
      SignerAccessDeniedError
    );
    await expect(signer.signJws('api', accessToken())).resolves.toEqual(expect.any(String));
    await expect(signer.signJws('api', logout)).rejects.toBeInstanceOf(SignerAccessDeniedError);
  });

  it.each(['signer', 'LOCAL', '', undefined, 'web; local'])(
    'refuses the unknown caller %s without echoing it',
    async (caller) => {
      const { signer } = await setup();

      const error = await signer
        .getJwks(caller as unknown as SignerCaller, REALM_A)
        .catch((e) => e);

      expect(error).toBeInstanceOf(SignerAccessDeniedError);
      expect(error.caller).toBeUndefined();
      if (caller) expect(error.message).not.toContain(`'${caller}'`);
    }
  );
});

describe('key material', () => {
  /** Every private material the realm stores, opened with the KEK, in the forms it could leak in. */
  async function storedMaterials(setup: Setup) {
    const materials: { purpose: string; bytes: Buffer }[] = [];
    for (const { key } of setup.keys.rows) {
      const bytes = await openKeyMaterial(setup.kekProvider, key, key);
      materials.push({ purpose: key.purpose, bytes });
      // The raw Ed25519 private key is the last 32 bytes of its PKCS#8 form.
      if (key.algorithm === 'EdDSA') {
        materials.push({ purpose: key.purpose, bytes: bytes.subarray(bytes.length - 32) });
      }
    }
    return materials;
  }

  function encodings(bytes: Buffer): string[] {
    return [bytes.toString('base64url'), bytes.toString('base64'), bytes.toString('hex')];
  }

  /** The purposes whose material appears anywhere in `value`, and any key object found. */
  function leaks(value: unknown, materials: { purpose: string; bytes: Buffer }[]) {
    const found = new Set<string>();
    const visit = (node: unknown): void => {
      if (node instanceof KeyObject || node instanceof MlDsaKey) found.add('key object');
      else if (typeof CryptoKey !== 'undefined' && node instanceof CryptoKey)
        found.add('key object');
      else if (node instanceof Uint8Array) {
        for (const { purpose, bytes } of materials) {
          if (Buffer.from(node).includes(bytes)) found.add(purpose);
        }
      } else if (typeof node === 'string') {
        for (const { purpose, bytes } of materials) {
          if (encodings(bytes).some((encoded) => node.includes(encoded))) found.add(purpose);
        }
      } else if (typeof node === 'object' && node !== null) {
        for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv']) {
          if (Object.hasOwn(node, member) && 'kty' in node) found.add('private JWK member');
        }
        for (const child of Object.values(node)) visit(child);
        if (node instanceof Error) visit(node.message);
      }
    };
    visit(value);
    return [...found].sort();
  }

  it('offers exactly the operations of the interface', async () => {
    const { signer } = await setup({ hybrid: true, scoped: true });

    expect(Reflect.ownKeys(signer).sort()).toEqual([...SIGNER_OPERATIONS].sort());
    expect(Object.keys(CALLS).sort()).toEqual([...SIGNER_OPERATIONS].sort());
    expect(Object.isFrozen(signer)).toBe(true);
  });

  it('returns no key material from any operation but the cookie secrets', async () => {
    const context = await setup({ hybrid: true, scoped: true });
    const materials = await storedMaterials(context);
    expect(materials.map(({ purpose }) => purpose)).toEqual(
      expect.arrayContaining([
        'token_signing',
        'event_signing',
        'cookie_hmac',
        'data_at_rest',
        'webhook_signing',
        'upstream_client_assertion',
        'oid4vp_request_signing',
      ])
    );

    for (const operation of Object.keys(context.signer) as SignerOperation[]) {
      const result = await CALLS[operation](context.signer, 'local');
      const expected = operation === 'getCookieSecrets' ? ['cookie_hmac'] : [];

      expect({ operation, leaks: leaks(result, materials) }).toEqual({
        operation,
        leaks: expected,
      });
    }
  });

  it('returns a webhook secret once, from createKey, and never from a later call', async () => {
    const context = await setup({ hybrid: true, scoped: true });
    const scope = { realmId: REALM_A, purpose: 'webhook_signing', scopeId: SUBSCRIPTION } as const;
    const [next] = await context.factory.createKey({ ...scope, status: 'next' });
    const shown = [context.webhookSecrets.get(REALM_A) as string, next.secret as string];
    const secrets = shown.map((secret) => ({
      purpose: 'webhook_signing',
      bytes: Buffer.from(secret.slice('whsec_'.length), 'base64'),
    }));
    expect(secrets.map(({ bytes }) => bytes.length)).toEqual([32, 32]);

    const later: unknown[] = [];
    for (const caller of SIGNER_CALLERS) {
      for (const operation of SIGNER_OPERATIONS) {
        later.push(await CALLS[operation](context.signer, caller).catch((e: unknown) => e));
      }
    }
    const rotation = createKeyFactory({
      store: context.keys,
      kekProvider: context.kekProvider,
      enabledSignatureAlgorithms: context.enabled,
      hybridSigning: true,
      prepublishMs: 0,
      now: () => NOW,
    });
    later.push(
      await rotation.activateNextKey(scope),
      await rotation.provisionRealmKeys(REALM_A),
      await rotation.createKey({ ...scope, scopeId: 'subscription-2' }),
      await rotation.createKey({ ...scope, status: 'next' }).catch((e: unknown) => e),
      await rotation.activateNextKey(scope).catch((e: unknown) => e),
      await rotation.deleteScopedKeys(scope)
    );

    // Every encoding of both secrets, the whsec_ form included, is searched for.
    expect(leaks(later, secrets)).toEqual([]);
  });

  it('puts no key material in an error', async () => {
    const context = await setup({ hybrid: true, scoped: true });
    const materials = await storedMaterials(context);
    const errors = await Promise.all([
      context.signer.signJws('local', accessToken(REALM_A, { typ: 'logout+jwt' })).catch((e) => e),
      context.signer.signJws('web', accessToken()).catch((e) => e),
      context.signer.signJws('local', accessToken(REALM_WITHOUT_KEYS)).catch((e) => e),
      context.signer.decrypt('local', { realmId: REALM_A, ciphertext: 'v1.x.y.z' }).catch((e) => e),
      context.signer.signWebhook('local', webhook({ id: 'a.b' })).catch((e) => e),
      context.signer.signWebhook('local', webhook({ subscriptionId: 'other' })).catch((e) => e),
      context.signer
        .signClientAssertion('local', assertion({ providerId: 'other' }))
        .catch((e) => e),
    ]);
    const kekFailure = await (
      await setup({ hybrid: true, signerKek: localProvider({ KEK: KEK_B }) })
    ).signer
      .signHybrid('local', { realmId: REALM_A, typ: 'at+jwt', claims: CLAIMS })
      .catch((e) => e);

    for (const error of [...errors, kekFailure]) {
      expect(error).toBeInstanceOf(Error);
      expect(leaks(error, materials)).toEqual([]);
      expect(leaks(JSON.stringify(error), materials)).toEqual([]);
    }
  });
});
