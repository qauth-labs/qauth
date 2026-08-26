import type { FastifyBaseLogger, FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Credential-status audit CORRELATION (#378).
 *
 * The audit sink is the only server-side channel that carries the checker's
 * fine-grained rejection reason — status refusals deliberately bypass
 * `onRefusal` so that vocabulary can never reach the wire. An audit line an
 * operator cannot tie to a login attempt therefore makes the one diagnostic the
 * design leaves them useless for diagnosis, which is what these tests pin.
 *
 * Isolated in its own file because it mocks the checker factory to capture the
 * `onAudit` callback the deployment builds, which the sibling suite must not
 * inherit.
 */

const { envMock } = vi.hoisted(() => ({
  envMock: {
    WALLET_FEDERATION_ENABLED: true,
    JWT_ISSUER: 'https://auth.example.com',
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' as string | undefined,
    // The verifier-identity variables at their parsed DEFAULTS (#377). Stated
    // rather than omitted because the request path now resolves the profile with
    // the deployment's provisioned material, and
    // `resolveVerifierCertificateChainPems` reads `.length` off the array forms —
    // which the real parsed env always supplies (Zod defaults them to `[]`) and
    // an env stub silently would not.
    OID4VP_VERIFIER_SIGNING_KEY: undefined as string | undefined,
    OID4VP_VERIFIER_SIGNING_KEY_PATH: undefined as string | undefined,
    OID4VP_VERIFIER_CERTIFICATE_CHAIN: [] as readonly string[],
    OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: [] as readonly string[],
    OID4VP_VERIFIER_TRUST_ANCHORS: [] as readonly string[],
    OID4VP_VERIFIER_TRUST_ANCHORS_PATH: [] as readonly string[],
    OID4VP_REQUESTED_VCT: ['urn:example:pid'] as readonly string[] | undefined,
    OID4VP_WALLET_INVOCATION_ENDPOINT: 'openid4vp://',
    OID4VP_SUBJECT_RESOLUTION: undefined as string | undefined,
    OID4VP_SUBJECT_BINDING_CLAIMS: ['given_name'] as readonly string[] | undefined,
    OID4VP_SUBJECT_CLAIM: undefined as string | undefined,
    OID4VP_SUBJECT_CLAIM_ISSUERS: undefined as readonly string[] | undefined,
    OID4VP_TRUSTED_ISSUERS: {} as Record<string, readonly string[]>,
    OID4VP_ISSUER_JWKS: {} as Record<string, readonly Record<string, unknown>[]>,
    OID4VP_STATUS_LIST_TRUST_ANCHORS: ['-----BEGIN CERTIFICATE-----fake-----END CERTIFICATE-----'],
    OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH: [] as readonly string[],
    OID4VP_STATUS_LIST_URI_ALLOWLIST: ['https://status.example.com/'],
  },
}));

const { capturedOnAudit } = vi.hoisted(() => ({
  capturedOnAudit: { current: undefined as ((event: unknown) => void) | undefined },
}));

vi.mock('../../config/env', () => ({ env: envMock }));

// The anchors are never parsed here: the factory that would consume them is
// stubbed below, so this only has to be non-empty for a checker to be built.
vi.mock('@qauth-labs/server-config', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@qauth-labs/server-config')>()),
  resolveStatusListTrustAnchorPems: () => ['-----BEGIN CERTIFICATE-----fake'],
}));

vi.mock('@qauth-labs/fastify-plugin-federation', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@qauth-labs/fastify-plugin-federation')>()),
  createConfiguredCredentialStatusChecker: (config: { onAudit?: (event: unknown) => void }) => {
    capturedOnAudit.current = config.onAudit;
    return { resolveCredentialStatus: vi.fn(), assertCredentialNotRevoked: vi.fn() };
  },
}));

import {
  hasCredentialStatusAuditContext,
  resolveWalletVerificationSetup,
  runWithCredentialStatusAuditContext,
} from './wallet-verification';

/** One accepted check, shaped like the real `CredentialStatusAuditEvent`. */
const ACCEPTED_EVENT = {
  decision: 'accepted' as const,
  cacheHit: false,
  fetched: true,
  durationMs: 12,
  statusListUri: 'https://status.example.com/list/1',
  idx: 42,
  spec: 'token-status-list-draft',
};

/** One refusal, which is the line an operator actually goes looking for. */
const REJECTED_EVENT = { ...ACCEPTED_EVENT, decision: 'rejected' as const, reason: 'revoked' };

function makeLogger(): FastifyBaseLogger {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  } as unknown as FastifyBaseLogger;
}

function makeFastify(log: FastifyBaseLogger): FastifyInstance {
  return {
    repositories: { realms: { findById: vi.fn().mockResolvedValue(undefined) } },
    log,
  } as unknown as FastifyInstance;
}

/** Build the deployment's checker so its `onAudit` is captured. */
function bootAndCaptureAudit(serverLog: FastifyBaseLogger): (event: unknown) => void {
  resolveWalletVerificationSetup(makeFastify(serverLog));
  const onAudit = capturedOnAudit.current;
  if (onAudit === undefined) throw new Error('the deployment built no status checker');
  return onAudit;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('credential status audit correlation (#378)', () => {
  it('stamps the realm and uses the REQUEST logger inside a scope', () => {
    const serverLog = makeLogger();
    const onAudit = bootAndCaptureAudit(serverLog);
    const requestLog = makeLogger();

    runWithCredentialStatusAuditContext({ log: requestLog, realmId: 'realm-1' }, () => {
      onAudit(REJECTED_EVENT);
    });

    // The refusal goes to the REQUEST logger, whose lines carry `reqId`, and
    // carries the realm — the two things that let an operator tie this line to
    // the login attempt that produced it.
    expect(requestLog.warn).toHaveBeenCalledWith(
      expect.objectContaining({ decision: 'rejected', reason: 'revoked', realmId: 'realm-1' }),
      'credential status check refused a credential'
    );
    expect(serverLog.warn).not.toHaveBeenCalled();
  });

  it('records accepted checks too, so a rejection counter has a denominator', () => {
    const serverLog = makeLogger();
    const onAudit = bootAndCaptureAudit(serverLog);
    const requestLog = makeLogger();

    runWithCredentialStatusAuditContext({ log: requestLog, realmId: 'realm-1' }, () => {
      onAudit(ACCEPTED_EVENT);
    });

    expect(requestLog.info).toHaveBeenCalledWith(
      expect.objectContaining({ decision: 'accepted', realmId: 'realm-1' }),
      'credential status check accepted a credential'
    );
  });

  it('survives an await — the checker is async, so a scope that did not would be useless', async () => {
    const serverLog = makeLogger();
    const onAudit = bootAndCaptureAudit(serverLog);
    const requestLog = makeLogger();

    await runWithCredentialStatusAuditContext({ log: requestLog, realmId: 'realm-9' }, async () => {
      await Promise.resolve();
      await new Promise((resolve) => setTimeout(resolve, 1));
      onAudit(REJECTED_EVENT);
    });

    expect(requestLog.warn).toHaveBeenCalledWith(
      expect.objectContaining({ realmId: 'realm-9' }),
      'credential status check refused a credential'
    );
  });

  it('still RECORDS the event with no scope, losing only the correlation', () => {
    const serverLog = makeLogger();
    const onAudit = bootAndCaptureAudit(serverLog);

    onAudit(REJECTED_EVENT);

    // Never silently dropped: an unwrapped caller degrades to an uncorrelated
    // line, never to no line at all.
    expect(serverLog.warn).toHaveBeenCalledWith(
      expect.objectContaining({ decision: 'rejected' }),
      'credential status check refused a credential'
    );
    expect(serverLog.warn).toHaveBeenCalledWith(
      expect.not.objectContaining({ realmId: expect.anything() }),
      'credential status check refused a credential'
    );
  });

  it('never leaks the wallet-chosen URI or index anywhere but the log', () => {
    const serverLog = makeLogger();
    const onAudit = bootAndCaptureAudit(serverLog);
    const requestLog = makeLogger();

    runWithCredentialStatusAuditContext({ log: requestLog, realmId: 'realm-1' }, () => {
      onAudit(REJECTED_EVENT);
    });

    // `statusListUri` and `idx` are attacker-influenced. They belong in the
    // operator's log and nowhere else; this asserts they are at least present
    // there, so the diagnostic is real and the wire-side assertions elsewhere
    // are testing an actual omission rather than a value that never existed.
    const [record] = vi.mocked(requestLog.warn).mock.calls[0] as [Record<string, unknown>];
    expect(record['statusListUri']).toBe('https://status.example.com/list/1');
    expect(record['idx']).toBe(42);
  });

  it('reports no ambient scope outside one, so an inner seam can fill the gap', () => {
    expect(hasCredentialStatusAuditContext()).toBe(false);

    runWithCredentialStatusAuditContext({ log: makeLogger(), realmId: 'realm-1' }, () => {
      expect(hasCredentialStatusAuditContext()).toBe(true);
    });

    expect(hasCredentialStatusAuditContext()).toBe(false);
  });

  it('does not let an inner fallback clobber the richer scope a route set', () => {
    const serverLog = makeLogger();
    const onAudit = bootAndCaptureAudit(serverLog);
    const routeLog = makeLogger();

    runWithCredentialStatusAuditContext({ log: routeLog, realmId: 'realm-route' }, () => {
      // What `withStatusAuditCorrelation` in wallet-presentation.ts does: it
      // checks first, and only establishes a scope when there is none.
      if (!hasCredentialStatusAuditContext()) {
        throw new Error('the inner seam would have overwritten the route scope');
      }
      onAudit(REJECTED_EVENT);
    });

    expect(routeLog.warn).toHaveBeenCalledWith(
      expect.objectContaining({ realmId: 'realm-route' }),
      'credential status check refused a credential'
    );
  });
});
