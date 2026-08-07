import { InvalidCredentialsError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

import { DENY_ALL_TRUST_REGISTRY } from '../trust/trust-registry';
import {
  createCredentialStatusChecker,
  type CredentialStatusAuditEvent,
  type CredentialStatusCheckerConfig,
  DENY_ALL_CREDENTIAL_STATUS_CHECKER,
} from './credential-status-checker';
import { CREDENTIAL_STATUS_REJECTION_MESSAGE } from './credential-status-rejection';
import { createStatusEndpointBreaker } from './status-endpoint-breaker';
import { NO_STATUS_LIST_CACHE } from './status-list-cache';
import { createStatusListTrustAnchors } from './status-list-chain';
import type { StatusListFetch } from './status-list-fetch';
import { STATUS_LIST_TOKEN_TYP, TOKEN_STATUS_LIST_DRAFT } from './status-list-spec';
import { createStatusListUriAllowlist } from './status-list-uri';
import { encodeStatusList, signStatusListToken } from './test/status-list-fixtures';
import { createTestCertificate } from './test/x509-fixtures';

const NOW_MS = Date.parse('2026-07-26T12:00:00.000Z');
const nowSeconds = Math.floor(NOW_MS / 1000);
const validity = {
  notBefore: new Date('2026-07-01T00:00:00.000Z'),
  notAfter: new Date('2026-08-31T00:00:00.000Z'),
};

const root = createTestCertificate({ subject: 'QAuth Test Root', ca: true, ...validity });
const signer = createTestCertificate({
  subject: 'status.issuer.example',
  issuer: root,
  dnsNames: ['status.issuer.example'],
  ...validity,
});
const anchors = createStatusListTrustAnchors([root.pem]);
const uriAllowlist = createStatusListUriAllowlist(['https://status.issuer.example/lists']);

const URI = 'https://status.issuer.example/lists/1';

/** Index 0 VALID, 1 INVALID, 2 SUSPENDED, 3 application-specific. */
const ENTRIES = [0, 1, 2, 3, 0, 0, 0, 0];
const LST = encodeStatusList(ENTRIES, 2);

function statusListToken(
  overrides: Record<string, unknown> = {},
  header: Record<string, unknown> = {}
): string {
  return signStatusListToken({
    signer,
    header: { typ: STATUS_LIST_TOKEN_TYP, x5c: [signer.x5c], ...header },
    claims: {
      iss: 'https://status.issuer.example',
      sub: URI,
      iat: nowSeconds - 60,
      exp: nowSeconds + 3_600,
      ttl: 300,
      status_list: { bits: 2, lst: LST },
      ...overrides,
    },
  });
}

function status(idx: number, uri: string = URI): unknown {
  return { status_list: { idx, uri } };
}

interface Harness {
  readonly checker: ReturnType<typeof createCredentialStatusChecker>;
  readonly fetchToken: ReturnType<typeof vi.fn>;
  readonly audit: CredentialStatusAuditEvent[];
  advance(ms: number): void;
}

function harness(
  overrides: Partial<CredentialStatusCheckerConfig> = {},
  fetchImpl?: StatusListFetch
): Harness {
  let clock = NOW_MS;
  const audit: CredentialStatusAuditEvent[] = [];
  const fetchToken = vi.fn(
    fetchImpl ?? (async () => ({ outcome: 'ok' as const, token: statusListToken() }))
  );

  const checker = createCredentialStatusChecker({
    trustAnchors: anchors,
    uriAllowlist,
    fetch: fetchToken as unknown as StatusListFetch,
    now: () => clock,
    onAudit: (event) => audit.push(event),
    ...overrides,
  });

  return {
    checker,
    fetchToken,
    audit,
    advance: (ms: number): void => {
      clock += ms;
    },
  };
}

describe('createCredentialStatusChecker (#297)', () => {
  describe('status lookups', () => {
    it('accepts a credential whose bit is VALID', async () => {
      const { checker } = harness();
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({ decision: 'valid' });
      await expect(checker.assertCredentialNotRevoked(status(0))).resolves.toBeUndefined();
    });

    it('rejects a credential whose bit is INVALID', async () => {
      const { checker } = harness();
      expect(await checker.resolveCredentialStatus(status(1))).toEqual({
        decision: 'rejected',
        reason: 'revoked',
      });
    });

    it('rejects a credential whose bit is SUSPENDED', async () => {
      const { checker } = harness();
      expect(await checker.resolveCredentialStatus(status(2))).toEqual({
        decision: 'rejected',
        reason: 'suspended',
      });
    });

    it('rejects a status value this deployment has no meaning for', async () => {
      // draft-14 §7.1 leaves 0x03 application-specific. "Unknown" is not "valid".
      expect(await harness().checker.resolveCredentialStatus(status(3))).toEqual({
        decision: 'rejected',
        reason: 'status-unknown',
      });
    });

    it('rejects an index past the end of the list', async () => {
      expect(await harness().checker.resolveCredentialStatus(status(9_999))).toEqual({
        decision: 'rejected',
        reason: 'index-out-of-range',
      });
    });

    it('rejects a list whose lst cannot be decoded', async () => {
      const { checker } = harness({}, async () => ({
        outcome: 'ok',
        token: statusListToken({ status_list: { bits: 2, lst: 'not!base64url' } }),
      }));
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({
        decision: 'rejected',
        reason: 'list-unreadable',
      });
    });
  });

  describe('the status claim itself', () => {
    it('rejects an absent status claim when the profile requires one', async () => {
      const { checker } = harness();
      expect(await checker.resolveCredentialStatus(undefined)).toEqual({
        decision: 'rejected',
        reason: 'status-required-but-absent',
      });
      expect(await checker.resolveCredentialStatus(null, { statusRequired: true })).toEqual({
        decision: 'rejected',
        reason: 'status-required-but-absent',
      });
    });

    it('defaults to REQUIRING status when the caller says nothing', async () => {
      // The safe default is the one that refuses: forgetting to pass the
      // profile posture must not silently relax the check.
      expect(await harness().checker.resolveCredentialStatus(undefined)).toMatchObject({
        decision: 'rejected',
      });
    });

    it('accepts an absent status claim when the profile does not require one', async () => {
      const { checker, fetchToken } = harness();
      expect(await checker.resolveCredentialStatus(undefined, { statusRequired: false })).toEqual({
        decision: 'valid',
      });
      expect(fetchToken).not.toHaveBeenCalled();
    });

    it('rejects a PRESENT but unusable status claim even when status is optional', async () => {
      // HAIP §6.1: a credential that carries `status` MUST carry `status_list`.
      // A mechanism we cannot evaluate is a status we have not established.
      const { checker } = harness();
      for (const claim of [
        { some_other_mechanism: { id: 1 } },
        { status_list: { idx: -1, uri: URI } },
        { status_list: { idx: 0 } },
        'nonsense',
      ]) {
        expect(await checker.resolveCredentialStatus(claim, { statusRequired: false })).toEqual({
          decision: 'rejected',
          reason: 'malformed-status-claim',
        });
      }
    });
  });

  describe('SSRF boundary', () => {
    it('refuses a URI outside the allowlist and never dials it', async () => {
      const { checker, fetchToken } = harness();
      expect(
        await checker.resolveCredentialStatus(
          status(0, 'https://169.254.169.254/latest/meta-data/')
        )
      ).toEqual({ decision: 'rejected', reason: 'uri-not-permitted' });
      expect(fetchToken).not.toHaveBeenCalled();
    });

    it('refuses everything when no allowlist is configured', async () => {
      const { checker, fetchToken } = harness({ uriAllowlist: undefined });
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({
        decision: 'rejected',
        reason: 'uri-not-permitted',
      });
      expect(fetchToken).not.toHaveBeenCalled();
    });
  });

  describe('fail-closed on verification failure', () => {
    it('rejects when the endpoint is unreachable', async () => {
      const { checker } = harness({}, async () => ({ outcome: 'failed' }));
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({
        decision: 'rejected',
        reason: 'endpoint-unavailable',
      });
    });

    it('contains a transport that throws instead of letting it become a 500', async () => {
      const { checker } = harness({}, async () => {
        throw new Error('ECONNRESET');
      });
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({
        decision: 'rejected',
        reason: 'endpoint-unavailable',
      });
    });

    it('rejects a token whose signature does not verify', async () => {
      const { checker } = harness({}, async () => ({
        outcome: 'ok',
        token: signStatusListToken({
          signer,
          header: { typ: STATUS_LIST_TOKEN_TYP, x5c: [signer.x5c] },
          claims: { iss: 'https://status.issuer.example', sub: URI, iat: nowSeconds },
          tamper: true,
        }),
      }));
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({
        decision: 'rejected',
        reason: 'token-unverifiable',
      });
    });

    it('rejects a token from an unanchored status issuer', async () => {
      const { checker } = harness({ trustAnchors: undefined });
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({
        decision: 'rejected',
        reason: 'issuer-untrusted',
      });
    });

    it('rejects an expired Status List Token', async () => {
      const { checker } = harness({}, async () => ({
        outcome: 'ok',
        token: statusListToken({ exp: nowSeconds - 1 }),
      }));
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({
        decision: 'rejected',
        reason: 'token-unverifiable',
      });
    });

    it('rejects a token published for a DIFFERENT list', async () => {
      const { checker } = harness({}, async () => ({
        outcome: 'ok',
        token: statusListToken({ sub: 'https://status.issuer.example/lists/999' }),
      }));
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({
        decision: 'rejected',
        reason: 'token-unverifiable',
      });
    });

    it('honours an optional issuer trust registry', async () => {
      const { checker } = harness({ issuerTrustRegistry: DENY_ALL_TRUST_REGISTRY });
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({
        decision: 'rejected',
        reason: 'issuer-untrusted',
      });
    });

    it('never returns valid on any failure path', async () => {
      const failures: StatusListFetch[] = [
        async () => ({ outcome: 'failed' }),
        async () => ({ outcome: 'ok', token: 'garbage' }),
        async () => ({ outcome: 'ok', token: statusListToken({ iss: 'https://evil.example' }) }),
        async () => ({ outcome: 'ok', token: statusListToken({ status_list: undefined }) }),
      ];

      for (const fetchImpl of failures) {
        const { checker } = harness({}, fetchImpl);
        expect(await checker.resolveCredentialStatus(status(0))).toMatchObject({
          decision: 'rejected',
        });
      }
    });
  });

  describe('caching', () => {
    it('does not perform an uncached fetch on every login', async () => {
      const { checker, fetchToken } = harness();

      for (let index = 0; index < 5; index += 1) {
        expect(await checker.resolveCredentialStatus(status(0))).toEqual({ decision: 'valid' });
      }
      expect(fetchToken).toHaveBeenCalledTimes(1);
    });

    it('re-fetches once the issuer ttl elapses', async () => {
      const { checker, fetchToken, advance } = harness();
      await checker.resolveCredentialStatus(status(0));

      advance(299_000);
      await checker.resolveCredentialStatus(status(0));
      expect(fetchToken).toHaveBeenCalledTimes(1);

      advance(2_000);
      await checker.resolveCredentialStatus(status(0));
      expect(fetchToken).toHaveBeenCalledTimes(2);
    });

    it('caps reuse at the operator ceiling even when the issuer asks for more', async () => {
      // `ttl` is the ISSUER's claim; letting it win would let an issuer choose
      // QAuth's revocation-freshness window for it.
      const { checker, fetchToken, advance } = harness({ maxCacheTtlSeconds: 30 }, async () => ({
        outcome: 'ok',
        token: statusListToken({ ttl: 86_400 }),
      }));

      await checker.resolveCredentialStatus(status(0));
      advance(31_000);
      await checker.resolveCredentialStatus(status(0));
      expect(fetchToken).toHaveBeenCalledTimes(2);
    });

    it('never caches beyond the token exp', async () => {
      const { checker, fetchToken, advance } = harness({ maxCacheTtlSeconds: 3_600 }, async () => ({
        outcome: 'ok',
        token: statusListToken({ exp: nowSeconds + 20, ttl: 3_600 }),
      }));

      await checker.resolveCredentialStatus(status(0));
      advance(21_000);
      await checker.resolveCredentialStatus(status(0));
      expect(fetchToken).toHaveBeenCalledTimes(2);
    });

    it('does not cache failures', async () => {
      let attempt = 0;
      const { checker, fetchToken } = harness({}, async () => {
        attempt += 1;
        return attempt === 1
          ? { outcome: 'failed' as const }
          : { outcome: 'ok' as const, token: statusListToken() };
      });

      expect(await checker.resolveCredentialStatus(status(0))).toMatchObject({
        decision: 'rejected',
      });
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({ decision: 'valid' });
      expect(fetchToken).toHaveBeenCalledTimes(2);
    });

    it('serves every index of a cached list from one fetch', async () => {
      const { checker, fetchToken } = harness();
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({ decision: 'valid' });
      expect(await checker.resolveCredentialStatus(status(1))).toMatchObject({
        reason: 'revoked',
      });
      expect(fetchToken).toHaveBeenCalledTimes(1);
    });

    it('coalesces concurrent lookups into a single fetch', async () => {
      let release: (() => void) | undefined;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const { checker, fetchToken } = harness({}, async () => {
        await gate;
        return { outcome: 'ok', token: statusListToken() };
      });

      const pending = Promise.all([
        checker.resolveCredentialStatus(status(0)),
        checker.resolveCredentialStatus(status(0)),
        checker.resolveCredentialStatus(status(1)),
      ]);
      release?.();

      expect(await pending).toEqual([
        { decision: 'valid' },
        { decision: 'valid' },
        { decision: 'rejected', reason: 'revoked' },
      ]);
      expect(fetchToken).toHaveBeenCalledTimes(1);
    });

    it('fetches every time when caching is disabled', async () => {
      const { checker, fetchToken } = harness({ cache: NO_STATUS_LIST_CACHE });
      await checker.resolveCredentialStatus(status(0));
      await checker.resolveCredentialStatus(status(0));
      expect(fetchToken).toHaveBeenCalledTimes(2);
    });
  });

  describe('circuit breaker', () => {
    it('short-circuits an unreachable endpoint without dialling it', async () => {
      const { checker, fetchToken } = harness(
        { breaker: createStatusEndpointBreaker({ failureThreshold: 2, now: () => NOW_MS }) },
        async () => ({ outcome: 'failed' })
      );

      await checker.resolveCredentialStatus(status(0));
      await checker.resolveCredentialStatus(status(0));
      expect(fetchToken).toHaveBeenCalledTimes(2);

      expect(await checker.resolveCredentialStatus(status(0))).toEqual({
        decision: 'rejected',
        reason: 'circuit-open',
      });
      expect(fetchToken).toHaveBeenCalledTimes(2);
    });

    it('opening the circuit REJECTS; it never degrades to accepting', async () => {
      const { checker } = harness(
        { breaker: createStatusEndpointBreaker({ failureThreshold: 1, now: () => NOW_MS }) },
        async () => ({ outcome: 'failed' })
      );

      await checker.resolveCredentialStatus(status(0));
      for (let index = 0; index < 5; index += 1) {
        expect(await checker.resolveCredentialStatus(status(0))).toMatchObject({
          decision: 'rejected',
        });
      }
    });

    it('counts an unverifiable token as an endpoint failure', async () => {
      const { checker, fetchToken } = harness(
        { breaker: createStatusEndpointBreaker({ failureThreshold: 1, now: () => NOW_MS }) },
        async () => ({ outcome: 'ok', token: 'garbage' })
      );

      await checker.resolveCredentialStatus(status(0));
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({
        decision: 'rejected',
        reason: 'circuit-open',
      });
      expect(fetchToken).toHaveBeenCalledTimes(1);
    });
  });

  describe('assertCredentialNotRevoked', () => {
    it('throws the single non-enumerating refusal', async () => {
      const { checker } = harness();
      await expect(checker.assertCredentialNotRevoked(status(1))).rejects.toBeInstanceOf(
        InvalidCredentialsError
      );
      await expect(checker.assertCredentialNotRevoked(status(1))).rejects.toThrow(
        CREDENTIAL_STATUS_REJECTION_MESSAGE
      );
    });

    it('throws the SAME error for every failure mode', async () => {
      const cases: unknown[] = [
        status(1),
        status(2),
        status(3),
        status(9_999),
        status(0, 'https://elsewhere.example/lists/1'),
        undefined,
        { status_list: { idx: 'x', uri: URI } },
      ];

      const messages = new Set<string>();
      for (const claim of cases) {
        const { checker } = harness();
        await checker.assertCredentialNotRevoked(claim).then(
          () => expect.unreachable('should have refused'),
          (error: unknown) => {
            expect(error).toBeInstanceOf(InvalidCredentialsError);
            messages.add((error as Error).message);
          }
        );
      }
      expect(messages.size).toBe(1);
    });
  });

  describe('audit and metrics', () => {
    it('reports an accepted check', async () => {
      const { checker, audit } = harness();
      await checker.resolveCredentialStatus(status(0));

      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({
        decision: 'accepted',
        statusListUri: URI,
        idx: 0,
        statusValue: 0,
        cacheHit: false,
        fetched: true,
        spec: TOKEN_STATUS_LIST_DRAFT,
      });
      expect(audit[0]?.reason).toBeUndefined();
    });

    it('reports a revocation rejection with its server-side reason', async () => {
      const { checker, audit } = harness();
      await checker.resolveCredentialStatus(status(1));

      expect(audit[0]).toMatchObject({
        decision: 'rejected',
        reason: 'revoked',
        statusValue: 1,
      });
    });

    it('marks a cache hit', async () => {
      const { checker, audit } = harness();
      await checker.resolveCredentialStatus(status(0));
      await checker.resolveCredentialStatus(status(0));

      expect(audit[0]).toMatchObject({ cacheHit: false, fetched: true });
      expect(audit[1]).toMatchObject({ cacheHit: true, fetched: false });
    });

    it('reports a refusal that never reached the network', async () => {
      const { checker, audit } = harness();
      await checker.resolveCredentialStatus(status(0, 'https://evil.example/1'));

      expect(audit[0]).toMatchObject({
        decision: 'rejected',
        reason: 'uri-not-permitted',
        fetched: false,
      });
    });

    it('does not let a throwing audit sink become the fault', async () => {
      const { checker } = harness({
        onAudit: () => {
          throw new Error('log pipeline is down');
        },
      });
      expect(await checker.resolveCredentialStatus(status(0))).toEqual({ decision: 'valid' });
    });
  });
});

describe('DENY_ALL_CREDENTIAL_STATUS_CHECKER (#297)', () => {
  it('refuses every credential', async () => {
    expect(
      await DENY_ALL_CREDENTIAL_STATUS_CHECKER.resolveCredentialStatus(status(0))
    ).toMatchObject({ decision: 'rejected' });
    await expect(
      DENY_ALL_CREDENTIAL_STATUS_CHECKER.assertCredentialNotRevoked(undefined, {
        statusRequired: false,
      })
    ).rejects.toBeInstanceOf(InvalidCredentialsError);
  });
});

describe('an unconfigured checker (#297)', () => {
  it('fails closed with no anchors, no allowlist and no transport', async () => {
    const checker = createCredentialStatusChecker();
    expect(await checker.resolveCredentialStatus(status(0))).toEqual({
      decision: 'rejected',
      reason: 'uri-not-permitted',
    });
  });
});
