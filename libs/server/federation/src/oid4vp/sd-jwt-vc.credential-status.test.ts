import { readFileSync } from 'node:fs';
import path from 'node:path';

import { InvalidCredentialsError } from '@qauth-labs/shared-errors';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  fixtureValidationContext,
  type IssuedSdJwtVc,
  issueSdJwtVc,
  presentSdJwtVc,
  TEST_CREDENTIAL_QUERY,
} from '../../testing/sd-jwt-vc.fixture';
import {
  createCredentialStatusChecker,
  type CredentialStatusAuditEvent,
  type CredentialStatusChecker,
} from '../status/credential-status-checker';
import { CREDENTIAL_STATUS_REJECTION_MESSAGE } from '../status/credential-status-rejection';
import { createStatusEndpointBreaker } from '../status/status-endpoint-breaker';
import { createStatusListTrustAnchors } from '../status/status-list-chain';
import { createHttpsStatusListFetch, type StatusListFetch } from '../status/status-list-fetch';
import { STATUS_LIST_TOKEN_MEDIA_TYPE, STATUS_LIST_TOKEN_TYP } from '../status/status-list-spec';
import { createStatusListUriAllowlist } from '../status/status-list-uri';
import { encodeStatusList, signStatusListToken } from '../status/test/status-list-fixtures';
import { createTestCertificate } from '../status/test/x509-fixtures';
import { issuerTrustRejection } from '../trust/issuer-trust-rejection';
import { isPresentationValidationRejection } from './presentation-rejection';
import { validateSdJwtVcPresentation } from './sd-jwt-vc';
import type { PresentationValidationContext } from './validated-credential';

/**
 * The #297 status gate AT the #234 seam — the defect #378 reports, closed.
 *
 * `status/credential-status-checker.test.ts` proves the CHECKER: that a bit is
 * read correctly, that a dead endpoint refuses, that the cache and the breaker
 * behave. Every one of those tests passed on `main` while a revoked credential
 * still authenticated a user exactly like a live one, because the checker had no
 * call site. So what this file proves is the WIRING, and it proves it through
 * the real entry point (`validateSdJwtVcPresentation`) with real signatures on
 * both sides: a real issuer-signed SD-JWT VC, and a real X.509-anchored Status
 * List Token.
 *
 * ## Nothing here is stubbed except the socket
 *
 * The checker is the shipping `createCredentialStatusChecker`, wired to real
 * anchors and a real URI allowlist. Only {@link StatusListFetch} is injected —
 * the network is the one part that has to be faked to express "the endpoint
 * 500s", and for the transport-level cases even that goes through the shipping
 * `createHttpsStatusListFetch` so the media-type and status-code rules under
 * test are the ones a deployment runs.
 *
 * ## Two invariants this file exists to defend
 *
 *  - **Fail-CLOSED.** There is deliberately NO test asserting that a timeout, a
 *    500, a wrong media type or an open circuit lets a login through. Each of
 *    those is a REJECTION. A future edit that adds a "log and continue" path
 *    would have to delete an assertion here to land, which is the point.
 *  - **One refusal, always.** A revoked credential and a credential from an
 *    untrusted issuer must be indistinguishable to a client. That is asserted
 *    against the actual error objects rather than by matching a message, because
 *    matching a message would still pass if the status path grew a `reason`
 *    field the trust path does not have.
 */

const NONCE = 'nonce-for-credential-status';

/** The status list this deployment's anchors cover. */
const STATUS_LIST_URI = 'https://status.issuer.example/lists/1';

/** The Status List Token issuer; its host is bound by the signer's dNSName SAN. */
const STATUS_ISSUER = 'https://status.issuer.example';

/** What an operator would put in `OID4VP_STATUS_LIST_URI_ALLOWLIST`. */
const URI_ALLOWLIST_PREFIX = 'https://status.issuer.example/lists';

/**
 * Index 0 VALID, 1 INVALID (revoked), 2 SUSPENDED, 3 application-specific.
 *
 * draft-14 §7.1 leaves 0x03 to the application, which means THIS deployment has
 * not been told what it means — and "unknown" is not "valid".
 */
const STATUS_ENTRIES = [0, 1, 2, 3, 0, 0, 0, 0];

/** Index into {@link STATUS_ENTRIES}, named so the tests read as intent. */
const IDX = Object.freeze({ live: 0, revoked: 1, suspended: 2, unknown: 3 });

const validity = {
  notBefore: new Date(Date.now() - 3_600_000),
  notAfter: new Date(Date.now() + 30 * 24 * 3_600_000),
};

const root = createTestCertificate({ subject: 'QAuth Status Test Root', ca: true, ...validity });
const statusSigner = createTestCertificate({
  subject: 'status.issuer.example',
  issuer: root,
  dnsNames: ['status.issuer.example'],
  ...validity,
});

const anchors = createStatusListTrustAnchors([root.pem]);
const uriAllowlist = createStatusListUriAllowlist([URI_ALLOWLIST_PREFIX]);

/** A correctly signed, anchored Status List Token for {@link STATUS_LIST_URI}. */
function statusListToken(): string {
  const nowSeconds = Math.floor(Date.now() / 1000);
  return signStatusListToken({
    signer: statusSigner,
    header: { typ: STATUS_LIST_TOKEN_TYP, x5c: [statusSigner.x5c] },
    claims: {
      iss: STATUS_ISSUER,
      sub: STATUS_LIST_URI,
      iat: nowSeconds - 60,
      exp: nowSeconds + 3_600,
      ttl: 300,
      status_list: { bits: 2, lst: encodeStatusList(STATUS_ENTRIES, 2) },
    },
  });
}

/** The `status` claim a credential carries, as an issuer would sign it. */
function statusClaim(idx: number, uri: string = STATUS_LIST_URI): Record<string, unknown> {
  return { status_list: { idx, uri } };
}

/** A checker plus the seams a test needs to observe it. */
interface StatusHarness {
  readonly checker: CredentialStatusChecker;
  /** Every outbound fetch the checker issued. */
  readonly fetches: ReturnType<typeof vi.fn>;
  /** Every audit event, in order — accepted ones included. */
  readonly audit: CredentialStatusAuditEvent[];
  /** Move the checker's clock forward, to age its cache out. */
  advance(ms: number): void;
}

/**
 * Build the deployment's checker.
 *
 * @param fetchImpl - the transport. Defaults to one that serves the good token.
 * @param options - a real per-origin breaker instead of the inert default.
 */
function statusHarness(
  fetchImpl?: StatusListFetch,
  options: { readonly realBreaker?: boolean } = {}
): StatusHarness {
  const audit: CredentialStatusAuditEvent[] = [];
  const fetches = vi.fn(
    fetchImpl ?? (async () => ({ outcome: 'ok' as const, token: statusListToken() }))
  );
  // Starts at the real clock so the fixture certificates and the token's `exp`
  // are live; only the CACHE horizon is what a test moves.
  let clock = Date.now();

  const checker = createCredentialStatusChecker({
    trustAnchors: anchors,
    uriAllowlist,
    fetch: fetches as unknown as StatusListFetch,
    onAudit: (event) => audit.push(event),
    now: () => clock,
    ...(options.realBreaker === true ? { breaker: createStatusEndpointBreaker() } : {}),
  });

  return {
    checker,
    fetches,
    audit,
    advance: (ms: number): void => {
      clock += ms;
    },
  };
}

/** An HTTP response a stub `fetch` hands to the shipping transport. */
function httpResponse(
  status: number,
  body: string,
  contentType: string = STATUS_LIST_TOKEN_MEDIA_TYPE
): Response {
  return new Response(body, { status, headers: { 'content-type': contentType } });
}

/** Issue a credential carrying (or not carrying) a `status` claim. */
async function issueWithStatus(
  status?: Record<string, unknown>,
  overrides: Parameters<typeof issueSdJwtVc>[0] = {}
): Promise<IssuedSdJwtVc> {
  return issueSdJwtVc({
    ...(status === undefined ? {} : { plainClaims: { status } }),
    ...overrides,
  });
}

/** Present an issued credential against this request. */
async function present(issued: IssuedSdJwtVc): Promise<string> {
  return presentSdJwtVc(issued, { nonce: NONCE });
}

/** Validate through the real entry point. */
async function validate(presentation: string, context: PresentationValidationContext) {
  return validateSdJwtVcPresentation(presentation, 'pid', TEST_CREDENTIAL_QUERY, context);
}

/**
 * Settle a validation, whichever way it goes.
 *
 * `.rejects.toThrow()` is not enough anywhere in this file: the whole subject is
 * WHICH refusal was produced, and a test that only proves "it threw" would pass
 * for a credential refused three gates earlier.
 */
async function settle(
  promise: Promise<unknown>
): Promise<{ ok: true; value: unknown } | { ok: false; error: unknown }> {
  return promise.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error })
  );
}

/** Assert the presentation was refused, and return the error verbatim. */
async function refusalOf(promise: Promise<unknown>): Promise<unknown> {
  const settled = await settle(promise);
  if (settled.ok) {
    expect.fail(
      `expected a refusal, but validation RESOLVED with ${JSON.stringify(settled.value)}. A credential whose status was not established must never produce a ValidatedCredential.`
    );
  }
  return settled.error;
}

/**
 * Every client-observable property of a refusal.
 *
 * Deliberately more than the message. #236's guarantee is that a caller cannot
 * tell WHICH gate refused, and a message comparison alone would still pass if
 * the status path attached a `reason`, a `detail` or a different status code.
 */
function refusalShape(error: unknown): Record<string, unknown> {
  const err = error as Error & Record<string, unknown>;
  return {
    constructor: err.constructor.name,
    name: err.name,
    message: err.message,
    code: err['code'],
    statusCode: err['statusCode'],
    // Own enumerable keys: anything a serializer or a log line would pick up.
    ownKeys: Object.keys(err).sort(),
    serialized: JSON.stringify(err),
  };
}

// --------------------------------------------------------------- the gate

describe('#297 at the #234 seam — a bit is actually read (#378)', () => {
  it('accepts a credential whose status-list bit reads VALID, and says so', async () => {
    const { checker, fetches } = statusHarness();
    const issued = await issueWithStatus(statusClaim(IDX.live));

    const validated = await validate(
      await present(issued),
      fixtureValidationContext(issued, NONCE, {
        credentialStatus: checker,
        requireCredentialStatus: true,
      })
    );

    // `'checked'` is the whole point of #378: not a boolean, and not a literal
    // `false` on a path that did check.
    expect(validated.assurance.statusChecked).toBe('checked');
    expect(fetches).toHaveBeenCalledTimes(1);
  });

  it('reports the status list URI it dialled, and dials nothing else', async () => {
    const { checker, fetches } = statusHarness();
    const issued = await issueWithStatus(statusClaim(IDX.live));

    await validate(
      await present(issued),
      fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
    );

    expect(fetches.mock.calls).toHaveLength(1);
    expect((fetches.mock.calls[0]?.[0] as { uri: string }).uri).toBe(STATUS_LIST_URI);
  });

  it.each([
    ['INVALID (revoked)', IDX.revoked],
    ['SUSPENDED', IDX.suspended],
    ['an application-specific value this deployment has no meaning for', IDX.unknown],
  ])('REFUSES a credential whose bit is %s', async (_label, idx) => {
    const { checker } = statusHarness();
    const issued = await issueWithStatus(statusClaim(idx));

    const error = await refusalOf(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
      )
    );

    expect(error).toBeInstanceOf(InvalidCredentialsError);
    expect((error as Error).message).toBe(CREDENTIAL_STATUS_REJECTION_MESSAGE);
  });

  it('refuses a REVOKED credential byte-identically to an UNTRUSTED issuer (#236)', async () => {
    // The acceptance criterion in its strongest available form. "Is my
    // credential revoked yet?" is the single question the holder of a credential
    // most wants to probe for, and it must be unanswerable: a revocation refusal
    // and a trust refusal are the SAME object, field for field.
    const { checker } = statusHarness();
    const issued = await issueWithStatus(statusClaim(IDX.revoked));

    const revoked = await refusalOf(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
      )
    );

    // The refusal #236 produces, obtained from the shipping factory rather than
    // hand-built, so this comparison tracks any future change to it.
    const untrusted: unknown = issuerTrustRejection();

    expect(refusalShape(revoked)).toEqual(refusalShape(untrusted));
    // Named individually as well, so a failure says WHICH property drifted.
    expect((revoked as Error).constructor).toBe((untrusted as Error).constructor);
    expect((revoked as Error).message).toBe((untrusted as Error).message);
    expect((revoked as { statusCode?: number }).statusCode).toBe(401);
    expect((revoked as { code?: string }).code).toBe('INVALID_CREDENTIALS');
  });

  it('leaks neither the status list URI nor the index into the thrown error', async () => {
    // Both are strings the WALLET chose. They are exactly what an operator needs
    // and exactly what a client must never be told.
    const { checker } = statusHarness();
    const issued = await issueWithStatus(statusClaim(IDX.revoked));

    const error = await refusalOf(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
      )
    );

    const surface = `${(error as Error).message}${JSON.stringify(error)}`;
    expect(surface).not.toContain('status.issuer.example');
    expect(surface).not.toContain('status_list');
    expect(surface).not.toContain('revoked');
    expect(error).not.toHaveProperty('reason');
    expect(error).not.toHaveProperty('detail');
  });

  it('is NOT a PresentationValidationRejection — the checker error propagates unwrapped', async () => {
    // Deliberate, and documented on `validateSdJwtVcPresentation`: wrapping it
    // would gain a `detail` whose only honest content is wallet-chosen data. The
    // wire is identical either way because the message already IS
    // `ISSUER_TRUST_REJECTION_MESSAGE`.
    const { checker } = statusHarness();
    const issued = await issueWithStatus(statusClaim(IDX.revoked));

    const error = await refusalOf(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
      )
    );

    expect(isPresentationValidationRejection(error)).toBe(false);
    expect(CREDENTIAL_STATUS_REJECTION_MESSAGE).toBe(issuerTrustRejection().message);
  });

  it('never produces a ValidatedCredential for a revoked credential', async () => {
    // The end-to-end form of the criterion: there is no object for a downstream
    // consumer to read claims off, so nothing can enrol an account from one.
    const { checker } = statusHarness();
    const issued = await issueWithStatus(statusClaim(IDX.revoked));

    const settled = await settle(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
      )
    );

    expect(settled.ok).toBe(false);
  });
});

// ------------------------------------------------- fail-closed transports

describe('#297 fail-closed — an endpoint that cannot answer refuses the login', () => {
  /**
   * Every case below is a REJECTION and there is intentionally no companion test
   * asserting a pass-through. `status-endpoint-breaker.ts`, verbatim: *"an open
   * circuit is an immediate REJECTION, the same one a failed fetch produces. It
   * makes the failure cheaper, never more permissive."*
   */
  async function expectRefusedWith(fetchImpl: StatusListFetch): Promise<unknown> {
    const { checker } = statusHarness(fetchImpl);
    const issued = await issueWithStatus(statusClaim(IDX.live));

    return refusalOf(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
      )
    );
  }

  it('REFUSES when the fetch times out', async () => {
    // The shipping transport, handed a `fetch` that aborts exactly as
    // `AbortSignal.timeout` makes it.
    const error = await expectRefusedWith(
      createHttpsStatusListFetch((async () => {
        throw Object.assign(new Error('The operation was aborted due to timeout'), {
          name: 'TimeoutError',
        });
      }) as unknown as typeof fetch)
    );

    expect(error).toBeInstanceOf(InvalidCredentialsError);
    expect((error as Error).message).toBe(CREDENTIAL_STATUS_REJECTION_MESSAGE);
  });

  it('REFUSES when the endpoint 500s', async () => {
    const error = await expectRefusedWith(
      createHttpsStatusListFetch((async () =>
        httpResponse(500, 'upstream on fire')) as unknown as typeof fetch)
    );

    expect(error).toBeInstanceOf(InvalidCredentialsError);
  });

  it('REFUSES when the endpoint serves the WRONG media type', async () => {
    // A captive portal, an auth redirect body or a JSON error object. Without
    // the content-type check these reach the JWS parser and every failure is
    // reported as "unverifiable token", hiding a misconfiguration behind a
    // security refusal — but either way it is a refusal, never a pass.
    const error = await expectRefusedWith(
      createHttpsStatusListFetch((async () =>
        httpResponse(200, statusListToken(), 'text/html')) as unknown as typeof fetch)
    );

    expect(error).toBeInstanceOf(InvalidCredentialsError);
  });

  it('REFUSES when the Status List Token will not verify against the anchors', async () => {
    // A token signed by a certificate that chains to nothing this deployment
    // anchored: a genuine-looking status answer from a party the operator never
    // trusted to give one.
    const stranger = createTestCertificate({
      subject: 'status.issuer.example',
      dnsNames: ['status.issuer.example'],
      ...validity,
    });
    const nowSeconds = Math.floor(Date.now() / 1000);

    const error = await expectRefusedWith(async () => ({
      outcome: 'ok',
      token: signStatusListToken({
        signer: stranger,
        header: { typ: STATUS_LIST_TOKEN_TYP, x5c: [stranger.x5c] },
        claims: {
          iss: STATUS_ISSUER,
          sub: STATUS_LIST_URI,
          iat: nowSeconds - 60,
          exp: nowSeconds + 3_600,
          status_list: { bits: 2, lst: encodeStatusList([0], 2) },
        },
      }),
    }));

    expect(error).toBeInstanceOf(InvalidCredentialsError);
  });

  it('REFUSES a status list URI outside the operator allowlist, without dialling it', async () => {
    // The SSRF boundary. The URI is attacker-authored; the allowlist decision
    // happens before any socket is opened, so the refusal comes with ZERO
    // outbound calls.
    const { checker, fetches } = statusHarness();
    const issued = await issueWithStatus(
      statusClaim(IDX.live, 'https://169-254-169-254.metadata.example/latest/meta-data/')
    );

    const error = await refusalOf(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
      )
    );

    expect(error).toBeInstanceOf(InvalidCredentialsError);
    expect(fetches).not.toHaveBeenCalled();
  });

  it('REFUSES while the circuit is OPEN, and stops dialling the dead endpoint', async () => {
    const { checker, fetches, audit } = statusHarness(
      createHttpsStatusListFetch((async () =>
        httpResponse(503, 'unavailable')) as unknown as typeof fetch),
      { realBreaker: true }
    );
    const issued = await issueWithStatus(statusClaim(IDX.live));
    const presentation = await present(issued);
    const context = fixtureValidationContext(issued, NONCE, { credentialStatus: checker });

    // Five consecutive failures trip the per-origin breaker.
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(await refusalOf(validate(presentation, context))).toBeInstanceOf(
        InvalidCredentialsError
      );
    }
    expect(fetches).toHaveBeenCalledTimes(5);

    // The sixth is refused WITHOUT a fetch — cheaper, and every bit as closed.
    const sixth = await refusalOf(validate(presentation, context));

    expect(sixth).toBeInstanceOf(InvalidCredentialsError);
    expect(fetches).toHaveBeenCalledTimes(5);
    expect(audit.at(-1)?.reason).toBe('circuit-open');
    expect(audit.at(-1)?.fetched).toBe(false);
    // And it is still indistinguishable from every other refusal on the wire.
    expect(refusalShape(sixth)).toEqual(refusalShape(issuerTrustRejection()));
  });

  it('REFUSES an index past the end of the published list', async () => {
    const { checker } = statusHarness();
    const issued = await issueWithStatus(statusClaim(9_999));

    expect(
      await refusalOf(
        validate(
          await present(issued),
          fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
        )
      )
    ).toBeInstanceOf(InvalidCredentialsError);
  });
});

// ------------------------------------------------------------- the posture

describe('#297 postures — VerifierProfile.requireCredentialStatus is finally read', () => {
  it('REFUSES a credential carrying NO status claim when the profile requires one', async () => {
    // HAIP §6.1. Before #378 this was the profile knob that no code consulted:
    // a `haip-1.0` operator declared revocation checking mandatory and got none.
    const { checker, fetches } = statusHarness();
    const issued = await issueWithStatus();

    const error = await refusalOf(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, {
          credentialStatus: checker,
          requireCredentialStatus: true,
        })
      )
    );

    expect(error).toBeInstanceOf(InvalidCredentialsError);
    expect(fetches).not.toHaveBeenCalled();
  });

  it('ACCEPTS a credential carrying no status claim when the profile requires none', async () => {
    // Base OID4VP 1.0 mandates no revocation mechanism, so there is nothing to
    // consult — and `'not-required'` records precisely that nobody looked.
    const { checker, fetches } = statusHarness();
    const issued = await issueWithStatus();

    const validated = await validate(
      await present(issued),
      fixtureValidationContext(issued, NONCE, {
        credentialStatus: checker,
        requireCredentialStatus: false,
      })
    );

    expect(validated.assurance.statusChecked).toBe('not-required');
    expect(fetches).not.toHaveBeenCalled();
  });

  it('still CHECKS a credential that carries a status claim under the lax posture', async () => {
    // `requireCredentialStatus: false` governs one question only — what to do
    // with a credential naming no mechanism at all. It does not switch the gate
    // off for credentials that DO carry one.
    const { checker, fetches } = statusHarness();
    const issued = await issueWithStatus(statusClaim(IDX.revoked));

    expect(
      await refusalOf(
        validate(
          await present(issued),
          fixtureValidationContext(issued, NONCE, {
            credentialStatus: checker,
            requireCredentialStatus: false,
          })
        )
      )
    ).toBeInstanceOf(InvalidCredentialsError);
    expect(fetches).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['a mechanism that is not status_list', { some_other_mechanism: { id: 1 } }],
    ['a status_list with a negative index', { status_list: { idx: -1, uri: STATUS_LIST_URI } }],
    ['a status_list with no uri', { status_list: { idx: 0 } }],
    ['a status_list with no idx', { status_list: { uri: STATUS_LIST_URI } }],
  ])(
    'REFUSES %s under BOTH postures (HAIP §6.1)',
    async (_label, claim: Record<string, unknown>) => {
      // A `status` claim that is present but unusable is never "no status": a
      // mechanism this verifier cannot evaluate is a status it has not
      // established, whatever the profile says about requiring one.
      for (const requireCredentialStatus of [true, false]) {
        const { checker, fetches } = statusHarness();
        const issued = await issueWithStatus(claim);

        expect(
          await refusalOf(
            validate(
              await present(issued),
              fixtureValidationContext(issued, NONCE, {
                credentialStatus: checker,
                requireCredentialStatus,
              })
            )
          )
        ).toBeInstanceOf(InvalidCredentialsError);
        expect(fetches).not.toHaveBeenCalled();
      }
    }
  );

  it('REFUSES when the profile mandates status and this deployment wired NO checker', async () => {
    // A mandate no code can satisfy must not resolve to "accepted". This is the
    // one status refusal raised by the adapter itself, so it IS a
    // `PresentationValidationRejection` — and its reason stays coarse.
    const issued = await issueWithStatus(statusClaim(IDX.live));

    const error = await refusalOf(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, { requireCredentialStatus: true })
      )
    );

    expect(isPresentationValidationRejection(error)).toBe(true);
    if (!isPresentationValidationRejection(error)) return;
    expect(error.reason).toBe('credential-status-unestablished');
    // Still the same thing on the wire.
    expect(refusalShape(error.toClientError())).toEqual(refusalShape(issuerTrustRejection()));
  });

  it('reports not-required, and fetches nothing, when no checker is wired and none is required', async () => {
    // The shipped `oid4vp-1.0-base` behaviour, unchanged by #378.
    const issued = await issueWithStatus(statusClaim(IDX.revoked));

    const validated = await validate(
      await present(issued),
      fixtureValidationContext(issued, NONCE)
    );

    expect(validated.assurance.statusChecked).toBe('not-required');
  });
});

// ------------------------------------------------------------- the ordering

describe('#297 ordering — nothing is dialled on behalf of an unverified credential', () => {
  /**
   * The SSRF property, asserted rather than argued.
   *
   * The status list URI is bytes the WALLET chose until the Issuer signature
   * covers them. A fetch issued before that signature verifies would hand any
   * caller an outbound request to a host of their choosing, and the operator's
   * allowlist is the only thing between that and the metadata service. So: for
   * every presentation that fails ANY earlier gate, the fetch count must be
   * exactly zero.
   */
  let harness: StatusHarness;

  beforeEach(() => {
    harness = statusHarness();
  });

  /** A context wired with the shared harness. */
  function contextFor(issued: IssuedSdJwtVc): PresentationValidationContext {
    return fixtureValidationContext(issued, NONCE, {
      credentialStatus: harness.checker,
      requireCredentialStatus: true,
    });
  }

  it('issues ZERO outbound calls when the ISSUER SIGNATURE does not verify', async () => {
    // The case that matters most: the `status` claim is present, well-formed and
    // points at an allowlisted URI — and the credential is signed by a key this
    // deployment did not resolve for that issuer. Nothing may be dialled.
    const issued = await issueWithStatus(statusClaim(IDX.live));
    const impostor = await issueWithStatus(statusClaim(IDX.live));

    // A real presentation, validated against the OTHER issuer's published key.
    const error = await refusalOf(validate(await present(impostor), contextFor(issued)));

    expect(isPresentationValidationRejection(error)).toBe(true);
    if (isPresentationValidationRejection(error)) {
      expect(error.reason).toBe('issuer-signature-invalid');
    }
    expect(harness.fetches).not.toHaveBeenCalled();
  });

  it('issues ZERO outbound calls when the issuer key cannot be resolved at all', async () => {
    const issued = await issueWithStatus(statusClaim(IDX.live), {
      issuer: 'https://unknown.issuer.example',
    });

    await refusalOf(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, {
          credentialStatus: harness.checker,
          requireCredentialStatus: true,
          resolveIssuerKey: async () => undefined,
        })
      )
    );

    expect(harness.fetches).not.toHaveBeenCalled();
  });

  it('issues ZERO outbound calls when the KEY BINDING JWT does not verify', async () => {
    // The gate the issue names alongside the signature: status runs strictly
    // after `verifyKeyBinding`, so a presentation nobody proved possession of
    // costs this deployment no outbound request either.
    const issued = await issueWithStatus(statusClaim(IDX.live));
    const stranger = await issueSdJwtVc();

    await refusalOf(
      validate(
        await presentSdJwtVc(issued, {
          nonce: NONCE,
          signingKeys: stranger.holderKeys.keyPair,
        }),
        contextFor(issued)
      )
    );

    expect(harness.fetches).not.toHaveBeenCalled();
  });

  it('issues ZERO outbound calls when the Key Binding JWT carries the wrong nonce', async () => {
    const issued = await issueWithStatus(statusClaim(IDX.live));

    await refusalOf(
      validate(
        await presentSdJwtVc(issued, { nonce: 'a-nonce-from-another-request' }),
        contextFor(issued)
      )
    );

    expect(harness.fetches).not.toHaveBeenCalled();
  });

  it('issues ZERO outbound calls for an EXPIRED credential', async () => {
    const issued = await issueWithStatus(statusClaim(IDX.live), {
      exp: Math.floor(Date.now() / 1000) - 7_200,
    });

    await refusalOf(validate(await present(issued), contextFor(issued)));

    expect(harness.fetches).not.toHaveBeenCalled();
  });

  it('issues ZERO outbound calls when `status` arrives through a DISCLOSURE', async () => {
    // SD-JWT VC §3.2.2.2 forbids it, and the refusal lands before the gate: a
    // selectively-disclosable status pointer is one the checker would otherwise
    // be handed by the holder rather than by the issuer.
    const issued = await issueSdJwtVc({
      selectiveClaims: { status: statusClaim(IDX.live) },
    });

    const error = await refusalOf(validate(await present(issued), contextFor(issued)));

    expect(isPresentationValidationRejection(error)).toBe(true);
    if (isPresentationValidationRejection(error)) {
      expect(error.reason).toBe('forbidden-selective-disclosure');
    }
    expect(harness.fetches).not.toHaveBeenCalled();
  });

  it('reads the status claim from the VERIFIED payload, not the disclosed one', async () => {
    // Both agree here by construction — a Disclosure of `status` is refused
    // outright — so this pins that the gate consumes the issuer-signed value and
    // nothing a holder can influence after the fact.
    const { checker, fetches } = statusHarness();
    const issued = await issueSdJwtVc({
      plainClaims: { status: statusClaim(IDX.live) },
      selectiveClaims: { given_name: 'Alice' },
    });

    const validated = await validate(
      await present(issued),
      fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
    );

    expect(validated.assurance.statusChecked).toBe('checked');
    expect((fetches.mock.calls[0]?.[0] as { uri: string }).uri).toBe(STATUS_LIST_URI);
    // `status` is not a claim a consumer receives; it is machinery this gate
    // consumed. It survives into `claims` only because it is not stripped —
    // asserted so a future change to the stripped set is a deliberate one.
    expect(validated.claims).toHaveProperty('status');
  });
});

// ---------------------------------------------------------------- the audit

describe('#297 audit — every check is countable, accepted ones included', () => {
  it('emits an audit event for an ACCEPTED check', async () => {
    // A revocation-rejection counter with no denominator cannot tell "we started
    // rejecting everything" from "traffic grew".
    const { checker, audit } = statusHarness();
    const issued = await issueWithStatus(statusClaim(IDX.live));

    await validate(
      await present(issued),
      fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
    );

    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      decision: 'accepted',
      statusListUri: STATUS_LIST_URI,
      idx: IDX.live,
      statusValue: 0,
      fetched: true,
      cacheHit: false,
    });
    expect(audit[0]?.reason).toBeUndefined();
    expect(typeof audit[0]?.durationMs).toBe('number');
    expect(typeof audit[0]?.spec).toBe('string');
  });

  it('emits an audit event naming the PRECISE reason for a refusal', async () => {
    // The fine-grained vocabulary the client never sees. This is the only place
    // an operator can tell a revoked credential from a dead endpoint.
    const { checker, audit } = statusHarness();
    const issued = await issueWithStatus(statusClaim(IDX.revoked));

    await refusalOf(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
      )
    );

    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      decision: 'rejected',
      reason: 'revoked',
      statusListUri: STATUS_LIST_URI,
      idx: IDX.revoked,
    });
  });

  it.each([
    ['a suspended bit', IDX.suspended, 'suspended'],
    ['an unrecognised bit', IDX.unknown, 'status-unknown'],
    ['an index past the end', 9_999, 'index-out-of-range'],
  ])('distinguishes %s server-side while the wire stays uniform', async (_label, idx, reason) => {
    const { checker, audit } = statusHarness();
    const issued = await issueWithStatus(statusClaim(idx));

    const error = await refusalOf(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
      )
    );

    expect(audit.at(-1)?.reason).toBe(reason);
    expect(refusalShape(error)).toEqual(refusalShape(issuerTrustRejection()));
  });

  it('emits an event for a check that never left the process', async () => {
    // `status-required-but-absent`: no URI, no fetch, and still counted — the
    // denominator has to include the checks that cost nothing.
    const { checker, audit } = statusHarness();
    const issued = await issueWithStatus();

    await refusalOf(
      validate(
        await present(issued),
        fixtureValidationContext(issued, NONCE, {
          credentialStatus: checker,
          requireCredentialStatus: true,
        })
      )
    );

    expect(audit).toEqual([
      expect.objectContaining({
        decision: 'rejected',
        reason: 'status-required-but-absent',
        fetched: false,
        cacheHit: false,
      }),
    ]);
    expect(audit[0]).not.toHaveProperty('statusListUri');
  });

  it('survives an audit sink that throws, without converting a 401 into a 500', async () => {
    const checker = createCredentialStatusChecker({
      trustAnchors: anchors,
      uriAllowlist,
      fetch: async () => ({ outcome: 'ok', token: statusListToken() }),
      onAudit: () => {
        throw new Error('the log pipeline is down');
      },
    });
    const issued = await issueWithStatus(statusClaim(IDX.live));

    const validated = await validate(
      await present(issued),
      fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
    );

    expect(validated.assurance.statusChecked).toBe('checked');
  });
});

// -------------------------------------------------- the instance owns the state

describe('#297 the checker INSTANCE owns cache and coalescing — not the call site', () => {
  it('serves a second validation of the same list from cache, with no second fetch', async () => {
    // Why the checker is constructed once at bootstrap rather than per request.
    // A per-request checker has a cold cache, a breaker that can never reach its
    // threshold, and turns every login into an outbound round-trip.
    const { checker, fetches, audit } = statusHarness();
    const first = await issueWithStatus(statusClaim(IDX.live));
    const second = await issueWithStatus(statusClaim(IDX.live));

    await validate(
      await present(first),
      fixtureValidationContext(first, NONCE, { credentialStatus: checker })
    );
    await validate(
      await present(second),
      fixtureValidationContext(second, NONCE, { credentialStatus: checker })
    );

    expect(fetches).toHaveBeenCalledTimes(1);
    expect(audit.map((event) => event.cacheHit)).toEqual([false, true]);
  });

  it('coalesces concurrent validations of the same list into ONE fetch', async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const { checker, fetches } = statusHarness(async () => {
      await gate;
      return { outcome: 'ok', token: statusListToken() };
    });

    const credentials = await Promise.all([
      issueWithStatus(statusClaim(IDX.live)),
      issueWithStatus(statusClaim(IDX.live)),
      issueWithStatus(statusClaim(IDX.live)),
    ]);

    const validations = Promise.all(
      credentials.map(async (issued) =>
        validate(
          await present(issued),
          fixtureValidationContext(issued, NONCE, { credentialStatus: checker })
        )
      )
    );

    // Let all three reach the gate before the single flight resolves.
    await new Promise((resolve) => setImmediate(resolve));
    release?.();

    const validated = await validations;

    expect(validated.map((credential) => credential.assurance.statusChecked)).toEqual([
      'checked',
      'checked',
      'checked',
    ]);
    expect(fetches).toHaveBeenCalledTimes(1);
  });

  it('does NOT serve a STALE list once the cached entry has aged out', async () => {
    // The fallback that must never exist, on the SAME URI whose entry expired —
    // "we had a good answer five minutes ago" is exactly the reasoning that lets
    // an attacker who can degrade a third party's availability un-revoke
    // credentials. The token pins `ttl: 300`, so 301 s later the entry is gone
    // and a failing endpoint is a refusal rather than a licence to reuse it.
    let healthy = true;
    const { checker, fetches, advance } = statusHarness(async () =>
      healthy ? { outcome: 'ok', token: statusListToken() } : { outcome: 'failed' }
    );

    const live = await issueWithStatus(statusClaim(IDX.live));
    const presentation = await present(live);
    const context = fixtureValidationContext(live, NONCE, { credentialStatus: checker });

    expect((await validate(presentation, context)).assurance.statusChecked).toBe('checked');
    // Still warm: the second check costs no request at all.
    expect((await validate(presentation, context)).assurance.statusChecked).toBe('checked');
    expect(fetches).toHaveBeenCalledTimes(1);

    advance(301_000);
    healthy = false;

    expect(await refusalOf(validate(presentation, context))).toBeInstanceOf(
      InvalidCredentialsError
    );
    // It re-fetched rather than reusing — the refusal is the endpoint's answer.
    expect(fetches).toHaveBeenCalledTimes(2);
  });

  it('does not let one list URI answer for another', async () => {
    // The cache is keyed on the URI, and a warm entry must not be handed to a
    // credential pointing somewhere else — that would make one issuer's status
    // list authoritative for another's credentials.
    let healthy = true;
    const { checker } = statusHarness(async () =>
      healthy ? { outcome: 'ok', token: statusListToken() } : { outcome: 'failed' }
    );

    const live = await issueWithStatus(statusClaim(IDX.live));
    await validate(
      await present(live),
      fixtureValidationContext(live, NONCE, { credentialStatus: checker })
    );

    healthy = false;
    const other = await issueWithStatus(
      statusClaim(IDX.live, 'https://status.issuer.example/lists/2')
    );

    expect(
      await refusalOf(
        validate(
          await present(other),
          fixtureValidationContext(other, NONCE, { credentialStatus: checker })
        )
      )
    ).toBeInstanceOf(InvalidCredentialsError);
  });
});

// ------------------------------------------------------ the call site exists

describe('#378 — the checker has a production call site', () => {
  it('is invoked from the shipped validation path, not only from its own tests', () => {
    // The regression #378 IS. Every unit test in `status/` passed while
    // `git grep` over `libs/**` and `apps/**` found no production caller at all,
    // so the acceptance criterion has to be asserted against the source: a
    // future refactor that quietly drops the call must fail here rather than in
    // production.
    const adapter = readFileSync(path.join(__dirname, 'sd-jwt-vc.ts'), 'utf8');
    // Strip block comments: a JSDoc mention is exactly how #297 looked wired
    // when it was not.
    const code = adapter.replace(/\/\*[\s\S]*?\*\//g, '');

    expect(
      /assertCredentialNotRevoked\(/.test(code),
      'sd-jwt-vc.ts no longer calls CredentialStatusChecker.assertCredentialNotRevoked. Issue #378 is precisely the state where the checker exists, is tested, and nothing calls it.'
    ).toBe(true);
    expect(/context\.credentialStatus/.test(code)).toBe(true);
  });
});
