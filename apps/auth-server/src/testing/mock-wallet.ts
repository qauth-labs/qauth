import { createHash, randomBytes } from 'node:crypto';

import {
  exportPublicSigningJwk,
  generateSigningKeyPair,
  type JwsAlgorithm,
  type SigningKeyPair,
} from '@qauth-labs/core-crypto';
import { CompactSign, type JWK } from 'jose';

/**
 * A REFERENCE / MOCK WALLET (issue #240, OID4VP 1.0, ADR-004).
 *
 * The counterparty QAuth's E2E suite talks to: it parses an OID4VP 1.0
 * Authorization Request off a wallet invocation URI, evaluates the request's
 * DCQL query against the credentials it holds, builds a `vp_token`, and POSTs it
 * to the `response_uri` with `response_mode=direct_post`.
 *
 * ## Why it lives here and not in `libs/server/federation/testing/`
 *
 * That directory holds the VERIFIER's attack harness (`sd-jwt-vc.fixture.ts`):
 * a credential minter built to produce credentials that are correct in every
 * respect but one, so each rejection path can be provoked in isolation. Its own
 * `test-support-boundary.test.ts` pins it inside that library and forbids
 * anything reaching it — including this suite, since `apps/auth-server` is
 * `scope:app` and the workspace's module boundaries forbid it from importing
 * `scope:server` libraries at all.
 *
 * That separation is worth keeping rather than working around. A wallet is not
 * part of the verifier: it holds keys the verifier never sees, it decides what to
 * disclose, and it speaks to QAuth only over HTTP. Building it out of
 * `@qauth-labs/core-crypto` and `jose` — with no import of the code under test —
 * is what makes the E2E an INTEROPERABILITY test rather than a round trip
 * through QAuth's own encoder.
 *
 * The two are cross-checked where it counts: every presentation this module
 * produces is validated by the shipping `#234` validator inside the running app,
 * so a divergence between the wallet's encoding and the verifier's expectations
 * fails the E2E rather than hiding in a shared helper.
 *
 * ## The format seam
 *
 * {@link WALLET_PRESENTATION_BUILDERS} is a table keyed by DCQL credential
 * format, exactly as the verifier's `CREDENTIAL_FORMAT_ADAPTERS` is. `dc+sd-jwt`
 * ships; `mso_mdoc` is deliberately ABSENT and a request for it is REFUSED
 * rather than answered by the SD-JWT path. Adding an mdoc wallet later is a new
 * table entry plus a credential the wallet holds — not a rewrite of the suite.
 *
 * ## What it is not
 *
 * Not a conformance target, and not a claim that any real wallet behaves this
 * way. HAIP 1.0 interoperability against a real wallet is an open research
 * question — see `docs/wallet-interop-manual-validation.md`.
 */

/** DCQL credential format this wallet can answer for (OID4VP 1.0 §6). */
export const MOCK_WALLET_SD_JWT_VC_FORMAT = 'dc+sd-jwt';

/** SD-JWT VC issuer-signed JWT `typ` (SD-JWT VC §3.2.1). */
const SD_JWT_VC_TYP = 'dc+sd-jwt';

/** Key Binding JWT `typ` (SD-JWT §4.3). */
const KEY_BINDING_JWT_TYP = 'kb+jwt';

/** An OID4VP 1.0 Authorization Request, as a wallet reads it off the wire. */
export interface Oid4vpRequestView {
  readonly clientId: string;
  readonly responseType: string;
  readonly responseMode: string;
  readonly responseUri: string;
  readonly nonce: string;
  readonly state: string;
  readonly dcqlQuery: DcqlQueryView;
  readonly clientMetadata: Record<string, unknown>;
}

/** The subset of DCQL a wallet has to understand to answer a query. */
export interface DcqlQueryView {
  readonly credentials: readonly DcqlCredentialQueryView[];
}

/** One DCQL Credential Query (OID4VP 1.0 §6.1). */
export interface DcqlCredentialQueryView {
  readonly id: string;
  readonly format: string;
  readonly meta?: { readonly vct_values?: readonly string[] };
}

/** A key pair plus the public JWK its issuer would publish. */
export interface MockWalletKeys {
  readonly keyPair: SigningKeyPair;
  readonly jwk: JWK;
}

/** A credential the mock wallet holds, as issued to it. */
export interface HeldCredential {
  /** DCQL `format` this credential can answer for. */
  readonly format: string;
  /** The credential type (`vct`) a DCQL query matches on. */
  readonly credentialType: string;
  /** The issuer identifier the credential is signed under. */
  readonly issuer: string;
  /** The issuer-signed JWT. */
  readonly issuerSignedJwt: string;
  /** Every Disclosure the issuer produced. */
  readonly disclosures: readonly string[];
  /** The holder key the credential is bound to (`cnf.jwk`). */
  readonly holderKeys: MockWalletKeys;
  /** Node hash identifier matching the credential's `_sd_alg`. */
  readonly hashAlgorithm: string;
}

/** An issuer the mock wallet received credentials from. */
export interface MockCredentialIssuer {
  /** Issuer identifier (`iss`), an https URL. */
  readonly identifier: string;
  /** Public JWK a verifier is configured with (`OID4VP_ISSUER_JWKS`). */
  readonly jwk: JWK;
  /** Issue a credential from this issuer into the wallet. */
  issue(options?: IssueCredentialOptions): Promise<HeldCredential>;
}

/** What {@link MockCredentialIssuer.issue} may vary. */
export interface IssueCredentialOptions {
  /** Credential type. Defaults to {@link DEFAULT_VCT}. */
  readonly credentialType?: string;
  /** Selectively disclosable claims — one Disclosure and `_sd` digest each. */
  readonly claims?: Record<string, unknown>;
  /** `exp`, epoch seconds. Omitted when absent. */
  readonly expiresAt?: number;
  /** `nbf`, epoch seconds. Omitted when absent. */
  readonly notBefore?: number;
  /** Reuse an existing holder key — e.g. a re-issued credential for one device. */
  readonly holderKeys?: MockWalletKeys;
}

/** The `vct` the mock issuer signs unless told otherwise. */
export const DEFAULT_VCT = 'https://credentials.example.com/pid';

/** Signature algorithm the mock ecosystem uses end to end (HAIP §7's floor). */
const ALGORITHM: JwsAlgorithm = 'ES256';

/** Generate a signing key pair and export its public JWK. */
export async function generateWalletKeys(kid?: string): Promise<MockWalletKeys> {
  const keyPair = await generateSigningKeyPair(ALGORITHM, { extractable: true });
  const jwk = await exportPublicSigningJwk(keyPair.publicKey, {
    alg: ALGORITHM,
    ...(kid === undefined ? {} : { kid }),
  });
  return { keyPair, jwk };
}

/** Sign a compact JWS over an arbitrary payload. */
async function signCompactJws(
  payload: Record<string, unknown>,
  keyPair: SigningKeyPair,
  header: Record<string, unknown>
): Promise<string> {
  return new CompactSign(Buffer.from(JSON.stringify(payload), 'utf8'))
    .setProtectedHeader({ ...header, alg: ALGORITHM } as never)
    .sign(keyPair.privateKey);
}

/** Encode a Disclosure exactly as SD-JWT §4.2 specifies. */
function encodeDisclosure(parts: readonly unknown[]): string {
  return Buffer.from(JSON.stringify(parts), 'utf8').toString('base64url');
}

/** Digest an encoded Disclosure. */
function digestDisclosure(encoded: string, hashAlgorithm: string): string {
  return createHash(hashAlgorithm).update(encoded, 'ascii').digest('base64url');
}

/**
 * Create a credential ISSUER — a party the verifier may or may not trust.
 *
 * Separate from the wallet on purpose: #236's whole point is that a validly
 * signed credential from an unlisted issuer must be refused, and that test is
 * only meaningful if the untrusted issuer is a real, independently-keyed issuer
 * whose signature verifies.
 *
 * @param identifier - the `iss` value, an https URL.
 * @param kid - optional key id, stamped in the issuer JWS header and the JWK.
 */
export async function createMockIssuer(
  identifier: string,
  kid?: string
): Promise<MockCredentialIssuer> {
  const issuerKeys = await generateWalletKeys(kid);

  return {
    identifier,
    jwk: issuerKeys.jwk,

    async issue(options: IssueCredentialOptions = {}): Promise<HeldCredential> {
      const hashAlgorithm = 'sha256';
      const holderKeys = options.holderKeys ?? (await generateWalletKeys());
      const credentialType = options.credentialType ?? DEFAULT_VCT;
      const claims = options.claims ?? { given_name: 'Alice', family_name: 'Doe' };

      const disclosures: string[] = [];
      const digests: string[] = [];

      for (const [name, value] of Object.entries(claims)) {
        const encoded = encodeDisclosure([randomBytes(16).toString('base64url'), name, value]);
        disclosures.push(encoded);
        digests.push(digestDisclosure(encoded, hashAlgorithm));
      }

      const issuerSignedJwt = await signCompactJws(
        {
          iss: identifier,
          vct: credentialType,
          iat: Math.floor(Date.now() / 1000),
          ...(options.notBefore === undefined ? {} : { nbf: options.notBefore }),
          ...(options.expiresAt === undefined ? {} : { exp: options.expiresAt }),
          _sd_alg: 'sha-256',
          _sd: digests,
          cnf: { jwk: holderKeys.jwk },
        },
        issuerKeys.keyPair,
        { typ: SD_JWT_VC_TYP, ...(kid === undefined ? {} : { kid }) }
      );

      return {
        format: MOCK_WALLET_SD_JWT_VC_FORMAT,
        credentialType,
        issuer: identifier,
        issuerSignedJwt,
        disclosures,
        holderKeys,
        hashAlgorithm,
      };
    },
  };
}

/**
 * Build one presentation of a held credential, bound to a request.
 *
 * The per-format seam. One entry per DCQL credential format; a format with no
 * entry is refused by {@link presentCredential} rather than served by another
 * format's builder.
 */
export type WalletPresentationBuilder = (
  credential: HeldCredential,
  binding: { readonly nonce: string; readonly audience: string }
) => Promise<string>;

/** SD-JWT VC presentation with a Key Binding JWT (SD-JWT §4.3, HAIP §5). */
const buildSdJwtVcPresentation: WalletPresentationBuilder = async (credential, binding) => {
  const prefix = [credential.issuerSignedJwt, ...credential.disclosures, ''].join('~');
  const sdHash = createHash(credential.hashAlgorithm).update(prefix, 'ascii').digest('base64url');

  const keyBindingJwt = await signCompactJws(
    {
      iat: Math.floor(Date.now() / 1000),
      aud: binding.audience,
      nonce: binding.nonce,
      sd_hash: sdHash,
    },
    credential.holderKeys.keyPair,
    { typ: KEY_BINDING_JWT_TYP }
  );

  return `${prefix}${keyBindingJwt}`;
};

/**
 * Formats this wallet can present, keyed by DCQL `format`.
 *
 * `mso_mdoc` is deliberately absent. OID4VP 1.0 and HAIP §5 both sanction it,
 * and QAuth tracks it as a fast-follow — but a wallet that answered an mdoc query
 * with an SD-JWT VC would make the suite pass for a credential the verifier can
 * never receive in production. Absence is the honest state, and
 * {@link presentCredential} refuses rather than falling through.
 */
export const WALLET_PRESENTATION_BUILDERS: Readonly<Record<string, WalletPresentationBuilder>> =
  Object.freeze({
    [MOCK_WALLET_SD_JWT_VC_FORMAT]: buildSdJwtVcPresentation,
  });

/**
 * Present a held credential in its own format.
 *
 * @throws Error when no builder is registered for the credential's format.
 */
export async function presentCredential(
  credential: HeldCredential,
  binding: { readonly nonce: string; readonly audience: string }
): Promise<string> {
  const build = WALLET_PRESENTATION_BUILDERS[credential.format];
  if (build === undefined) {
    throw new Error(
      `mock wallet holds no presentation builder for format '${credential.format}'. ` +
        'Register one in WALLET_PRESENTATION_BUILDERS rather than answering with another format.'
    );
  }
  return build(credential, binding);
}

/**
 * Parse an OID4VP 1.0 Authorization Request out of a wallet invocation URI.
 *
 * A wallet reads the request off the wire; it does not receive QAuth's internal
 * object. Parsing it here is what makes the E2E exercise
 * `encodeOid4vpRequestUri` for real, and what would catch a parameter QAuth
 * stopped sending.
 *
 * @throws Error when a REQUIRED parameter is missing — a wallet that guessed a
 * default would hide exactly the regression this is here to catch.
 */
export function parseOid4vpRequest(invocationUri: string): Oid4vpRequestView {
  const query = invocationUri.slice(invocationUri.indexOf('?') + 1);
  const params = new URLSearchParams(query);

  const required = (name: string): string => {
    const value = params.get(name);
    if (value === null || value === '') {
      throw new Error(`OID4VP authorization request is missing required parameter '${name}'`);
    }
    return value;
  };

  const dcqlQuery = JSON.parse(required('dcql_query')) as DcqlQueryView;
  const rawMetadata = params.get('client_metadata');

  return {
    clientId: required('client_id'),
    responseType: required('response_type'),
    responseMode: required('response_mode'),
    responseUri: required('response_uri'),
    nonce: required('nonce'),
    state: required('state'),
    dcqlQuery,
    clientMetadata:
      rawMetadata === null ? {} : (JSON.parse(rawMetadata) as Record<string, unknown>),
  };
}

/**
 * A `vp_token` (OID4VP 1.0 §8.1).
 *
 * Keyed by DCQL Credential Query id, and each value is an ARRAY of
 * presentations — even for a query with `multiple` unset, where the array holds
 * exactly one. The final spec made this uniform; a bare string is a draft-era
 * shape the Verifier refuses.
 */
export type VpToken = Record<string, readonly string[]>;

/** What {@link MockWallet.buildResponse} produced. */
export interface WalletAuthorizationResponse {
  /** The parsed request this answers. */
  readonly request: Oid4vpRequestView;
  /** Form body to POST to `response_uri`. */
  readonly formBody: Record<string, string>;
  /** The `vp_token` object, before serialization — for assertions. */
  readonly vpToken: VpToken;
}

/** A wallet holding credentials, able to answer presentation requests. */
export interface MockWallet {
  /** Put a credential in the wallet. */
  hold(credential: HeldCredential): void;
  /** Every credential currently held. */
  readonly credentials: readonly HeldCredential[];
  /**
   * Answer an invocation URI: parse it, satisfy every Credential Query, and
   * return the form body a `direct_post` response carries.
   */
  buildResponse(invocationUri: string): Promise<WalletAuthorizationResponse>;
  /** Answer with an OAuth-style error instead of a `vp_token` (§8.2). */
  buildErrorResponse(invocationUri: string, error?: string): WalletAuthorizationErrorResponse;
}

/** A wallet-reported failure, as `direct_post` accepts it. */
export interface WalletAuthorizationErrorResponse {
  readonly request: Oid4vpRequestView;
  readonly formBody: Record<string, string>;
}

/**
 * Select the credential that satisfies one DCQL Credential Query.
 *
 * Matching is on `format` AND `meta.vct_values`, both of which the verifier
 * re-checks — a wallet that ignored `vct_values` would produce a presentation
 * QAuth refuses, so the E2E would fail with `vct` mismatch instead of proving
 * the flow.
 */
function selectForQuery(
  held: readonly HeldCredential[],
  query: DcqlCredentialQueryView
): HeldCredential | undefined {
  const wanted = query.meta?.vct_values;
  return held.find(
    (credential) =>
      credential.format === query.format &&
      (wanted === undefined || wanted.includes(credential.credentialType))
  );
}

/**
 * Create a mock wallet.
 *
 * @param credentials - credentials to hold from the start.
 */
export function createMockWallet(credentials: readonly HeldCredential[] = []): MockWallet {
  const held: HeldCredential[] = [...credentials];

  return {
    hold(credential: HeldCredential): void {
      held.push(credential);
    },

    get credentials(): readonly HeldCredential[] {
      return held;
    },

    async buildResponse(invocationUri: string): Promise<WalletAuthorizationResponse> {
      const request = parseOid4vpRequest(invocationUri);
      const vpToken: Record<string, string[]> = {};

      for (const query of request.dcqlQuery.credentials) {
        const credential = selectForQuery(held, query);
        if (credential === undefined) {
          throw new Error(
            `mock wallet holds no credential for DCQL query '${query.id}' ` +
              `(format '${query.format}', vct ${JSON.stringify(query.meta?.vct_values ?? [])})`
          );
        }

        // The `aud` of the Key Binding JWT is the request's `client_id`
        // VERBATIM — including its Client Identifier Prefix. OID4VP 1.0 §5.9
        // makes the prefixed form the Verifier's identity, and a wallet that
        // stripped it would produce a binding QAuth refuses.
        vpToken[query.id] = [
          await presentCredential(credential, {
            nonce: request.nonce,
            audience: request.clientId,
          }),
        ];
      }

      return {
        request,
        vpToken,
        formBody: { state: request.state, vp_token: JSON.stringify(vpToken) },
      };
    },

    buildErrorResponse(
      invocationUri: string,
      error = 'access_denied'
    ): WalletAuthorizationErrorResponse {
      const request = parseOid4vpRequest(invocationUri);
      return { request, formBody: { state: request.state, error } };
    },
  };
}

/**
 * The `OID4VP_ISSUER_JWKS` value a deployment needs to verify these issuers.
 *
 * Built from the issuers rather than written out, so a test cannot configure a
 * key that does not match the one the credential was signed with — which would
 * make every presentation fail for an uninteresting reason.
 */
export function issuerJwksConfig(issuers: readonly MockCredentialIssuer[]): string {
  const map: Record<string, JWK[]> = {};
  for (const issuer of issuers) map[issuer.identifier] = [issuer.jwk];
  return JSON.stringify(map);
}
