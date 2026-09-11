import { createHash, randomBytes, X509Certificate } from 'node:crypto';

import {
  exportPublicSigningJwk,
  generateSigningKeyPair,
  type JwsAlgorithm,
  type SigningKeyPair,
} from '@qauth-labs/core-crypto';
import { CompactEncrypt, CompactSign, compactVerify, importJWK, importSPKI, type JWK } from 'jose';

/**
 * A REFERENCE / MOCK WALLET (issue #240, OID4VP 1.0, ADR-004).
 *
 * The counterparty QAuth's E2E suite talks to: it parses an OID4VP 1.0
 * Authorization Request off a wallet invocation URI (or out of a verified JAR),
 * evaluates the request's DCQL query against the credentials it holds, builds a
 * `vp_token`, and POSTs it to the `response_uri` — in the clear under
 * `response_mode=direct_post`, or encrypted to the Verifier's per-request key
 * under `direct_post.jwt`.
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
 * ## The signed-request seam (#377)
 *
 * Under a profile that mandates signed requests the wallet receives a
 * `request_uri` reference, fetches a JAR, and has to decide whether to believe
 * it. {@link verifyOid4vpRequestObject} is that decision, and it is written HERE
 * rather than delegated for the same reason as everything else in this file: it
 * must not be the verifier's own chain reader. The anchor it validates against
 * is passed in from a trust list the wallet holds OUT OF BAND — never read from
 * the request — which is the property the whole exercise is about.
 *
 * ## The encrypted-response seam (#377 Phase C)
 *
 * Under `response_mode=direct_post.jwt` (OID4VP 1.0 §8.3, HAIP §5.1) the wallet
 * does not post its parameters in the clear: it reads the Verifier's
 * per-request encryption key out of `client_metadata.jwks`, encrypts the whole
 * Authorization Response to it as a compact JWE, and posts ONE `response`
 * parameter. {@link encryptAuthorizationResponse} is that step, written against
 * `jose` directly for the reason everything else here is — a wallet that
 * encrypted with the verifier's own helper would prove nothing about whether
 * the verifier can open what a conformant peer sends. The `kid` the Verifier
 * published is echoed in the JWE protected header (§8.3), which is the only
 * thing the Verifier has to find its key with.
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
  /**
   * The `status` claim (Token Status List, HAIP §6.1, #297) — build it with
   * `MockStatusList.statusClaimFor(idx)`.
   *
   * Signed in the CLEAR and never made selectively disclosable, because
   * SD-JWT VC §3.2.2.2 forbids it: a status pointer a holder could withhold is
   * one the verifier's status checker never sees, and QAuth refuses such a
   * credential outright. Omitted entirely when absent, which is a credential
   * naming no revocation mechanism — permitted by base OID4VP 1.0 and refused
   * under a profile whose `requireCredentialStatus` is `true`.
   */
  readonly status?: Record<string, unknown>;
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
          ...(options.status === undefined ? {} : { status: options.status }),
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
  /**
   * Form body to POST to `response_uri`.
   *
   * Under `direct_post` this is `state` + `vp_token` in the clear; under
   * `direct_post.jwt` it is the single `response` parameter carrying the JWE
   * (#377 Phase C). Which one is decided by the REQUEST's `response_mode`, as
   * a wallet decides it, so a suite posts whatever this is without knowing.
   */
  readonly formBody: Record<string, string>;
  /** The `vp_token` object, before serialization — for assertions. */
  readonly vpToken: VpToken;
}

/** The OID4VP Response Mode that carries a JWE (§8.3). */
const DIRECT_POST_JWT = 'direct_post.jwt';

/** The `enc` a wallet falls back to when the Verifier advertised none (HAIP §5). */
const DEFAULT_ENC = 'A128GCM';

/** The `enc` HAIP §5 has a wallet PREFER when the Verifier supports it. */
const PREFERRED_ENC = 'A256GCM';

/**
 * Select the Verifier's encryption key out of `client_metadata` (§5.1).
 *
 * A wallet picks a key with `use: 'enc'` (or no `use`) from the published
 * `jwks`, and refuses to encrypt to nothing — a request that asks for
 * `direct_post.jwt` and publishes no key is unanswerable, and a wallet that
 * fell back to posting plaintext would be the downgrade the mode exists to
 * prevent. Every key QAuth publishes MUST carry a `kid` (§5.1), and it is
 * required here so a Verifier that stopped stamping one fails the E2E rather
 * than getting a JWE it cannot correlate.
 *
 * @throws Error when no usable key is published.
 */
export function selectResponseEncryptionKey(clientMetadata: Record<string, unknown>): JWK {
  const jwks = clientMetadata['jwks'] as { keys?: unknown } | undefined;
  const keys = Array.isArray(jwks?.keys) ? (jwks.keys as JWK[]) : [];
  const key = keys.find((candidate) => candidate.use === undefined || candidate.use === 'enc');

  if (key === undefined) {
    throw new Error(
      'the request asks for an encrypted response but client_metadata publishes no encryption key'
    );
  }
  if (typeof key.kid !== 'string' || key.kid === '') {
    throw new Error("the Verifier's encryption key carries no kid (OID4VP 1.0 §5.1)");
  }
  return key;
}

/**
 * Choose the content-encryption algorithm from what the Verifier advertised.
 *
 * `encrypted_response_enc_values_supported` (§5.1) lists what the Verifier
 * will open. HAIP 1.0 §5: "If both are supported, the Wallet SHOULD use
 * A256GCM for the JWE enc." — so `A256GCM` is taken whenever it is advertised,
 * wherever in the list it sits; otherwise the first advertised value; absent
 * any list, the `A128GCM` floor §5 fixes. Taking `advertised[0]` would have
 * had the E2E post an `enc` a real HAIP wallet never produces against a
 * Verifier that lists both.
 */
function selectResponseEnc(clientMetadata: Record<string, unknown>): string {
  const advertised = clientMetadata['encrypted_response_enc_values_supported'];
  if (!Array.isArray(advertised)) return DEFAULT_ENC;
  if (advertised.includes(PREFERRED_ENC)) return PREFERRED_ENC;
  if (typeof advertised[0] === 'string') return advertised[0];
  return DEFAULT_ENC;
}

/** What {@link encryptAuthorizationResponse} may vary, for the refusal tests. */
export interface EncryptResponseOptions {
  /** Override the `kid` echoed in the JWE header. Defaults to the key's own. */
  readonly kid?: string;
  /** Override the recipient key — e.g. one the Verifier never published. */
  readonly recipient?: JWK;
}

/**
 * Encrypt an Authorization Response as a wallet does under `direct_post.jwt`
 * (OID4VP 1.0 §8.3; HAIP §5).
 *
 * The parameters — `state`, and `vp_token` as a JSON OBJECT, or `error` — are
 * the JWE payload. `alg` is `ECDH-ES` (HAIP §5), `enc` is whatever the Verifier
 * advertised, and the protected header carries the `kid` of the key selected
 * from `client_metadata`, which is how the Verifier finds the private half
 * without decrypting anything.
 *
 * Written against `jose` directly — no import of QAuth's JWE helper — so the
 * ciphertext is what an independent implementation produces.
 */
export async function encryptAuthorizationResponse(
  request: Oid4vpRequestView,
  parameters: Record<string, unknown>,
  options: EncryptResponseOptions = {}
): Promise<string> {
  const recipient = options.recipient ?? selectResponseEncryptionKey(request.clientMetadata);
  const enc = selectResponseEnc(request.clientMetadata);
  const kid = options.kid ?? (recipient.kid as string);

  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(parameters)))
    .setProtectedHeader({ alg: 'ECDH-ES', enc, kid } as never)
    .encrypt(await importJWK(recipient, 'ECDH-ES'));
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
  /**
   * Answer a request the wallet already read — the signed path, where the
   * parameters came out of a verified request object rather than off the URI
   * (#377). {@link MockWallet.buildResponse} is this, plus the parse.
   */
  buildResponseForRequest(request: Oid4vpRequestView): Promise<WalletAuthorizationResponse>;
  /**
   * Answer with an OAuth-style error instead of a `vp_token` (§8.2).
   *
   * Asynchronous since #377 Phase C: under `direct_post.jwt` the error travels
   * inside the JWE like every other parameter, so refusing is an encryption.
   */
  buildErrorResponse(
    invocationUri: string,
    error?: string
  ): Promise<WalletAuthorizationErrorResponse>;
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
      return this.buildResponseForRequest(parseOid4vpRequest(invocationUri));
    },

    async buildResponseForRequest(
      request: Oid4vpRequestView
    ): Promise<WalletAuthorizationResponse> {
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

      // The wire shape follows the REQUEST's Response Mode, as it would for a
      // real wallet (#377 Phase C): an encrypted mode gets one `response`
      // parameter carrying the JWE, with `vp_token` as an OBJECT inside it
      // (§8.3 — the payload is JSON, so there is nothing to string-encode);
      // the plain mode gets the form parameters it always got.
      if (request.responseMode === DIRECT_POST_JWT) {
        return {
          request,
          vpToken,
          formBody: {
            response: await encryptAuthorizationResponse(request, {
              state: request.state,
              vp_token: vpToken,
            }),
          },
        };
      }

      return {
        request,
        vpToken,
        formBody: { state: request.state, vp_token: JSON.stringify(vpToken) },
      };
    },

    async buildErrorResponse(
      invocationUri: string,
      error = 'access_denied'
    ): Promise<WalletAuthorizationErrorResponse> {
      const request = parseOid4vpRequest(invocationUri);

      if (request.responseMode === DIRECT_POST_JWT) {
        return {
          request,
          formBody: {
            response: await encryptAuthorizationResponse(request, { state: request.state, error }),
          },
        };
      }

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

/** The `typ` a wallet requires on a JAR request object (RFC 9101 §10.8). */
const REQUEST_OBJECT_TYP = 'oauth-authz-req+jwt';

/** OID4VP 1.0 §5.9.3 — the prefix HAIP mandates for a signed request. */
const X509_HASH_PREFIX = 'x509_hash:';

/** A `request_uri` invocation, as a wallet reads it off the wire (#377). */
export interface Oid4vpRequestReference {
  /** `client_id`, which RFC 9101 §5.2.2 keeps OUTSIDE the request object. */
  readonly clientId: string;
  /** Absolute URI the request object is fetched from. */
  readonly requestUri: string;
}

/**
 * Parse a `request_uri`-form wallet invocation URI (#377).
 *
 * A wallet that received this form must NOT find the request parameters here:
 * they live inside the signed object, and a second unsigned copy on the wire
 * would be a value an attacker could steer. So this refuses an invocation that
 * carries `dcql_query` — the shape a downgrade to the query form would take.
 *
 * @throws Error when a required parameter is missing or the unsigned parameters
 * are present alongside the reference.
 */
export function parseOid4vpRequestReference(invocationUri: string): Oid4vpRequestReference {
  const params = new URLSearchParams(invocationUri.slice(invocationUri.indexOf('?') + 1));

  const clientId = params.get('client_id');
  const requestUri = params.get('request_uri');

  if (clientId === null || clientId === '') {
    throw new Error("a request_uri invocation is missing required parameter 'client_id'");
  }
  if (requestUri === null || requestUri === '') {
    throw new Error("a request_uri invocation is missing required parameter 'request_uri'");
  }
  if (params.has('dcql_query') || params.has('client_metadata')) {
    throw new Error(
      'a request_uri invocation must not also carry the unsigned request parameters — ' +
        'the signed object is the only copy a wallet may act on'
    );
  }

  return { clientId, requestUri };
}

/** What the wallet holds out of band about who it will accept requests from. */
export interface WalletTrustList {
  /**
   * PEM trust anchor from the wallet's own trust list.
   *
   * The request never carries this and must never be able to: an `x5c` that
   * shipped its own anchor would validate against itself.
   */
  readonly trustAnchorPem: string;
  /** Reference time for every validity window. Defaults to now. */
  readonly now?: Date;
}

/** A signed request the wallet decided to believe (#377). */
export interface VerifiedOid4vpRequest {
  /** The request parameters, read from the SIGNED payload. */
  readonly request: Oid4vpRequestView;
  /** The `x5c` chain the request object carried, leaf first. */
  readonly x5c: readonly string[];
  /** The certificates that chain, parsed — for a suite to assert about. */
  readonly chain: readonly X509Certificate[];
}

/** Decode one base64url JOSE segment into an object. */
function decodeJoseSegment(segment: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** Whether `certificate` is inside its validity window at `now`. */
function isTemporallyValid(certificate: X509Certificate, now: Date): boolean {
  return (
    certificate.validFromDate.getTime() <= now.getTime() &&
    now.getTime() <= certificate.validToDate.getTime()
  );
}

/**
 * Verify a JAR request object the way a wallet would (#377, RFC 9101, HAIP §5).
 *
 * Written against `node:crypto` and `jose` alone, with no import of QAuth's own
 * chain reader — the independence that makes this an interoperability check
 * rather than a round trip through the encoder under test.
 *
 * The order matters and mirrors what a wallet can actually know at each step.
 * Everything before the signature check treats the header as attacker-supplied,
 * because it is: the key that would authenticate it is what the chain produces.
 *
 *  1. `alg` is `ES256` and `typ` is the JAR type — a pin, so a token minted for
 *     something else cannot be replayed here.
 *  2. `x5c` parses, leaf first.
 *  3. The wallet's own anchor is NOT in the chain.
 *  4. Every certificate is inside its validity window.
 *  5. Every link is genuinely issued by the next, by name AND by signature.
 *  6. The top of the chain is issued by the wallet's anchor.
 *  7. `client_id` equals `x509_hash:` + base64url(SHA-256(DER(leaf))).
 *  8. Only now: the signature verifies under the leaf's key.
 *
 * @throws Error naming the first check that refused.
 */
export async function verifyOid4vpRequestObject(
  requestObject: string,
  trust: WalletTrustList
): Promise<VerifiedOid4vpRequest> {
  const now = trust.now ?? new Date();
  const segments = requestObject.split('.');

  if (segments.length !== 3) throw new Error('request object is not a compact JWS');

  const header = decodeJoseSegment(segments[0] as string);

  if (header['alg'] !== 'ES256') {
    throw new Error(`request object must be signed with ES256; got '${String(header['alg'])}'`);
  }
  if (header['typ'] !== REQUEST_OBJECT_TYP) {
    throw new Error(`request object must carry typ '${REQUEST_OBJECT_TYP}'`);
  }

  const x5c = header['x5c'];
  if (!Array.isArray(x5c) || x5c.length === 0) {
    throw new Error('request object carries no x5c chain');
  }

  const chain = x5c.map((entry) => {
    if (typeof entry !== 'string') throw new Error('x5c entry is not a string');
    return new X509Certificate(Buffer.from(entry, 'base64'));
  });

  const anchor = new X509Certificate(trust.trustAnchorPem);

  if (chain.some((certificate) => certificate.raw.equals(anchor.raw))) {
    throw new Error(
      'x5c carries the trust anchor; a chain that ships its own anchor validates against itself'
    );
  }

  for (const certificate of chain) {
    if (!isTemporallyValid(certificate, now)) {
      throw new Error(`certificate '${certificate.subject}' is outside its validity window`);
    }
  }

  for (let index = 0; index < chain.length - 1; index += 1) {
    const child = chain[index] as X509Certificate;
    const parent = chain[index + 1] as X509Certificate;
    if (parent.ca !== true) throw new Error('an x5c intermediate is not a CA');
    if (!child.checkIssued(parent) || !child.verify(parent.publicKey)) {
      throw new Error('x5c chain is broken');
    }
  }

  const top = chain[chain.length - 1] as X509Certificate;
  if (
    !isTemporallyValid(anchor, now) ||
    !top.checkIssued(anchor) ||
    !top.verify(anchor.publicKey)
  ) {
    throw new Error('x5c chain does not terminate at the trust anchor this wallet holds');
  }

  const leaf = chain[0] as X509Certificate;
  const expectedClientId = `${X509_HASH_PREFIX}${createHash('sha256').update(leaf.raw).digest('base64url')}`;

  const { payload } = await compactVerify(
    requestObject,
    await importSPKI(leaf.publicKey.export({ type: 'spki', format: 'pem' }).toString(), 'ES256'),
    { algorithms: ['ES256'] }
  );

  const claims = JSON.parse(Buffer.from(payload).toString('utf8')) as Record<string, unknown>;

  if (claims['client_id'] !== expectedClientId) {
    throw new Error(
      "the request object's client_id is not the base64url SHA-256 of its own leaf certificate"
    );
  }

  const required = (name: string): string => {
    const value = claims[name];
    if (typeof value !== 'string' || value === '') {
      throw new Error(`signed OID4VP request is missing required claim '${name}'`);
    }
    return value;
  };

  return {
    request: {
      clientId: expectedClientId,
      responseType: required('response_type'),
      responseMode: required('response_mode'),
      responseUri: required('response_uri'),
      nonce: required('nonce'),
      state: required('state'),
      dcqlQuery: claims['dcql_query'] as DcqlQueryView,
      clientMetadata: (claims['client_metadata'] ?? {}) as Record<string, unknown>,
    },
    x5c: x5c as readonly string[],
    chain,
  };
}
