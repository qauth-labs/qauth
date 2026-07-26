/**
 * TEST SUPPORT — a working SD-JWT VC issuer and holder (issue #234).
 *
 * Lives in `testing/`, OUTSIDE `src/`, and that placement is load-bearing rather
 * than tidy: this module mints real, correctly-signed credentials, so leaving it
 * next to the validator it exists to attack would put a credential minter one
 * careless import away from the package's shipped source (`package.json` `main`
 * is `src/index.ts`). It is not exported from `index.ts` and nothing under
 * `src/` may import it — `src/test-support-boundary.test.ts` asserts both, so
 * the rule survives a future edit that does not read this comment.
 *
 * ## Why hand-constructed credentials rather than recorded ones
 *
 * Every rejection path this validator has must be provable, and most of them are
 * only reachable by producing a credential that is CORRECT in every respect but
 * one — a real issuer signature over a payload whose `exp` has passed, a real
 * Key Binding JWT carrying yesterday's `nonce`, a genuine Disclosure whose
 * digest the issuer never signed. A recorded fixture from a real wallet cannot
 * be bent that way without also breaking its signature, which would make several
 * different tests all pass for the same uninteresting reason.
 *
 * So this issues credentials for real: real ES256/EdDSA keys, real signatures,
 * real digests. A test that mutates one field therefore fails for exactly the
 * reason it names.
 *
 * The composition is two-phase, mirroring the protocol: {@link issueSdJwtVc}
 * plays the ISSUER (signs the credential and its digests), {@link presentSdJwtVc}
 * plays the HOLDER (chooses which Disclosures to reveal and signs the Key
 * Binding JWT). Splitting them is what makes holder-side attacks expressible —
 * a holder presenting more, fewer, or different Disclosures than the issuer
 * signed is a distinct test from an issuer signing the wrong thing.
 */

import { createHash, randomBytes } from 'node:crypto';

import {
  exportPublicSigningJwk,
  generateSigningKeyPair,
  type JwsAlgorithm,
  type SigningKeyPair,
} from '@qauth-labs/core-crypto';
import { type CompactJWSHeaderParameters, CompactSign, type JWK } from 'jose';

import type { DcqlCredentialQuery } from '../src/oid4vp/dcql';
import { createStaticIssuerKeyResolver } from '../src/oid4vp/issuer-key-resolution';
import { KEY_BINDING_JWT_TYP, SD_JWT_VC_TYP } from '../src/oid4vp/sd-jwt-vc';
import type { PresentationValidationContext } from '../src/oid4vp/validated-credential';
import type { CredentialFormat } from '../src/profiles/verifier-profile.types';

/** The issuer identity every fixture credential claims. */
export const TEST_ISSUER = 'https://issuer.example.com';

/** The credential type every fixture credential carries. */
export const TEST_VCT = 'https://credentials.example.com/pid';

/** QAuth's `client_id` in fixture flows. */
export const TEST_CLIENT_ID = 'https://auth.example.com/oid4vp/response';

/** The DCQL Credential Query fixture credentials answer. */
export const TEST_CREDENTIAL_QUERY: DcqlCredentialQuery = Object.freeze({
  id: 'pid',
  format: 'dc+sd-jwt' satisfies CredentialFormat,
  meta: Object.freeze({ vct_values: Object.freeze([TEST_VCT]) }),
});

/** Encode a Disclosure exactly as SD-JWT §4.2 specifies. */
export function encodeDisclosure(parts: readonly unknown[]): string {
  return Buffer.from(JSON.stringify(parts), 'utf8').toString('base64url');
}

/** Digest an encoded Disclosure. */
export function digestDisclosure(encoded: string, hashAlgorithm = 'sha256'): string {
  return createHash(hashAlgorithm).update(encoded, 'ascii').digest('base64url');
}

/** A fresh 128-bit salt, base64url — what a real issuer would mint per claim. */
export function randomSalt(): string {
  return randomBytes(16).toString('base64url');
}

/** Build an object-property Disclosure and its digest. */
export function objectDisclosure(
  name: string,
  value: unknown,
  hashAlgorithm = 'sha256'
): { readonly encoded: string; readonly digest: string } {
  const encoded = encodeDisclosure([randomSalt(), name, value]);
  return { encoded, digest: digestDisclosure(encoded, hashAlgorithm) };
}

/** Build an array-element Disclosure and its digest. */
export function arrayDisclosure(
  value: unknown,
  hashAlgorithm = 'sha256'
): { readonly encoded: string; readonly digest: string } {
  const encoded = encodeDisclosure([randomSalt(), value]);
  return { encoded, digest: digestDisclosure(encoded, hashAlgorithm) };
}

/** Sign an arbitrary payload as a compact JWS. */
export async function signCompactJws(
  payload: Record<string, unknown>,
  keyPair: SigningKeyPair,
  header: CompactJWSHeaderParameters
): Promise<string> {
  return new CompactSign(Buffer.from(JSON.stringify(payload), 'utf8'))
    .setProtectedHeader(header)
    .sign(keyPair.privateKey);
}

/** A generated key pair plus its published public JWK. */
export interface FixtureKeys {
  readonly keyPair: SigningKeyPair;
  readonly jwk: JWK;
}

/** Generate a signing key pair and export its public JWK. */
export async function generateFixtureKeys(
  algorithm: JwsAlgorithm = 'ES256',
  kid?: string
): Promise<FixtureKeys> {
  const keyPair = await generateSigningKeyPair(algorithm, { extractable: true });
  const jwk = await exportPublicSigningJwk(keyPair.publicKey, {
    alg: algorithm,
    ...(kid === undefined ? {} : { kid }),
  });
  return { keyPair, jwk };
}

/** What {@link issueSdJwtVc} may vary. */
export interface IssueSdJwtVcOptions {
  readonly issuer?: string;
  readonly vct?: string;
  /** Claims signed in the clear, always visible. */
  readonly plainClaims?: Record<string, unknown>;
  /** Claims made selectively disclosable — one Disclosure and `_sd` digest each. */
  readonly selectiveClaims?: Record<string, unknown>;
  readonly exp?: number;
  readonly nbf?: number;
  readonly iat?: number;
  /** `_sd_alg`; omitted entirely when `null`, exercising the sha-256 default. */
  readonly sdAlg?: string | null;
  readonly algorithm?: JwsAlgorithm;
  readonly holderAlgorithm?: JwsAlgorithm;
  /** Reuse an existing issuer key pair — e.g. two credentials from one issuer. */
  readonly issuerKeys?: FixtureKeys;
  /** Reuse an existing holder key pair. */
  readonly holderKeys?: FixtureKeys;
  /** Issuer JWS `typ`; override to test cross-token confusion. */
  readonly typ?: string;
  readonly kid?: string;
  /** Replace `cnf` wholesale (or remove it with `null`). */
  readonly cnf?: Record<string, unknown> | null;
  /** Merged into the payload last — the escape hatch for hand-built structures. */
  readonly payloadOverrides?: Record<string, unknown>;
  /** Merged into the protected header last (`x5c`, and anything else a test needs). */
  readonly headerOverrides?: Record<string, unknown>;
  /** Extra Disclosures the issuer signed digests for, beyond `selectiveClaims`. */
  readonly extraDisclosures?: readonly string[];
}

/** An issued credential, with everything a test needs to bend it. */
export interface IssuedSdJwtVc {
  readonly issuerSignedJwt: string;
  /** Every Disclosure the issuer produced, in `selectiveClaims` order. */
  readonly disclosures: readonly string[];
  readonly issuerKeys: FixtureKeys;
  readonly holderKeys: FixtureKeys;
  readonly issuer: string;
  readonly hashAlgorithm: string;
}

/** Node hash identifier for an IANA `_sd_alg` name. */
function nodeHashAlgorithm(sdAlg: string | null | undefined): string {
  if (sdAlg === undefined || sdAlg === null || sdAlg === 'sha-256') return 'sha256';
  if (sdAlg === 'sha-384') return 'sha384';
  if (sdAlg === 'sha-512') return 'sha512';
  return 'sha256';
}

/**
 * Play the ISSUER: sign a credential over a set of selectively-disclosable
 * claims.
 *
 * Defaults produce a credential that validates cleanly, so every test states
 * only what it changes.
 */
export async function issueSdJwtVc(options: IssueSdJwtVcOptions = {}): Promise<IssuedSdJwtVc> {
  const algorithm = options.algorithm ?? 'ES256';
  const holderAlgorithm = options.holderAlgorithm ?? 'ES256';
  const issuerKeys = options.issuerKeys ?? (await generateFixtureKeys(algorithm, options.kid));
  const holderKeys = options.holderKeys ?? (await generateFixtureKeys(holderAlgorithm));
  const hashAlgorithm = nodeHashAlgorithm(options.sdAlg);
  const nowSeconds = Math.floor(Date.now() / 1000);

  const selectiveClaims = options.selectiveClaims ?? { given_name: 'Alice', family_name: 'Doe' };
  const disclosures: string[] = [];
  const digests: string[] = [];

  for (const [name, value] of Object.entries(selectiveClaims)) {
    const disclosure = objectDisclosure(name, value, hashAlgorithm);
    disclosures.push(disclosure.encoded);
    digests.push(disclosure.digest);
  }

  for (const encoded of options.extraDisclosures ?? []) {
    disclosures.push(encoded);
    digests.push(digestDisclosure(encoded, hashAlgorithm));
  }

  const confirmation =
    options.cnf === undefined ? { jwk: holderKeys.jwk } : (options.cnf ?? undefined);

  const payload: Record<string, unknown> = {
    iss: options.issuer ?? TEST_ISSUER,
    vct: options.vct ?? TEST_VCT,
    iat: options.iat ?? nowSeconds,
    ...(options.nbf === undefined ? {} : { nbf: options.nbf }),
    ...(options.exp === undefined ? {} : { exp: options.exp }),
    ...(options.sdAlg === null ? {} : { _sd_alg: options.sdAlg ?? 'sha-256' }),
    ...(digests.length === 0 ? {} : { _sd: digests }),
    ...(confirmation === undefined ? {} : { cnf: confirmation }),
    ...(options.plainClaims ?? {}),
    ...(options.payloadOverrides ?? {}),
  };

  const issuerSignedJwt = await signCompactJws(payload, issuerKeys.keyPair, {
    alg: algorithm,
    typ: options.typ ?? SD_JWT_VC_TYP,
    ...(options.kid === undefined ? {} : { kid: options.kid }),
    ...(options.headerOverrides ?? {}),
  });

  return {
    issuerSignedJwt,
    disclosures,
    issuerKeys,
    holderKeys,
    issuer: options.issuer ?? TEST_ISSUER,
    hashAlgorithm,
  };
}

/** What {@link presentSdJwtVc} may vary. */
export interface PresentSdJwtVcOptions {
  readonly nonce: string;
  readonly audience?: string;
  /** Disclosures to reveal; defaults to every one the issuer produced. */
  readonly disclosures?: readonly string[];
  /** Key Binding JWT `iat`. */
  readonly issuedAt?: number;
  /** Override the computed `sd_hash` — the direct way to break the binding. */
  readonly sdHash?: string;
  /** Key Binding JWT `typ`. */
  readonly typ?: string;
  /** Sign the Key Binding JWT with a key OTHER than the credential's `cnf` key. */
  readonly signingKeys?: SigningKeyPair;
  readonly algorithm?: JwsAlgorithm;
  /** Omit the Key Binding JWT entirely. */
  readonly omitKeyBinding?: boolean;
  /** Extra Disclosures appended AFTER the `sd_hash` was computed. */
  readonly appendAfterBinding?: readonly string[];
}

/**
 * Play the HOLDER: choose Disclosures and sign the Key Binding JWT over them.
 *
 * @returns the compact Presentation, ready to hand to the validator.
 */
export async function presentSdJwtVc(
  issued: IssuedSdJwtVc,
  options: PresentSdJwtVcOptions
): Promise<string> {
  const disclosures = options.disclosures ?? issued.disclosures;
  const prefix = [issued.issuerSignedJwt, ...disclosures, ''].join('~');

  if (options.omitKeyBinding === true) return prefix;

  const algorithm = options.algorithm ?? 'ES256';
  const sdHash =
    options.sdHash ?? createHash(issued.hashAlgorithm).update(prefix, 'ascii').digest('base64url');

  const keyBindingJwt = await signCompactJws(
    {
      iat: options.issuedAt ?? Math.floor(Date.now() / 1000),
      aud: options.audience ?? TEST_CLIENT_ID,
      nonce: options.nonce,
      sd_hash: sdHash,
    },
    options.signingKeys ?? issued.holderKeys.keyPair,
    { alg: algorithm, typ: options.typ ?? KEY_BINDING_JWT_TYP }
  );

  const appended = options.appendAfterBinding ?? [];

  if (appended.length > 0) {
    return `${[issued.issuerSignedJwt, ...disclosures, ...appended, ''].join('~')}${keyBindingJwt}`;
  }

  return `${prefix}${keyBindingJwt}`;
}

/**
 * A validation context wired to the fixture issuer's published key.
 *
 * The default is the CLEAN path — a deployment that knows this issuer's key and
 * permits this credential format. Overrides express the deviation under test.
 */
export function fixtureValidationContext(
  issued: IssuedSdJwtVc,
  nonce: string,
  overrides: Partial<PresentationValidationContext> = {}
): PresentationValidationContext {
  return {
    clientId: TEST_CLIENT_ID,
    nonce,
    signatureAlgorithms: ['ES256', 'EdDSA'],
    permittedFormats: ['dc+sd-jwt'],
    resolveIssuerKey: createStaticIssuerKeyResolver([
      { issuer: issued.issuer, jwks: [issued.issuerKeys.jwk] },
    ]),
    ...overrides,
  };
}
