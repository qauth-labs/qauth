import { randomBytes as nodeRandomBytes } from 'node:crypto';

import { isWebAuthnOriginForRpId, normaliseWebAuthnOrigin } from '@qauth-labs/shared-validation';
import { z } from 'zod';

import {
  authenticationResponseSchema,
  type CreationOptionsJSON,
  type CredentialDescriptorJSON,
  registrationResponseSchema,
  type RequestOptionsJSON,
  WEBAUTHN_ALGORITHMS,
  type WebAuthnPurpose,
  type WebAuthnTransport,
} from '../webauthn/webauthn.types';
import type { WebAuthnChallengeStore } from '../webauthn/webauthn-challenge-store';
import {
  type WebAuthnCeremonyState,
  webauthnCeremonyStateSchema,
} from '../webauthn/webauthn-challenge-store';
import { WebAuthnRejection } from '../webauthn/webauthn-rejection';
import type { WebAuthnVerifier } from '../webauthn/webauthn-verifier';
import type {
  CredentialProvider,
  UserAttribute,
  VerifiedIdentity,
} from './credential-provider.interface';
import {
  normalisePasskeyNickname,
  type WebAuthnCredentialData,
  webauthnCredentialDataSchema,
} from './webauthn-credential-data';

/**
 * WebAuthnProvider — the `type='webauthn'` {@link CredentialProvider}
 * (ADR-017 Decision 14 and phase F2b, ADR-003, issue #467).
 *
 * The ONE WebAuthn provider QAuth has. First-party sign-in (the FiPA
 * `webauthn_get` and `webauthn_create` steps), the hosted account pages, admin
 * sign-in and the Authority Tree's out-of-band approval (ADR-014 §14) all use
 * it, so the ceremony rules exist once.
 *
 * ## What it owns
 *
 * - The `user_credentials` row's meaning: `external_sub` is the credential id
 *   (base64url) and `credential_data` is {@link WebAuthnCredentialData}.
 * - Options: `attestation: "none"`, the algorithms EdDSA, ES256 and RS256 and
 *   nothing else, and the user-verification rule of the ceremony's purpose.
 * - The ceremony state: a fresh 32-byte challenge per ceremony, stored under
 *   the transaction with the RP ID and origins it must match, and taken (read
 *   and deleted at once) before an answer is checked, so a challenge answers
 *   once and only for its transaction.
 * - The sign counter: a counter that does not grow past a nonzero stored one
 *   is FLAGGED (`sign_counter_regressed` in `rawClaims`, and
 *   `sign_counter_regressed_at` on the record), not refused. WebAuthn Level 3
 *   §6.1.1 leaves the decision to the relying party; a synced passkey reports 0
 *   forever, and refusing a hardware key outright on one glitch would lock its
 *   owner out. The caller records the flag and decides.
 *
 * ## Two rounds, one `verify()`
 *
 * ADR-003's `verify()` is single-shot: it takes an assertion and returns who
 * answered. The rounds around it are separate methods: `startAuthentication`
 * before it, and `startRegistration` / `finishRegistration` for enrolment.
 * The step verifiers above the provider drive them per transport.
 *
 * ## Assurance
 *
 * `assuranceLevel` is `'low'`, so a passkey sign-in emits no `acr` claim, as a
 * password sign-in does not. A passkey is a stronger authenticator, but the
 * `acr` vocabulary describes identity assurance (ADR-010), and an
 * authenticator-strength `acr` is planned work (ADR-017 F5), not this change.
 *
 * ## Where the RP ID comes from
 *
 * The caller passes the RP ID and origins at the start of each ceremony, from
 * the realm row and the client row (ADR-019 Decision 1: no URL is built from
 * the request). So one provider serves every realm, and the RP ID rules in
 * `webauthn/relying-party-id.ts` decide what a realm's RP ID is.
 */

/** `user_credentials.provider_type` / registry key for this provider. */
export const WEBAUTHN_PROVIDER_TYPE = 'webauthn';

/** How long a ceremony waits for its answer, and the `timeout` hint sent with the options. */
export const WEBAUTHN_CEREMONY_TIMEOUT_MS = 5 * 60 * 1000;

/** Challenge size in bytes. WebAuthn Level 3 §13.4.3 asks for at least 16. */
export const WEBAUTHN_CHALLENGE_BYTES = 32;

/** Longest `user.name` and `user.displayName` sent to an authenticator. */
const USER_NAME_MAX_LENGTH = 256;

/** A user handle: 1–64 bytes (§5.4.3), base64url. */
const userHandleSchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{2,86}$/, 'must be the base64url form of 1 to 64 bytes');

/** What {@link WebAuthnProvider.startRegistration} takes. */
export interface StartRegistrationInput {
  /** The transaction the ceremony belongs to. */
  readonly transactionId: string;
  readonly purpose: WebAuthnPurpose;
  /** The realm's RP ID, and the name an authenticator may show. */
  readonly rp: { readonly id: string; readonly name: string };
  /** The origins an answer may come from: the realm's, and the client's operator-set ones. */
  readonly origins: readonly string[];
  readonly user: {
    /**
     * The WebAuthn user handle, base64url of 1–64 bytes with no personal data
     * (§14.6.1). Reuse the handle of the user's existing passkeys, so an
     * authenticator replaces its credential for the account instead of adding
     * a second one; {@link generateWebAuthnUserHandle} makes a new one.
     */
    readonly handle: string;
    readonly name: string;
    readonly displayName: string;
  };
  /** The user's existing credentials, so an authenticator does not enrol twice. */
  readonly excludeCredentials?: readonly StoredCredentialHint[];
}

/** A stored credential named in options. */
export interface StoredCredentialHint {
  /** The credential id, base64url (the row's `external_sub`). */
  readonly id: string;
  readonly transports?: readonly WebAuthnTransport[];
}

/** What {@link WebAuthnProvider.finishRegistration} takes. */
export interface FinishRegistrationInput {
  readonly transactionId: string;
  /** The browser's `RegistrationResponseJSON`, unparsed. */
  readonly response: unknown;
  /** The name the user gave the passkey. */
  readonly nickname?: string | null;
}

/** A verified registration: the `user_credentials` row to write. */
export interface WebAuthnEnrolment {
  /** `user_credentials.external_sub`: the credential id. */
  readonly externalSub: string;
  readonly credentialData: WebAuthnCredentialData;
  /** The RP ID the credential is bound to: the realm's lock, if it has none yet. */
  readonly rpId: string;
  readonly purpose: WebAuthnPurpose;
  /** The attestation statement format, for the audit record. */
  readonly attestationFormat: string;
}

/** What {@link WebAuthnProvider.startAuthentication} takes. */
export interface StartAuthenticationInput {
  readonly transactionId: string;
  readonly purpose: WebAuthnPurpose;
  readonly rpId: string;
  readonly origins: readonly string[];
  /**
   * The credentials that may answer. Empty or absent for a passkey-first
   * sign-in, where the account is not known yet. A second factor always has an
   * account, so `second-factor` requires at least one.
   */
  readonly allowCredentials?: readonly StoredCredentialHint[];
}

/**
 * Input contract of {@link CredentialProvider.verify} for `'webauthn'`: the
 * transaction, the browser's answer, and the stored credential the answer
 * names. The caller looks the credential up by the response's `id` within the
 * realm (`(realm_id, 'webauthn', external_sub)`). `.strict()`: built
 * in-process, so an unknown key is a programming error.
 */
export const webauthnVerifyInputSchema = z
  .object({
    transactionId: z.string().min(1).max(512),
    response: z.unknown(),
    credential: z
      .object({
        externalSub: z.string().min(1),
        credentialData: z.record(z.string(), z.unknown()),
      })
      .strict(),
  })
  .strict();

export type WebAuthnVerifyInput = z.infer<typeof webauthnVerifyInputSchema>;

/**
 * `rawClaims` of a passkey assertion. A `type` alias, not an interface, so it
 * is assignable to `Record<string, unknown>` (see `WalletRawClaims`).
 */
export type WebAuthnRawClaims = {
  readonly credential_id: string;
  readonly rp_id: string;
  readonly origin: string;
  readonly purpose: WebAuthnPurpose;
  readonly user_verified: boolean;
  readonly backup_eligible: boolean;
  readonly backed_up: boolean;
  /** The counter the authenticator presented. */
  readonly sign_count: number;
  /** The counter did not grow past a nonzero stored counter: possibly a cloned authenticator. */
  readonly sign_counter_regressed: boolean;
};

/** The WebAuthn {@link CredentialProvider} with its ceremony rounds. */
export interface WebAuthnProvider extends CredentialProvider {
  readonly type: typeof WEBAUTHN_PROVIDER_TYPE;
  /** Start a registration: store the ceremony state, return the creation options. */
  startRegistration(input: StartRegistrationInput): Promise<CreationOptionsJSON>;
  /** Check a registration answer and return the credential to store. */
  finishRegistration(input: FinishRegistrationInput): Promise<WebAuthnEnrolment>;
  /** Start an authentication: store the ceremony state, return the request options. */
  startAuthentication(input: StartAuthenticationInput): Promise<RequestOptionsJSON>;
  /**
   * Check an assertion against the stored credential and its transaction.
   *
   * @throws WebAuthnRejection when the answer is refused; its `reason` says why.
   * @throws Error when the input or the stored record is malformed: a wiring
   * error, never a wire answer.
   */
  verify(input: unknown): Promise<VerifiedIdentity>;
  /** A passkey asserts nothing about the person: always `[]`. */
  extractAttributes(result: VerifiedIdentity): UserAttribute[];
}

/** What {@link createWebAuthnProvider} needs. */
export interface WebAuthnProviderDependencies {
  /** The library seam. */
  readonly verifier: WebAuthnVerifier;
  /** Where ceremony state waits between rounds. Must take atomically (see the port). */
  readonly challenges: WebAuthnChallengeStore;
  /** Clock, epoch milliseconds. */
  readonly now?: () => number;
  /** Source of challenge bytes. */
  readonly randomBytes?: (size: number) => Uint8Array;
}

/** A new WebAuthn user handle: 32 random bytes, base64url. */
export function generateWebAuthnUserHandle(
  randomBytes: (size: number) => Uint8Array = nodeRandomBytes
): string {
  return Buffer.from(randomBytes(32)).toString('base64url');
}

/**
 * Create the WebAuthn {@link CredentialProvider}. One instance serves every
 * realm; the realm's RP ID and origins arrive with each ceremony.
 */
export function createWebAuthnProvider(deps: WebAuthnProviderDependencies): WebAuthnProvider {
  const now = deps.now ?? Date.now;
  const randomBytes = deps.randomBytes ?? nodeRandomBytes;

  async function beginCeremony(
    transactionId: string,
    state: Omit<WebAuthnCeremonyState, 'challenge' | 'expiresAt'>
  ): Promise<string> {
    assertTransactionId(transactionId);
    const challenge = Buffer.from(randomBytes(WEBAUTHN_CHALLENGE_BYTES)).toString('base64url');
    await deps.challenges.begin(
      transactionId,
      { ...state, challenge, expiresAt: now() + WEBAUTHN_CEREMONY_TIMEOUT_MS },
      WEBAUTHN_CEREMONY_TIMEOUT_MS
    );
    return challenge;
  }

  /** Take the transaction's ceremony state; refuse a missing, expired or wrong one. */
  async function takeCeremony(
    transactionId: string,
    ceremony: WebAuthnCeremonyState['ceremony']
  ): Promise<WebAuthnCeremonyState> {
    const stored = await deps.challenges.take(transactionId);
    if (stored === undefined) throw new WebAuthnRejection('challenge-unavailable');
    const parsed = webauthnCeremonyStateSchema.safeParse(stored);
    if (!parsed.success) {
      throw new WebAuthnRejection('challenge-unavailable', { cause: parsed.error });
    }
    if (parsed.data.expiresAt <= now()) throw new WebAuthnRejection('challenge-unavailable');
    if (parsed.data.ceremony !== ceremony) throw new WebAuthnRejection('ceremony-mismatch');
    return parsed.data;
  }

  return {
    type: WEBAUTHN_PROVIDER_TYPE,

    async startRegistration(input: StartRegistrationInput): Promise<CreationOptionsJSON> {
      const rpId = input.rp.id;
      const origins = ceremonyOrigins(input.origins, rpId);
      const handle = userHandleSchema.parse(input.user.handle);
      const signIn = input.purpose === 'sign-in';

      const challenge = await beginCeremony(input.transactionId, {
        ceremony: 'registration',
        purpose: input.purpose,
        rpId,
        origins,
        userHandle: handle,
      });

      return {
        rp: { id: rpId, name: input.rp.name },
        user: {
          id: handle,
          name: boundedName(input.user.name),
          displayName: boundedName(input.user.displayName),
        },
        challenge,
        pubKeyCredParams: WEBAUTHN_ALGORITHMS.map((alg) => ({ type: 'public-key' as const, alg })),
        timeout: WEBAUTHN_CEREMONY_TIMEOUT_MS,
        excludeCredentials: descriptors(input.excludeCredentials),
        authenticatorSelection: {
          // A passkey that signs in alone must be discoverable and verify the
          // user; a second factor need not be either.
          residentKey: signIn ? 'required' : 'discouraged',
          requireResidentKey: signIn,
          userVerification: signIn ? 'required' : 'preferred',
        },
        attestation: 'none',
        extensions: { credProps: true },
      };
    },

    async finishRegistration(input: FinishRegistrationInput): Promise<WebAuthnEnrolment> {
      const state = await takeCeremony(input.transactionId, 'registration');
      const response = registrationResponseSchema.safeParse(input.response);
      if (!response.success) {
        throw new WebAuthnRejection('malformed-response', { cause: response.error });
      }
      if (state.userHandle === undefined) throw new WebAuthnRejection('challenge-unavailable');

      const verified = await deps.verifier.verifyRegistration({
        response: response.data,
        expectedChallenge: state.challenge,
        expectedOrigins: state.origins,
        expectedRpId: state.rpId,
        requireUserVerification: state.purpose === 'sign-in',
      });

      const registeredAt = now();
      return {
        externalSub: verified.credentialId,
        rpId: state.rpId,
        purpose: state.purpose,
        attestationFormat: verified.attestationFormat,
        credentialData: {
          public_key: verified.publicKey,
          algorithm: verified.algorithm,
          sign_count: verified.signCount,
          transports: [...verified.transports],
          backup_eligible: verified.backupEligible,
          backed_up: verified.backedUp,
          aaguid: verified.aaguid,
          rp_id: state.rpId,
          user_handle: state.userHandle,
          nickname: normalisePasskeyNickname(input.nickname),
          created_at: registeredAt,
          last_used_at: null,
          sign_counter_regressed_at: null,
        },
      };
    },

    async startAuthentication(input: StartAuthenticationInput): Promise<RequestOptionsJSON> {
      const origins = ceremonyOrigins(input.origins, input.rpId);
      const allow = descriptors(input.allowCredentials);
      if (input.purpose === 'second-factor' && allow.length === 0) {
        throw new Error(
          'A second-factor WebAuthn ceremony needs the account’s credentials in allowCredentials'
        );
      }

      const challenge = await beginCeremony(input.transactionId, {
        ceremony: 'authentication',
        purpose: input.purpose,
        rpId: input.rpId,
        origins,
        allowCredentialIds: allow.map((credential) => credential.id),
      });

      return {
        challenge,
        rpId: input.rpId,
        timeout: WEBAUTHN_CEREMONY_TIMEOUT_MS,
        allowCredentials: allow,
        userVerification: input.purpose === 'sign-in' ? 'required' : 'preferred',
      };
    },

    async verify(input: unknown): Promise<VerifiedIdentity> {
      const parsedInput = webauthnVerifyInputSchema.safeParse(input);
      if (!parsedInput.success) {
        throw new Error(
          `WebAuthnProvider.verify received a malformed input: ${parsedInput.error.message}`
        );
      }
      const { transactionId, credential } = parsedInput.data;

      // First, before anything is checked: a failed answer burns the challenge too.
      const state = await takeCeremony(transactionId, 'authentication');

      const stored = webauthnCredentialDataSchema.safeParse(credential.credentialData);
      if (!stored.success) {
        throw new Error(
          `WebAuthnProvider.verify received a malformed credential_data: ${stored.error.message}`
        );
      }
      const response = authenticationResponseSchema.safeParse(parsedInput.data.response);
      if (!response.success) {
        throw new WebAuthnRejection('malformed-response', { cause: response.error });
      }

      const allowed = state.allowCredentialIds ?? [];
      if (
        response.data.id !== credential.externalSub ||
        (allowed.length > 0 && !allowed.includes(response.data.id))
      ) {
        throw new WebAuthnRejection('credential-mismatch');
      }
      // A credential created under another RP ID cannot answer this one.
      if (stored.data.rp_id !== state.rpId) throw new WebAuthnRejection('rp-id-mismatch');

      const verified = await deps.verifier.verifyAssertion({
        response: response.data,
        expectedChallenge: state.challenge,
        expectedOrigins: state.origins,
        expectedRpId: state.rpId,
        requireUserVerification: state.purpose === 'sign-in',
        credential: { id: credential.externalSub, publicKey: stored.data.public_key },
      });

      // WebAuthn Level 3 §7.2 step 6: when the account was not named before
      // the ceremony, the user handle is how the answer names it, so it must be
      // there; when it is there, it must be this credential's.
      if (
        (allowed.length === 0 && verified.userHandle === undefined) ||
        (verified.userHandle !== undefined && verified.userHandle !== stored.data.user_handle)
      ) {
        throw new WebAuthnRejection('user-handle-mismatch');
      }
      if (verified.backupEligible !== stored.data.backup_eligible) {
        throw new WebAuthnRejection('backup-eligibility-changed');
      }

      const rawClaims: WebAuthnRawClaims = {
        credential_id: credential.externalSub,
        rp_id: state.rpId,
        origin: verified.origin,
        purpose: state.purpose,
        user_verified: verified.userVerified,
        backup_eligible: verified.backupEligible,
        backed_up: verified.backedUp,
        sign_count: verified.signCount,
        sign_counter_regressed: signCounterRegressed(stored.data.sign_count, verified.signCount),
      };
      return { externalSub: credential.externalSub, assuranceLevel: 'low', rawClaims };
    },

    extractAttributes(): UserAttribute[] {
      // Unlike a wallet credential, a passkey carries no claim about the
      // person: there is nothing here to drop, so `[]` is the full answer.
      return [];
    },
  };
}

/**
 * WebAuthn Level 3 §6.1.1: when either counter is nonzero, the presented one
 * must be greater than the stored one. Otherwise the authenticator may have
 * been cloned. Both zero means the authenticator keeps no counter.
 */
export function signCounterRegressed(storedCount: number, presentedCount: number): boolean {
  return (storedCount > 0 || presentedCount > 0) && presentedCount <= storedCount;
}

/**
 * The stored record after an accepted assertion: the higher counter (a
 * regressed counter never lowers it), the current BS flag, the time of use,
 * and the time of a regression when there was one.
 */
export function webauthnCredentialDataAfterAssertion(
  stored: WebAuthnCredentialData,
  claims: WebAuthnRawClaims,
  usedAt: number
): WebAuthnCredentialData {
  return {
    ...stored,
    sign_count: Math.max(stored.sign_count, claims.sign_count),
    backed_up: claims.backed_up,
    last_used_at: usedAt,
    sign_counter_regressed_at: claims.sign_counter_regressed
      ? usedAt
      : stored.sign_counter_regressed_at,
  };
}

function assertTransactionId(transactionId: string): void {
  if (
    typeof transactionId !== 'string' ||
    transactionId.length === 0 ||
    transactionId.length > 512
  ) {
    throw new Error('A WebAuthn ceremony needs a transaction id of 1 to 512 characters');
  }
}

/**
 * The origins a ceremony allows, normalised, each one usable under the RP ID.
 * A wrong origin is the operator's configuration error, so it throws a plain
 * error naming it, at the start of the ceremony.
 */
function ceremonyOrigins(origins: readonly string[], rpId: string): string[] {
  if (origins.length === 0) throw new Error('A WebAuthn ceremony needs at least one origin');
  const normalised = new Set<string>();
  for (const origin of origins) {
    const value = normaliseWebAuthnOrigin(origin);
    if (!isWebAuthnOriginForRpId(value, rpId)) {
      throw new Error(`The origin "${value}" cannot run a ceremony for the RP ID "${rpId}"`);
    }
    normalised.add(value);
  }
  return [...normalised];
}

function descriptors(
  credentials: readonly StoredCredentialHint[] | undefined
): CredentialDescriptorJSON[] {
  return (credentials ?? []).map((credential) => ({
    type: 'public-key' as const,
    id: credential.id,
    ...(credential.transports && credential.transports.length > 0
      ? { transports: [...credential.transports] }
      : {}),
  }));
}

function boundedName(value: string): string {
  return Array.from(value).slice(0, USER_NAME_MAX_LENGTH).join('');
}
