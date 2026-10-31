import { z } from 'zod';

import { constant, displayText, jsonString, matching, object, openObject } from '../zod-kit';

/**
 * Pieces several steps share, as the contract's `steps/shared.ts` defines
 * them.
 */

/** The account identifier, as the transaction holds it: personal data. */
export const accountIdentifier = displayText(
  'account',
  254,
  'The identifier of the account this transaction is for. Before a first factor succeeds it is the identifier exactly as the person gave it, after the one normalisation every input gets, whether or not an account holds it, so it tells nothing about which accounts exist; the form the account holds appears only after authentication. Personal data: only the personal-data read returns it.'
);

/** The personal data of a step whose screen shows only who is signing in ("Not you?"). */
export const identifierPersonal = object(
  { identifier: accountIdentifier.optional() },
  'Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier.'
);

/** The description of {@link loginHint}, which two steps extend. */
export const LOGIN_HINT_DESCRIPTION =
  'The identifier: today an email address of at most 254 bytes in UTF-8 (ADR-017 Decision 3). The schema counts characters; the server counts bytes, checks the full email syntax and normalises the address before use.';

/** The identifier as an answer field (ADR-017 Decision 3: `login_hint`). */
export const loginHint = matching(z.string().min(3).max(254), '^[^@\\s]+@[^@\\s]+$').meta({
  description: LOGIN_HINT_DESCRIPTION,
});

/** A one-time code of six digits, as an answer field (FiPA Appendix B.1 names it `otp`). */
export const sixDigitOtp = matching(z.string(), '^[0-9]{6}$').meta({
  description: 'The six digits the authenticator app shows.',
});

/** `PublicKeyCredential.toJSON()` of an authentication (WebAuthn Level 3). */
const assertionJson = openObject({
  id: z.string(),
  rawId: z.string(),
  type: constant('public-key'),
  response: openObject({
    clientDataJSON: z.string(),
    authenticatorData: z.string(),
    signature: z.string(),
    userHandle: z.string().optional(),
  }),
  authenticatorAttachment: z.string().optional(),
  clientExtensionResults: openObject({}),
});

/** `PublicKeyCredential.toJSON()` of a registration (WebAuthn Level 3). */
const attestationJson = openObject({
  id: z.string(),
  rawId: z.string(),
  type: constant('public-key'),
  response: openObject({
    clientDataJSON: z.string(),
    attestationObject: z.string(),
    transports: z.array(z.string()).optional(),
  }),
  authenticatorAttachment: z.string().optional(),
  clientExtensionResults: openObject({}),
});

/** A WebAuthn response: `PublicKeyCredential.toJSON()` as a JSON string, as on the FiPA transport. */
export function webauthnResponse(maxLength: number, kind: 'assertion' | 'attestation') {
  return jsonString(
    kind === 'assertion' ? assertionJson : attestationJson,
    2,
    maxLength,
    `The ${
      kind === 'assertion' ? 'authentication' : 'registration'
    } response, \`PublicKeyCredential.toJSON()\` (WebAuthn Level 3), as a JSON string. It is a string on both transports, so a form post carries it in one field (ADR-017 Decision 3).`
  );
}
