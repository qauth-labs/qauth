import { displayText, type JsonSchema, object, openObject } from '../schema-kit';

/**
 * Pieces several steps share. Each step's published schema copies what it
 * uses, so a step file stands alone.
 */

/** The account identifier, as the transaction holds it: personal data. */
export const accountIdentifier: JsonSchema = displayText(
  'account',
  254,
  'The identifier of the account this transaction is for. Before a first factor succeeds it is the identifier exactly as the person gave it, after the one normalisation every input gets, whether or not an account holds it, so it tells nothing about which accounts exist; the form the account holds appears only after authentication. Personal data: only the personal-data read returns it.'
);

/** The personal data of a step whose screen shows only who is signing in ("Not you?"). */
export const identifierPersonal: JsonSchema = object(
  { identifier: accountIdentifier },
  [],
  'Who the transaction is for, so the screen can show it with a way to switch accounts. Absent until the transaction has an identifier.'
);

/** The identifier as an answer field (ADR-017 Decision 3: `login_hint`). */
export const loginHint: JsonSchema = {
  type: 'string',
  minLength: 3,
  maxLength: 254,
  pattern: '^[^@\\s]+@[^@\\s]+$',
  description:
    'The identifier: today an email address of at most 254 bytes in UTF-8 (ADR-017 Decision 3). The schema counts characters; the server counts bytes, checks the full email syntax and normalises the address before use.',
};

/** A one-time code of six digits, as an answer field (FiPA Appendix B.1 names it `otp`). */
export const sixDigitOtp: JsonSchema = {
  type: 'string',
  pattern: '^[0-9]{6}$',
  description: 'The six digits the authenticator app shows.',
};

/** A WebAuthn response: `PublicKeyCredential.toJSON()` as a JSON string, as on the FiPA transport. */
export function webauthnResponse(maxLength: number, kind: 'assertion' | 'attestation'): JsonSchema {
  const response: JsonSchema =
    kind === 'assertion'
      ? openObject(
          {
            clientDataJSON: { type: 'string' },
            authenticatorData: { type: 'string' },
            signature: { type: 'string' },
            userHandle: { type: 'string' },
          },
          ['clientDataJSON', 'authenticatorData', 'signature']
        )
      : openObject(
          {
            clientDataJSON: { type: 'string' },
            attestationObject: { type: 'string' },
            transports: { type: 'array', items: { type: 'string' } },
          },
          ['clientDataJSON', 'attestationObject']
        );
  return {
    type: 'string',
    minLength: 2,
    maxLength,
    contentMediaType: 'application/json',
    contentSchema: openObject(
      {
        id: { type: 'string' },
        rawId: { type: 'string' },
        type: { const: 'public-key' },
        response,
        authenticatorAttachment: { type: 'string' },
        clientExtensionResults: { type: 'object' },
      },
      ['id', 'rawId', 'type', 'response', 'clientExtensionResults']
    ),
    description: `The ${
      kind === 'assertion' ? 'authentication' : 'registration'
    } response, \`PublicKeyCredential.toJSON()\` (WebAuthn Level 3), as a JSON string. It is a string on both transports, so a form post carries it in one field (ADR-017 Decision 3).`,
  };
}
