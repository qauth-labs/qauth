import { randomBytes } from 'node:crypto';

import type {
  PasskeyAssertion,
  PasskeyBinding,
  PasskeyCeremonies,
  PasskeyRegistration,
  PasskeyRegistrationStart,
} from '../lib/ports';

/**
 * TEST SUPPORT — the passkey ceremonies in memory (#651): ceremonies taken
 * once, and passkeys that "sign" by echoing the challenge. Not WebAuthn: a
 * test builds an answer with {@link fakeAssertion} or
 * {@link fakeRegistration}, and says whether its authenticator data carries
 * the UV flag.
 */

/** The RP ID every ceremony runs under. */
export const MEMORY_PASSKEY_RP_ID = 'auth.example.com';

/** The name the memory gives an account with no address (#655). */
export const MEMORY_PASSKEY_ACCOUNT_NAME = 'account-memory';

/** One passkey the memory holds. */
export interface MemoryPasskey {
  readonly id: string;
  readonly userId: string;
  disabled: boolean;
}

interface Ceremony {
  readonly kind: 'assertion' | 'registration';
  readonly challenge: string;
  readonly userId?: string;
}

/** What a fake answer carries in place of a signature. */
interface FakeAnswer {
  readonly id: string;
  readonly challenge: string;
  readonly userVerified: boolean;
}

export interface MemoryPasskeys extends PasskeyCeremonies {
  readonly passkeys: Map<string, MemoryPasskey>;
  /** Every ceremony held, by key: one taken is gone. */
  readonly ceremonies: Map<string, Ceremony>;
  /** Every binding notice, in order. */
  readonly notices: { readonly realmId: string; readonly userId: string }[];
  /** Every call, by name, in order. */
  readonly calls: string[];
  /** Called once a passkey is bound, for the test's directory to show it. */
  onBind?: (passkey: MemoryPasskey) => void;
  /** Report the next assertion's UV flag as this, whatever the answer says: a port that lies. */
  forceUserVerified?: boolean;
  /** The account a binding finds: `account_disabled` or `subject_mismatch` refuse it. */
  bindRefusal?: 'account_disabled' | 'subject_mismatch';
}

/** The challenge of the ceremony `params` offered: the request options' or the creation options'. */
export function offeredChallenge(params: unknown): string {
  const value = params as { challenge?: unknown; options?: { challenge?: unknown } };
  const challenge = value.challenge ?? value.options?.challenge;
  if (typeof challenge !== 'string') throw new Error('no challenge offered');
  return challenge;
}

/** A `webauthn_response` for an assertion: `PublicKeyCredential.toJSON()` in shape, the fake's in content. */
export function fakeAssertion(
  credentialId: string,
  params: unknown,
  options: { readonly userVerified?: boolean } = {}
): string {
  return JSON.stringify({
    id: credentialId,
    rawId: credentialId,
    type: 'public-key',
    response: {
      clientDataJSON: offeredChallenge(params),
      authenticatorData: options.userVerified === false ? 'up' : 'up+uv',
      signature: 'fake',
    },
    clientExtensionResults: {},
  });
}

/** A `webauthn_response` for a registration of a new passkey `credentialId`. */
export function fakeRegistration(
  credentialId: string,
  params: unknown,
  options: { readonly userVerified?: boolean } = {}
): string {
  return JSON.stringify({
    id: credentialId,
    rawId: credentialId,
    type: 'public-key',
    response: {
      clientDataJSON: offeredChallenge(params),
      attestationObject: options.userVerified === false ? 'up' : 'up+uv',
    },
    clientExtensionResults: {},
  });
}

function readFake(response: string, kind: 'assertion' | 'registration'): FakeAnswer | null {
  try {
    const value = JSON.parse(response) as {
      id?: unknown;
      response?: {
        clientDataJSON?: unknown;
        authenticatorData?: unknown;
        attestationObject?: unknown;
      };
    };
    const flags =
      kind === 'assertion' ? value.response?.authenticatorData : value.response?.attestationObject;
    if (typeof value.id !== 'string' || typeof value.response?.clientDataJSON !== 'string') {
      return null;
    }
    return {
      id: value.id,
      challenge: value.response.clientDataJSON,
      userVerified: flags === 'up+uv',
    };
  } catch {
    return null;
  }
}

/** The passkey ceremonies in memory. */
export function createMemoryPasskeys(initial: readonly MemoryPasskey[] = []): MemoryPasskeys {
  const passkeys = new Map(initial.map((passkey) => [passkey.id, { ...passkey }]));
  const ceremonies = new Map<string, Ceremony>();
  const notices: { realmId: string; userId: string }[] = [];
  const calls: string[] = [];
  const challenge = () => randomBytes(32).toString('base64url');
  const take = (key: string, kind: Ceremony['kind']): Ceremony | undefined => {
    const ceremony = ceremonies.get(key);
    ceremonies.delete(key);
    return ceremony?.kind === kind ? ceremony : undefined;
  };

  const memory: MemoryPasskeys = {
    passkeys,
    ceremonies,
    notices,
    calls,
    async startAssertion({ key }) {
      calls.push('startAssertion');
      const started = challenge();
      ceremonies.set(key, { kind: 'assertion', challenge: started });
      return {
        challenge: started,
        rpId: MEMORY_PASSKEY_RP_ID,
        timeout: 300_000,
        userVerification: 'required',
      };
    },
    async verifyAssertion({ key, response }): Promise<PasskeyAssertion> {
      calls.push('verifyAssertion');
      const ceremony = take(key, 'assertion');
      const answer = readFake(response, 'assertion');
      if (ceremony === undefined || answer === null || answer.challenge !== ceremony.challenge) {
        return { kind: 'refused' };
      }
      const passkey = passkeys.get(answer.id);
      if (passkey === undefined || passkey.disabled) return { kind: 'refused' };
      const userVerified = memory.forceUserVerified ?? answer.userVerified;
      // The provider refuses a sign-in assertion without UV; a port that lies
      // about it (`forceUserVerified`) is how a test reaches the engine's own check.
      if (!userVerified && memory.forceUserVerified === undefined) return { kind: 'refused' };
      return { kind: 'verified', userId: passkey.userId, userVerified };
    },
    async startRegistration({ key, userId, identifier }): Promise<PasskeyRegistrationStart> {
      calls.push('startRegistration');
      const started = challenge();
      ceremonies.set(key, {
        kind: 'registration',
        challenge: started,
        ...(userId === undefined ? {} : { userId }),
      });
      // A registration's ceremony (#655) names no account, and excludes nothing.
      const excluded =
        userId === undefined
          ? []
          : [...passkeys.values()].filter((passkey) => passkey.userId === userId);
      const name = identifier ?? MEMORY_PASSKEY_ACCOUNT_NAME;
      return {
        options: {
          challenge: started,
          rp: { id: MEMORY_PASSKEY_RP_ID, name: 'Example' },
          pubKeyCredParams: [
            { type: 'public-key', alg: -8 },
            { type: 'public-key', alg: -7 },
            { type: 'public-key', alg: -257 },
          ],
          timeout: 300_000,
          authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
          attestation: 'none',
        },
        personal: {
          user: { id: 'dXNlci1oYW5kbGU', name, displayName: name },
          excludeCredentials: excluded.map((passkey) => ({ type: 'public-key', id: passkey.id })),
        },
      };
    },
    async verifyRegistration({ key, userId, response }): Promise<PasskeyRegistration> {
      calls.push('verifyRegistration');
      const ceremony = take(key, 'registration');
      const answer = readFake(response, 'registration');
      if (
        ceremony === undefined ||
        ceremony.userId !== userId ||
        answer === null ||
        answer.challenge !== ceremony.challenge ||
        !answer.userVerified
      ) {
        return { kind: 'refused' };
      }
      return { kind: 'verified', registration: JSON.stringify({ id: answer.id, userId }) };
    },
    async bind({ realmId, userId, registration }): Promise<PasskeyBinding> {
      calls.push('bind');
      if (memory.bindRefusal !== undefined) return { kind: 'refused', reason: memory.bindRefusal };
      const held = JSON.parse(registration) as { id: string; userId: string };
      if (held.userId !== userId) return { kind: 'refused', reason: 'subject_mismatch' };
      if (passkeys.has(held.id)) return { kind: 'refused', reason: 'credential_exists' };
      const passkey: MemoryPasskey = { id: held.id, userId, disabled: false };
      passkeys.set(held.id, passkey);
      notices.push({ realmId, userId });
      memory.onBind?.(passkey);
      return { kind: 'bound' };
    },
  };
  return memory;
}
