import { grammarStep, type StepParams } from '@qauth-labs/server-step-grammar';

import type { AccountDirectory, PasskeyCeremonies, SignInAccount } from '../ports';
import { fromStore, SignInStoreUnavailableError } from '../store';
import type { StepHandler, StepVerdict } from './handler';

/** What the passkey step needs. */
export interface PasskeyStepDependencies {
  readonly passkeys: PasskeyCeremonies;
  readonly accounts: AccountDirectory;
}

/** Every refused assertion, whatever the reason: nothing says why, or whose. */
const REFUSED: StepVerdict = Object.freeze({
  kind: 'refused',
  error: 'invalid_credentials',
  audit: Object.freeze({ reason: 'invalid_credentials' }),
});

/** Whether `account` holds a passkey it can use: bound and not disabled. */
export function holdsUsablePasskey(account: SignInAccount): boolean {
  return account.factors.some((factor) => factor.type === 'passkey' && !factor.disabled);
}

/** The request options a port returned, checked against the step grammar: anything else is a store fault. */
function checkedRequestOptions(options: unknown): StepParams<'webauthn_get'> {
  const parsed = grammarStep('webauthn_get').params.safeParse(options);
  if (!parsed.success) {
    throw new SignInStoreUnavailableError('passkeys', new Error('not request options'));
  }
  return Object.freeze(parsed.data as StepParams<'webauthn_get'>);
}

/**
 * The `webauthn_get` step (#651; ADR-017 Decisions 4 and 10,
 * `graphs/flows/core/passkey/flow.yaml`): a passkey, the strongest first
 * factor. It is discoverable, so before any identifier it is the preferred
 * step of the first response, with the password and the identifier beside
 * it; with one, it is offered beside the password. Its params name no
 * account, so the offer is the same for every account.
 *
 * Its params are a WebAuthn ceremony (`ceremony`): the engine holds them in
 * the transaction and hands this step the ceremony's key. An assertion is
 * verified by the port against the realm's passkeys, after it took the
 * ceremony; one whose signed authenticator data does not carry the
 * user-verification (UV) flag is refused here again, whatever the port said
 * of the rest, so `["pop","mfa"]` always means a verified user. The account
 * the passkey names is read for the engine's checks: an enabled one, and one
 * subject per transaction. Every refusal is `invalid_credentials`.
 *
 * The ladder of PRO-12 has no passkey counter (ADR-017 Decision 7): an
 * assertion names no account before it is verified, and cannot be guessed.
 * The engine reserves the answer on the limiters first, as every credential.
 */
export function createPasskeyStep(deps: PasskeyStepDependencies): StepHandler<'webauthn_get'> {
  const handler: StepHandler<'webauthn_get'> = {
    step: 'webauthn_get',
    role: 'first_factor',
    factor: 'passkey',
    discoverable: true,
    ceremony: true,
    usableBy: holdsUsablePasskey,
    async params({ realmId, clientId, ceremonyKey }) {
      if (ceremonyKey === undefined) {
        throw new Error('sign-in engine: a passkey step offered without its ceremony');
      }
      return checkedRequestOptions(
        await fromStore('passkeys', () =>
          deps.passkeys.startAssertion({ realmId, clientId, key: ceremonyKey })
        )
      );
    },
    personal: ({ identifier }) => (identifier === undefined ? {} : { identifier }),
    async verify({ realmId, clientId, ceremonyKey }, read) {
      // No ceremony held for the step: nothing the answer could be checked
      // against, so it is refused like any other.
      if (ceremonyKey === undefined) return REFUSED;
      const outcome: unknown = await fromStore('passkeys', () =>
        deps.passkeys.verifyAssertion({
          realmId,
          clientId,
          key: ceremonyKey,
          response: read.answer.webauthn_response,
        })
      );
      const verified = outcome as Partial<{ kind: string; userId: unknown; userVerified: unknown }>;
      if (verified?.kind === 'refused') return REFUSED;
      if (
        verified?.kind !== 'verified' ||
        typeof verified.userId !== 'string' ||
        verified.userId.length === 0 ||
        typeof verified.userVerified !== 'boolean'
      ) {
        throw new SignInStoreUnavailableError('passkeys', new Error('not an assertion outcome'));
      }
      // The UV flag of the signed authenticator data (ADR-017 Decision 10):
      // without it the passkey proves possession alone, which never signs a
      // person in.
      if (verified.userVerified !== true) return REFUSED;
      const userId = verified.userId;
      const account = await fromStore('accounts', () =>
        deps.accounts.findByUserId(realmId, userId)
      );
      if (account === null || account.userId !== userId) return REFUSED;
      return Object.freeze({
        kind: 'proved',
        account: Object.freeze({
          userId: account.userId,
          enabled: account.enabled,
          verified: account.verified,
          ...(account.identifier === undefined ? {} : { identifier: account.identifier }),
        }),
      });
    },
  };
  return Object.freeze(handler);
}
