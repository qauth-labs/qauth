import { RESTART_NOTICES, stepByUrn, stepUrn } from '@qauth-labs/shared-interaction-contract';
import { describe, expect, it } from 'vitest';

import {
  listedUpstreamProvider,
  refusedLinkStep,
  refusedUpstreamStep,
  restartedStep,
  restartNoticeOf,
  type TransactionEndCause,
  upstreamRefusalCodeOf,
} from './interaction-outcomes';
import { type InteractionStep, interactionStepSchema } from './interaction-record';

/**
 * THE OUTCOMES THE CEREMONY PAGE DRAWS (#1081): the notice of a restarted
 * sign-in, a provider that did not sign the person in, and a refused link,
 * as the record keeps them. The Interaction API's integration suites drive
 * them end to end.
 */

const UPSTREAM = stepUrn('upstream');
const IDENTIFIER = stepUrn('identifier');
const PASSKEY = stepUrn('webauthn_get');
const CORP = { provider: 'oidc_corp', name: 'Corp SSO' } as const;
const PARTNER = { provider: 'oidc_partner', name: 'Partner' } as const;

describe('restartNoticeOf (#1081)', () => {
  it('says a burned code and another account by their names', () => {
    expect(restartNoticeOf('code_burned')).toBe('code_burned');
    expect(restartNoticeOf('subject_mismatch')).toBe('subject_mismatch');
  });

  it('says every other end as expired, whatever it says of the account', () => {
    const others: TransactionEndCause[] = [
      'transaction_expired',
      'transaction_invalid',
      'account_disabled',
      'registration_conflict',
      'reset_since',
      'authentication_stale',
    ];
    for (const cause of others) expect(restartNoticeOf(cause)).toBe('expired');
  });

  it('answers only notices of the contract', () => {
    for (const cause of ['code_burned', 'subject_mismatch', 'account_disabled'] as const) {
      expect(RESTART_NOTICES).toContain(restartNoticeOf(cause));
    }
  });
});

describe('refusedUpstreamStep (#1081)', () => {
  const FIRST_STEP: InteractionStep = {
    name: IDENTIFIER,
    params: { login_hint_shown: false },
    alternatives: [PASSKEY, UPSTREAM],
    alternativeParams: {
      [PASSKEY]: { challenge: 'c' },
      [UPSTREAM]: { providers: [CORP, PARTNER] },
    },
  };

  it('makes the upstream step current with the error and the provider, the others behind it in order', () => {
    const refused = refusedUpstreamStep(FIRST_STEP, CORP, 'provider_declined');
    expect(refused).toEqual({
      name: UPSTREAM,
      params: { providers: [CORP, PARTNER], error_provider: CORP },
      alternatives: [IDENTIFIER, PASSKEY],
      alternativeParams: {
        [IDENTIFIER]: { login_hint_shown: false },
        [PASSKEY]: { challenge: 'c' },
      },
      error: 'provider_declined',
    });
    // A step the record keeps: the error is the upstream step's own.
    expect(interactionStepSchema.parse(refused)).toEqual(refused);
  });

  it('replaces an earlier refusal of a current upstream step', () => {
    const first = refusedUpstreamStep(FIRST_STEP, CORP, 'provider_declined');
    const second = refusedUpstreamStep(first as InteractionStep, PARTNER, 'provider_error');
    expect(second).toMatchObject({
      name: UPSTREAM,
      params: { providers: [CORP, PARTNER], error_provider: PARTNER },
      alternatives: [IDENTIFIER, PASSKEY],
      error: 'provider_error',
    });
  });

  it('leaves out the params of a step that has none', () => {
    const refused = refusedUpstreamStep(
      { name: IDENTIFIER, params: {}, alternatives: [UPSTREAM] },
      CORP,
      'provider_error'
    );
    expect(refused).toEqual({
      name: UPSTREAM,
      params: { error_provider: CORP },
      alternatives: [IDENTIFIER],
      error: 'provider_error',
    });
  });

  it('answers nothing for a step that offers no upstream step', () => {
    expect(
      refusedUpstreamStep(
        { name: IDENTIFIER, params: {}, alternatives: [] },
        CORP,
        'provider_error'
      )
    ).toBeUndefined();
  });
});

describe('listedUpstreamProvider (#1081)', () => {
  it('finds a provider by its type in the upstream step, current or an alternative', () => {
    const current: InteractionStep = {
      name: UPSTREAM,
      params: { providers: [CORP, PARTNER] },
      alternatives: [],
    };
    expect(listedUpstreamProvider(current, PARTNER.provider)).toEqual(PARTNER);
    const alternative: InteractionStep = {
      name: IDENTIFIER,
      params: {},
      alternatives: [UPSTREAM],
      alternativeParams: { [UPSTREAM]: { providers: [CORP] } },
    };
    expect(listedUpstreamProvider(alternative, CORP.provider)).toEqual(CORP);
  });

  it('finds nothing for a provider the step does not list, or a step without one', () => {
    const current: InteractionStep = {
      name: UPSTREAM,
      params: { providers: [CORP] },
      alternatives: [],
    };
    expect(listedUpstreamProvider(current, 'oidc_other')).toBeUndefined();
    expect(
      listedUpstreamProvider({ name: IDENTIFIER, params: {}, alternatives: [] }, CORP.provider)
    ).toBeUndefined();
  });
});

describe('refusedLinkStep (#1081)', () => {
  it('names the provider and the reason, offers no new account, and nothing of the identity', () => {
    for (const reason of ['already_linked', 'provider_linked', 'account_unavailable'] as const) {
      const step = refusedLinkStep(CORP, reason);
      expect(step).toEqual({
        name: stepUrn('upstream_link'),
        params: { provider: CORP, create: false },
        alternatives: [],
        error: reason,
      });
      expect(interactionStepSchema.parse(step)).toEqual(step);
    }
  });
});

describe('upstreamRefusalCodeOf (#1106)', () => {
  const STEP: InteractionStep = {
    name: IDENTIFIER,
    params: {},
    alternatives: [UPSTREAM],
    alternativeParams: { [UPSTREAM]: { providers: [CORP] } },
  };

  it('says what the provider did, and a throttle and a store that could not answer', () => {
    expect(upstreamRefusalCodeOf('declined')).toBe('provider_declined');
    for (const reason of [
      'provider_error',
      'invalid_response',
      'method_fault',
      'verification_refused',
    ]) {
      expect(upstreamRefusalCodeOf(reason), reason).toBe('provider_error');
    }
    expect(upstreamRefusalCodeOf('upstream_unavailable')).toBe('provider_unavailable');
    expect(upstreamRefusalCodeOf('throttled')).toBe('too_many_requests');
    expect(upstreamRefusalCodeOf('unavailable')).toBe('service_unavailable');
  });

  it('says unknown_identity for every reason that depends on the account, and for one it does not know', () => {
    for (const reason of [
      'unknown_identity',
      'credential_invalid',
      'issuer_mismatch',
      'credential_disabled',
      'sign_up_disabled',
      'verification_unavailable',
      'invalid_answer',
      'step_not_available',
      'a_reason_added_later',
    ]) {
      expect(upstreamRefusalCodeOf(reason), reason).toBe('unknown_identity');
    }
  });

  it('answers nothing for a callback with no interaction left to go back to', () => {
    expect(upstreamRefusalCodeOf('transaction_mismatch')).toBeNull();
    expect(upstreamRefusalCodeOf('interaction_expired')).toBeNull();
  });

  it("answers only the upstream step's errors, each a step the record keeps", () => {
    const errors = stepByUrn(UPSTREAM)?.errors ?? [];
    for (const reason of [
      'declined',
      'method_fault',
      'upstream_unavailable',
      'throttled',
      'unavailable',
      'credential_disabled',
    ]) {
      const code = upstreamRefusalCodeOf(reason);
      expect(code).not.toBeNull();
      expect(errors).toContain(code);
      const refused = refusedUpstreamStep(STEP, CORP, code as NonNullable<typeof code>);
      expect(interactionStepSchema.safeParse(refused).success, reason).toBe(true);
    }
  });
});

describe('restartedStep (#1106)', () => {
  it("drops an earlier refusal's error and provider, and keeps the rest", () => {
    const refused = refusedUpstreamStep(
      {
        name: IDENTIFIER,
        params: {},
        alternatives: [UPSTREAM],
        alternativeParams: { [UPSTREAM]: { providers: [CORP] } },
      },
      CORP,
      'provider_declined'
    ) as InteractionStep;
    const restarted = restartedStep(refused);
    expect(restarted).not.toHaveProperty('error');
    expect(restarted.params).toEqual({ providers: [CORP] });
    expect(restarted.alternatives).toEqual(refused.alternatives);
    expect(interactionStepSchema.safeParse(restarted).success).toBe(true);
  });

  it('keeps a step with no error as it is', () => {
    const step: InteractionStep = { name: IDENTIFIER, params: {}, alternatives: [UPSTREAM] };
    expect(restartedStep(step)).toBe(step);
  });

  it('drops the error of a step that is not the upstream step, and nothing else', () => {
    const step: InteractionStep = {
      name: stepUrn('password'),
      params: {},
      alternatives: [],
      error: 'invalid_credentials',
    };
    expect(restartedStep(step)).toEqual({
      name: stepUrn('password'),
      params: {},
      alternatives: [],
    });
  });
});
