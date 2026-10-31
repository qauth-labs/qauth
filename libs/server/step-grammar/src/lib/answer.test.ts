import { stepNamed } from '@qauth-labs/shared-interaction-contract';
import { describe, expect, it } from 'vitest';

import { StepAnswerError, type StepAnswerErrorCode } from './answer-error';
import { createFipaMapper, FIPA_SERVES_ALL } from './fipa-mapper';
import { createInteractionMapper } from './interaction-mapper';
import type { StepOffer } from './offer';
import {
  FIPA_STEP_NAMES,
  grammarStep,
  INTERACTION_ONLY_STEP_NAMES,
  STEP_NAMES,
  STEP_URNS,
  type StepName,
} from './steps';

/**
 * Reading an answer, on both transports: only a step the transport
 * presented may be answered, only that step's answer members are taken from
 * the body, the parse is strict, and the answer must fit the params the step
 * was offered with.
 */

const interaction = createInteractionMapper();
const fipa = createFipaMapper(FIPA_SERVES_ALL);
/** A client that lists every step the FiPA endpoint may serve. */
const LISTING = { interactionTypesSupported: FIPA_STEP_NAMES.map((name) => STEP_URNS[name]) };

/** The offer of a step's example, as the contract shows it, with no alternative. */
function exampleOffer(name: StepName): StepOffer {
  const { step } = stepNamed(name).example;
  return {
    current: {
      step: name,
      params: step.params,
      ...(step.error === undefined ? {} : { error: step.error }),
    },
    alternatives: [],
  } as StepOffer;
}

/** A step's example answer as a form post sends it: every value a string. */
function asForm(answer: Readonly<Record<string, unknown>>): Record<string, string> {
  return Object.fromEntries(Object.entries(answer).map(([key, value]) => [key, String(value)]));
}

const exampleAnswer = (name: StepName) =>
  stepNamed(name).example.answer as Readonly<Record<string, unknown>>;

function expectRefusal(run: () => unknown, code: StepAnswerErrorCode) {
  let caught: unknown;
  try {
    run();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(StepAnswerError);
  expect((caught as StepAnswerError).code).toBe(code);
  return caught as StepAnswerError;
}

describe('an answer on the Interaction API', () => {
  it.each(STEP_NAMES)(
    '%s: the contract’s example answer is read, as JSON and as a form post',
    (name) => {
      const offer = exampleOffer(name);
      const expected = grammarStep(name).answer.parse(exampleAnswer(name));
      const fromJson = interaction.readAnswer(offer, STEP_URNS[name], exampleAnswer(name), 'json');
      expect(fromJson).toStrictEqual({
        step: name,
        params: offer.current.params,
        answer: expected,
      });
      const fromForm = interaction.readAnswer(offer, STEP_URNS[name], asForm(exampleAnswer(name)));
      expect(fromForm).toStrictEqual(fromJson);
    }
  );

  it('takes an answer to an alternative the step read named, with that step’s params', () => {
    const offer = {
      current: { step: 'totp', params: { digits: 6 } },
      alternatives: [{ step: 'recovery_code', params: {} }],
    } as StepOffer;
    expect(
      interaction.readAnswer(offer, STEP_URNS.recovery_code, {
        recovery_code: 'k7qd-2mvw-x4ra-p6tn',
      })
    ).toStrictEqual({
      step: 'recovery_code',
      params: {},
      answer: { recovery_code: 'k7qd-2mvw-x4ra-p6tn' },
    });
  });

  it('reads a form post’s booleans, and an unchecked box as false', () => {
    const offer = exampleOffer('consent');
    const read = (form: Record<string, unknown>, encoding?: 'json' | 'form') =>
      interaction.readAnswer(offer, STEP_URNS.consent, form, encoding).answer;
    expect(read({ decision: 'allow', remember: 'true' })).toEqual({
      decision: 'allow',
      remember: true,
    });
    expect(read({ decision: 'allow' })).toEqual({ decision: 'allow', remember: false });
    expectRefusal(() => read({ decision: 'allow', remember: 'yes' }), 'invalid_answer');
    // A JSON body has real booleans.
    expectRefusal(() => read({ decision: 'allow', remember: 'true' }, 'json'), 'invalid_answer');
  });
});

describe('an answer on the FiPA endpoint', () => {
  it.each(FIPA_STEP_NAMES)('%s: the contract’s example answer is read from the form', (name) => {
    const offer = exampleOffer(name);
    expect(fipa.readAnswer(offer, LISTING, STEP_URNS[name], asForm(exampleAnswer(name)))).toEqual({
      step: name,
      params: offer.current.params,
      answer: grammarStep(name).answer.parse(exampleAnswer(name)),
    });
  });

  it('takes an answer to the alternative that replaced a preferred step the client cannot answer', () => {
    const offer = {
      current: { step: 'webauthn_get', params: stepNamed('webauthn_get').example.step.params },
      alternatives: [{ step: 'password', params: {} }],
      required: false,
    } as StepOffer;
    const listing = { interactionTypesSupported: [STEP_URNS.password] };
    expect(
      fipa.readAnswer(offer, listing, STEP_URNS.password, { password: 'correct horse' })
    ).toEqual({ step: 'password', params: {}, answer: { password: 'correct horse' } });
    expectRefusal(
      () => fipa.readAnswer(offer, listing, STEP_URNS.webauthn_get, { webauthn_response: '{}' }),
      'not_offered'
    );
  });
});

describe('an answer to a step the transport did not present', () => {
  it('is refused: a step not offered, and a name no step has', () => {
    const offer = exampleOffer('password');
    expectRefusal(
      () => interaction.readAnswer(offer, STEP_URNS.identifier, { login_hint: 'a@b.example' }),
      'not_offered'
    );
    expectRefusal(
      () => interaction.readAnswer(offer, 'urn:qauth:ia:password:v1', { password: 'x' }),
      'not_offered'
    );
    expectRefusal(
      () => interaction.readAnswer(offer, 42 as never, { password: 'x' }),
      'not_offered'
    );
  });

  it('is refused on the FiPA endpoint for a step it left out', () => {
    const offer = {
      current: { step: 'password', params: {} },
      alternatives: [
        { step: 'recovery_code', params: {} },
        { step: 'password_reset', params: {} },
      ],
    } as StepOffer;
    // Offered by the engine, but only the Interaction API serves it.
    expect(INTERACTION_ONLY_STEP_NAMES).toContain('recovery_code');
    expectRefusal(
      () =>
        fipa.readAnswer(offer, LISTING, STEP_URNS.recovery_code, {
          recovery_code: 'k7qd-2mvw-x4ra-p6tn',
        }),
      'not_offered'
    );
    // Served, but the client did not list it.
    expectRefusal(
      () =>
        fipa.readAnswer(
          offer,
          { interactionTypesSupported: [STEP_URNS.password] },
          STEP_URNS.password_reset,
          {}
        ),
      'not_offered'
    );
    // After redirect_to_web, nothing may be answered.
    expectRefusal(
      () => fipa.readAnswer(exampleOffer('consent'), LISTING, STEP_URNS.consent, {}),
      'not_offered'
    );
  });

  it('is refused on the Interaction API for a step its configuration does not serve', () => {
    const narrow = createInteractionMapper({ serves: ['password', 'identifier'] });
    const offer = {
      current: { step: 'password', params: {} },
      alternatives: [{ step: 'recovery_code', params: {} }],
    } as StepOffer;
    expectRefusal(
      () =>
        narrow.readAnswer(offer, STEP_URNS.recovery_code, { recovery_code: 'k7qd-2mvw-x4ra-p6tn' }),
      'not_offered'
    );
  });
});

describe('the members of an answer', () => {
  it('are only the answered step’s: the envelope and another step’s fields stay behind', () => {
    const offer = exampleOffer('totp');
    const read = interaction.readAnswer(offer, STEP_URNS.totp, {
      type: STEP_URNS.totp,
      csrf: 'Y3NyZi10b2tlbi1vZi0zMi1yYW5kb20tYnl0ZXMhIQ',
      otp: '482913',
      password: 'correct horse',
      new_password: 'another one',
      message: 'Remember this device',
    });
    expect(read.answer).toStrictEqual({ otp: '482913' });
    const form = fipa.readAnswer(offer, LISTING, STEP_URNS.totp, {
      auth_session: 'YXV0aC1zZXNzaW9uLWhhbmRsZS1vZi0zMi1ieXRlcyE',
      qauth_interaction_type: STEP_URNS.totp,
      client_id: 'app',
      otp: '482913',
      login_hint: 'alice@example.com',
    });
    expect(form.answer).toStrictEqual({ otp: '482913' });
  });

  it('are parsed strictly, and the refusal names no value', () => {
    const offer = exampleOffer('password');
    const secret = `${'p'.repeat(256)}x`;
    const error = expectRefusal(
      () => interaction.readAnswer(offer, STEP_URNS.password, { password: secret }),
      'invalid_answer'
    );
    expect(error.message).not.toContain('ppp');
    expectRefusal(
      () => interaction.readAnswer(offer, STEP_URNS.password, { password: ['a', 'b'] }),
      'invalid_answer'
    );
    expectRefusal(
      () => interaction.readAnswer(offer, STEP_URNS.password, 'password=x'),
      'invalid_answer'
    );
    expectRefusal(() => interaction.readAnswer(offer, STEP_URNS.password, null), 'invalid_answer');
  });
});

describe('an answer and the params it was offered with', () => {
  const emailCode = (length: 6 | 8) =>
    ({
      current: {
        step: 'email_code',
        params: { purpose: 'verify_account', length, expires_in: 600, resend_after: 60 },
      },
      alternatives: [],
    }) as StepOffer;

  it('carries a code of exactly the offered length', () => {
    expect(
      fipa.readAnswer(emailCode(8), LISTING, STEP_URNS.email_code, { otp: '48291377' }).answer
    ).toEqual({ otp: '48291377' });
    expectRefusal(
      () => fipa.readAnswer(emailCode(8), LISTING, STEP_URNS.email_code, { otp: '482913' }),
      'invalid_answer'
    );
    expectRefusal(
      () => interaction.readAnswer(emailCode(6), STEP_URNS.email_code, { otp: '48291377' }),
      'invalid_answer'
    );
    // No code at all asks for a new one, whatever the length.
    expect(interaction.readAnswer(emailCode(8), STEP_URNS.email_code, {}).answer).toEqual({});
  });

  it('carries a response when the passkey enrolment may not be declined', () => {
    const params = stepNamed('webauthn_create').example.step.params as Record<string, unknown>;
    const offer = (optional: boolean) =>
      ({
        current: { step: 'webauthn_create', params: { ...params, optional } },
        alternatives: [],
      }) as unknown as StepOffer;
    expectRefusal(
      () => interaction.readAnswer(offer(false), STEP_URNS.webauthn_create, {}),
      'invalid_answer'
    );
    expectRefusal(
      () => fipa.readAnswer(offer(false), LISTING, STEP_URNS.webauthn_create, {}),
      'invalid_answer'
    );
    // An offer the person may decline: no response declines it.
    expect(interaction.readAnswer(offer(true), STEP_URNS.webauthn_create, {}).answer).toEqual({});
    expect(
      interaction.readAnswer(
        offer(false),
        STEP_URNS.webauthn_create,
        exampleAnswer('webauthn_create')
      ).answer
    ).toEqual(exampleAnswer('webauthn_create'));
  });

  it('is required: an empty answer to a step that needs one is refused', () => {
    expectRefusal(
      () => interaction.readAnswer(exampleOffer('identifier'), STEP_URNS.identifier, {}),
      'invalid_answer'
    );
    expectRefusal(
      () => fipa.readAnswer(exampleOffer('totp'), LISTING, STEP_URNS.totp, {}),
      'invalid_answer'
    );
    expectRefusal(
      () => interaction.readAnswer(exampleOffer('recovery_codes'), STEP_URNS.recovery_codes, {}),
      'invalid_answer'
    );
  });
});
