import { INTERACTION_API_VERSION, stepNamed } from '@qauth-labs/shared-interaction-contract';
import { describe, expect, expectTypeOf, it } from 'vitest';

import {
  createFipaMapper,
  FIPA_SERVES_ALL,
  FIPA_STEP_MAPPERS,
  type FipaInsufficientAuthorization,
  type FipaRoundContext,
  type FipaStepUrn,
  INTERACTION_ONLY,
} from './fipa-mapper';
import { StepMappingError, type StepMappingErrorCode } from './mapping-error';
import type { StepOffer } from './offer';
import {
  FIPA_STEP_NAMES,
  INTERACTION_ONLY_STEP_NAMES,
  STEP_NAMES,
  STEP_URNS,
  type StepName,
} from './steps';

const ISS = 'https://auth.acme.example';
const AUTH_SESSION = 'cm91bmQtaGFuZGxlLW9mLTMyLXJhbmRvbS1ieXRlcyE';
/** A client that lists every step the FiPA endpoint may serve. */
const FIPA_URNS = FIPA_STEP_NAMES.map((name) => STEP_URNS[name]);

/** A client that lists the FiPA steps and every step only the Interaction API serves, but one: 16 entries, the limit. */
const MOST_URNS = [
  ...FIPA_URNS,
  ...INTERACTION_ONLY_STEP_NAMES.slice(0, 7).map((name) => STEP_URNS[name]),
];

const round = (supported: readonly string[] = FIPA_URNS): FipaRoundContext => ({
  issuer: ISS,
  newAuthSession: () => AUTH_SESSION,
  interactionTypesSupported: supported,
});

/** A step's example params, as offered without an error: `new_password` without `reasons`. */
function paramsOf(name: StepName): never {
  const params = { ...(stepNamed(name).example.step.params as Record<string, unknown>) };
  delete params['reasons'];
  return params as never;
}
const offerOf = (name: StepName, alternatives: readonly StepName[] = []): StepOffer =>
  ({
    current: { step: name, params: paramsOf(name) },
    alternatives: alternatives.map((alternative) => ({
      step: alternative,
      params: paramsOf(alternative),
    })),
  }) as StepOffer;

function expectRefusal(run: () => unknown, code: StepMappingErrorCode) {
  let caught: unknown;
  try {
    run();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(StepMappingError);
  expect((caught as StepMappingError).code).toBe(code);
}

const mapper = createFipaMapper(FIPA_SERVES_ALL);
const challenge = (offer: StepOffer, context = round()) => mapper.challenge(offer, context);
const body = (offer: StepOffer, context = round()) =>
  challenge(offer, context).body as FipaInsufficientAuthorization;

describe('the FiPA mapper', () => {
  it('has a mapper for each step ADR-017 lists, and marks every other step', () => {
    expect(Object.keys(FIPA_STEP_MAPPERS)).toEqual(STEP_NAMES);
    for (const name of STEP_NAMES) {
      expect(FIPA_STEP_MAPPERS[name] === INTERACTION_ONLY, name).toBe(
        INTERACTION_ONLY_STEP_NAMES.includes(name as never)
      );
    }
    expect([...mapper.serves]).toEqual(FIPA_STEP_NAMES);
  });

  // ADR-017 Decision 3's wire example: a verify step after a correct password.
  it('answers the email-code example of ADR-017 Decision 3 member for member', () => {
    const response = mapper.challenge(
      {
        current: {
          step: 'email_code',
          params: { purpose: 'verify_account', length: 6, expires_in: 600, resend_after: 60 },
        },
        alternatives: [],
      },
      round()
    );
    expect(response).toStrictEqual({
      status: 403,
      body: {
        error: 'insufficient_authorization',
        iss: ISS,
        auth_session: AUTH_SESSION,
        interaction_type_required: 'urn:qauth:ia:email_code:v1-rc.0',
        qauth_interaction_types_offered: ['urn:qauth:ia:email_code:v1-rc.0'],
        qauth_interaction_params: {
          'urn:qauth:ia:email_code:v1-rc.0': {
            purpose: 'verify_account',
            length: 6,
            expires_in: 600,
            resend_after: 60,
          },
        },
      },
    });
  });

  // The uniform first response of ADR-017 Decision 3: the same for every
  // account, and a wrong password adds only the error.
  it('answers the uniform password step, and a refused password adds only qauth_interaction_error', () => {
    const offer: StepOffer = {
      current: { step: 'password', params: {} },
      alternatives: [{ step: 'password_reset', params: {} }],
    };
    const supported = ['password', 'email_code', 'new_password', 'password_reset'].map(
      (name) => STEP_URNS[name as StepName]
    );
    const first = body(offer, round(supported));
    expect(first).toStrictEqual({
      error: 'insufficient_authorization',
      iss: ISS,
      auth_session: AUTH_SESSION,
      interaction_type_required: 'urn:qauth:ia:password:v1-rc.0',
      qauth_interaction_types_offered: [
        'urn:qauth:ia:password:v1-rc.0',
        'urn:qauth:ia:password_reset:v1-rc.0',
      ],
      qauth_interaction_params: {
        'urn:qauth:ia:password:v1-rc.0': {},
        'urn:qauth:ia:password_reset:v1-rc.0': {},
      },
    });
    const refused = body(
      { ...offer, current: { ...offer.current, error: 'invalid_credentials' } } as StepOffer,
      round(supported)
    );
    expect(refused).toStrictEqual({ ...first, qauth_interaction_error: 'invalid_credentials' });
  });

  it('puts the required step first in the offered list, and only steps the client listed after it', () => {
    const supported = [STEP_URNS.password, STEP_URNS.identifier, 'urn:example:unknown'];
    const answer = body(
      offerOf('password', ['webauthn_get', 'identifier', 'password_reset']),
      round(supported)
    );
    expect(answer.qauth_interaction_types_offered).toEqual([
      STEP_URNS.password,
      STEP_URNS.identifier,
    ]);
    expect(Object.keys(answer.qauth_interaction_params)).toEqual([
      STEP_URNS.password,
      STEP_URNS.identifier,
    ]);
  });

  // The acceptance criterion: `interaction_type_required` always carries a
  // `:v1` step name, in the form ADR-018 §5 requires before 1.0.0: the label
  // `v1-rc.<M>`, the same as every step name's and the Interaction API path's.
  it('always gives interaction_type_required a step name of version 1, one the client listed', () => {
    const versionOne = /^urn:qauth:ia:[a-z][a-z0-9_]{0,62}:v1(?:-rc\.(?:0|[1-9][0-9]*))?$/;
    let answers = 0;
    for (const name of STEP_NAMES) {
      for (const supported of [
        MOST_URNS,
        [STEP_URNS[name]],
        FIPA_STEP_NAMES.map((n) => STEP_URNS[n]),
      ]) {
        for (const serves of [FIPA_STEP_NAMES, FIPA_STEP_NAMES.filter((n) => n !== 'captcha')]) {
          // A bot challenge is offered alone, and never as an alternative.
          const alternatives =
            name === 'captcha'
              ? []
              : STEP_NAMES.filter((other) => other !== name && other !== 'captcha').slice(0, 3);
          let response;
          try {
            response = createFipaMapper({ serves }).challenge(
              offerOf(name, alternatives),
              round(supported)
            );
          } catch (error) {
            expect((error as StepMappingError).code, name).toBe('not_negotiated');
            continue;
          }
          if (response.body.error !== 'insufficient_authorization') continue;
          answers += 1;
          const required = response.body.interaction_type_required;
          expect(required).toMatch(versionOne);
          expect(required.endsWith(`:${INTERACTION_API_VERSION}`)).toBe(true);
          expect(supported).toContain(required);
          expect(response.body.qauth_interaction_types_offered[0]).toBe(required);
        }
      }
    }
    expect(answers).toBeGreaterThan(40);
  });
});

describe('the FiPA mapper and the steps it cannot serve', () => {
  // The acceptance criterion: the FiPA mapper cannot serialise a step only
  // the Interaction API serves. As the required step it answers
  // redirect_to_web (ADR-017 Decision 4); as an alternative it is left out;
  // and no configuration can make the endpoint serve one.
  it.each(INTERACTION_ONLY_STEP_NAMES)(
    '%s: as the required step, gives redirect_to_web and nothing of the step',
    (name) => {
      const response = challenge(
        offerOf(name, ['identifier', 'password']),
        round([...FIPA_URNS, STEP_URNS[name]])
      );
      expect(response).toStrictEqual({ status: 403, body: { error: 'redirect_to_web', iss: ISS } });
      const text = JSON.stringify(response);
      expect(text).not.toContain(STEP_URNS[name]);
      expect(text).not.toContain(name);
    }
  );

  it.each(INTERACTION_ONLY_STEP_NAMES)(
    '%s: as an alternative, is left out of the offered list and the params',
    (name) => {
      const answer = body(
        offerOf('password', [name, 'identifier']),
        round([...FIPA_URNS, STEP_URNS[name]])
      );
      expect(answer.qauth_interaction_types_offered).toEqual([
        STEP_URNS.password,
        STEP_URNS.identifier,
      ]);
      expect(JSON.stringify(answer)).not.toContain(STEP_URNS[name]);
    }
  );

  it('cannot be configured to serve one, at run time or in the type check', () => {
    for (const name of INTERACTION_ONLY_STEP_NAMES) {
      expectRefusal(() => createFipaMapper({ serves: [name as never] }), 'invalid_configuration');
    }
    // @ts-expect-error -- `consent` is not a step the FiPA endpoint may serve.
    expect(() => createFipaMapper({ serves: ['consent'] })).toThrow(StepMappingError);
    expectTypeOf<typeof STEP_URNS.consent>().not.toExtend<FipaStepUrn>();
    expectTypeOf<typeof STEP_URNS.totp>().toExtend<FipaStepUrn>();
  });

  it('answers redirect_to_web for a step this deployment does not serve, or the client did not list', () => {
    const f1 = createFipaMapper({
      serves: ['identifier', 'password', 'email_code', 'new_password', 'password_reset'],
    });
    expect(f1.challenge(offerOf('webauthn_get'), round()).body).toStrictEqual({
      error: 'redirect_to_web',
      iss: ISS,
    });
    expect(challenge(offerOf('totp'), round([STEP_URNS.password])).body).toStrictEqual({
      error: 'redirect_to_web',
      iss: ISS,
    });
    expect(challenge(offerOf('password'), round([])).body).toStrictEqual({
      error: 'redirect_to_web',
      iss: ISS,
    });
  });

  it('never turns a bot challenge into redirect_to_web: the engine throttles instead', () => {
    expectRefusal(
      () => challenge(offerOf('captcha'), round([STEP_URNS.password])),
      'not_negotiated'
    );
    const f1 = createFipaMapper({ serves: ['identifier', 'password'] });
    expectRefusal(() => f1.challenge(offerOf('captcha'), round()), 'not_negotiated');
    expect(body(offerOf('captcha')).interaction_type_required).toBe(STEP_URNS.captcha);
  });

  it('serves the email code purpose the Interaction API does not, confirm_sign_in', () => {
    const params = {
      purpose: 'confirm_sign_in',
      length: 6,
      expires_in: 600,
      resend_after: 60,
    } as const;
    const answer = body({ current: { step: 'email_code', params }, alternatives: [] });
    expect(answer.qauth_interaction_params[STEP_URNS.email_code]).toEqual(params);
  });
});

describe('the FiPA round context', () => {
  it('refuses a malformed issuer, auth_session or list, and a member it does not define', () => {
    const offer = offerOf('password');
    for (const context of [
      { ...round(), issuer: 'auth.acme.example' },
      { ...round(), issuer: 'javascript:alert(1)' },
      { ...round(), newAuthSession: () => 'short' },
      { ...round(), newAuthSession: () => `${AUTH_SESSION}=` },
      { ...round(), newAuthSession: AUTH_SESSION },
      { ...round(), issuer: 'https://user:secret@auth.acme.example' },
      { ...round(), issuer: 'https://user@auth.acme.example' },
      { ...round(), interactionTypesSupported: 'urn:qauth:ia:password:v1-rc.0' },
      { ...round(), error_description: 'Enter your password' },
      { ...round(), issuer: 'https://auth.acme.example/?realm=b' },
      { ...round(), issuer: 'https://auth.acme.example/#x' },
      { ...round(), interactionTypesSupported: Array(17).fill(STEP_URNS.password) },
    ]) {
      expectRefusal(() => mapper.challenge(offer, context as never), 'invalid_configuration');
    }
  });

  it('takes an http issuer, which only a development realm has, and up to 16 listed steps', () => {
    const answer = body(offerOf('password'), {
      ...round(FIPA_STEP_NAMES.map((name) => STEP_URNS[name])),
      issuer: 'http://localhost:3000',
    });
    expect(answer.iss).toBe('http://localhost:3000');
    expect(body(offerOf('password'), round(Array(16).fill(STEP_URNS.password))).error).toBe(
      'insufficient_authorization'
    );
  });

  it('refuses a configuration that names a step twice or has another member', () => {
    expectRefusal(
      () => createFipaMapper({ serves: ['password', 'password'] }),
      'invalid_configuration'
    );
    expectRefusal(() => createFipaMapper({ serves: [], phase: 'F1' } as never), 'unknown_member');
  });
});

describe('the FiPA round’s new auth_session', () => {
  // ADR-017 Decision 6: burn first, then bind. The endpoint binds the handle
  // the body carries, so the mapper makes one only for a body that carries it.
  function counting() {
    const calls: string[] = [];
    const context: FipaRoundContext = {
      ...round(),
      newAuthSession: () => {
        calls.push(AUTH_SESSION);
        return AUTH_SESSION;
      },
    };
    return { calls, context };
  }

  it('is made once for insufficient_authorization, and the body carries it', () => {
    const { calls, context } = counting();
    const answer = mapper.challenge(offerOf('password'), context).body;
    expect(calls).toHaveLength(1);
    expect(answer).toMatchObject({
      error: 'insufficient_authorization',
      auth_session: AUTH_SESSION,
    });
  });

  it('is not made for redirect_to_web, a refused offer or a bot challenge the client did not list', () => {
    const { calls, context } = counting();
    expect(mapper.challenge(offerOf('consent'), context).body.error).toBe('redirect_to_web');
    expectRefusal(
      () =>
        mapper.challenge(
          { current: { step: 'totp', params: { digits: 8 } as never }, alternatives: [] },
          context
        ),
      'invalid_params'
    );
    expectRefusal(
      () =>
        mapper.challenge(offerOf('captcha'), {
          ...context,
          interactionTypesSupported: [STEP_URNS.password],
        }),
      'not_negotiated'
    );
    expect(calls).toHaveLength(0);
  });
});

describe('whether the FiPA endpoint can offer a step', () => {
  it('is true for a step ADR-017 lists, that the deployment serves and the client listed', () => {
    expect(mapper.negotiates('captcha', { interactionTypesSupported: FIPA_URNS })).toBe(true);
    expect(mapper.negotiates('password', round())).toBe(true);
  });

  it('is false for a step the client did not list, the deployment does not serve or only the Interaction API serves', () => {
    expect(mapper.negotiates('captcha', { interactionTypesSupported: [STEP_URNS.password] })).toBe(
      false
    );
    const f1 = createFipaMapper({ serves: ['identifier', 'password'] });
    expect(f1.negotiates('captcha', round())).toBe(false);
    expect(mapper.negotiates('consent', { interactionTypesSupported: [STEP_URNS.consent] })).toBe(
      false
    );
  });

  it('lets the engine keep a bot challenge from a client that cannot answer one', () => {
    // The engine's side of ADR-017 Decision 7: ask first, then throttle that
    // client with its delay and 429 instead of offering the challenge.
    const listing = { interactionTypesSupported: [STEP_URNS.password] };
    expect(mapper.negotiates('captcha', listing)).toBe(false);
    expectRefusal(
      () => challenge(offerOf('captcha'), round(listing.interactionTypesSupported)),
      'not_negotiated'
    );
  });

  it('refuses an unknown step and a malformed listing', () => {
    expectRefusal(() => mapper.negotiates('sms_code' as never, round()), 'unknown_step');
    expectRefusal(
      () => mapper.negotiates('captcha', { interactionTypesSupported: Array(17).fill('x') }),
      'invalid_configuration'
    );
    expectRefusal(() => mapper.negotiates('captcha', null as never), 'invalid_configuration');
  });
});

describe('a current step that is only preferred', () => {
  // ADR-017 Decision 4's passkey-first round: with no login_hint the engine
  // prefers a discoverable passkey and offers the password and the
  // identifier beside it.
  const passkeyFirst = (required?: boolean): StepOffer =>
    ({
      current: { step: 'webauthn_get', params: paramsOf('webauthn_get') },
      alternatives: [
        { step: 'password', params: {} },
        { step: 'identifier', params: {} },
      ],
      ...(required === undefined ? {} : { required }),
    }) as StepOffer;
  const passwordOnly = [STEP_URNS.identifier, STEP_URNS.password];

  it('gives way to the first alternative the client can answer, with its own params', () => {
    expect(body(passkeyFirst(false), round(passwordOnly))).toStrictEqual({
      error: 'insufficient_authorization',
      iss: ISS,
      auth_session: AUTH_SESSION,
      interaction_type_required: STEP_URNS.password,
      qauth_interaction_types_offered: [STEP_URNS.password, STEP_URNS.identifier],
      qauth_interaction_params: { [STEP_URNS.password]: {}, [STEP_URNS.identifier]: {} },
    });
    // A deployment that does not serve passkeys yet: the same.
    const f1 = createFipaMapper({ serves: ['identifier', 'password'] });
    expect(
      (f1.challenge(passkeyFirst(false), round()).body as FipaInsufficientAuthorization)
        .interaction_type_required
    ).toBe(STEP_URNS.password);
  });

  it('carries no error over from the step it replaces', () => {
    const offer = passkeyFirst(false);
    const refused = {
      ...offer,
      current: { ...offer.current, error: 'invalid_credentials' },
    } as StepOffer;
    const answer = body(refused, round(passwordOnly));
    expect(answer.interaction_type_required).toBe(STEP_URNS.password);
    expect(answer).not.toHaveProperty('qauth_interaction_error');
  });

  it('is still served as it is when the client listed it', () => {
    expect(body(passkeyFirst(false)).interaction_type_required).toBe(STEP_URNS.webauthn_get);
  });

  it('gives redirect_to_web when the client can answer no alternative', () => {
    expect(challenge(passkeyFirst(false), round([STEP_URNS.totp])).body).toStrictEqual({
      error: 'redirect_to_web',
      iss: ISS,
    });
  });

  it('keeps today’s answer when the step is required, or the offer does not say', () => {
    for (const required of [true, undefined]) {
      expect(challenge(passkeyFirst(required), round(passwordOnly)).body).toStrictEqual({
        error: 'redirect_to_web',
        iss: ISS,
      });
    }
  });

  it('never applies to a bot challenge: it has no alternative to give way to', () => {
    expectRefusal(
      () =>
        challenge(
          {
            current: { step: 'captcha', params: paramsOf('captcha') },
            alternatives: [],
            required: false,
          },
          round(passwordOnly)
        ),
      'not_negotiated'
    );
  });

  it('is refused unless the flag is a boolean', () => {
    expectRefusal(
      () => challenge({ ...passkeyFirst(), required: 'no' } as never, round(passwordOnly)),
      'unknown_member'
    );
  });
});

describe('the configuration that serves every step', () => {
  it('is frozen', () => {
    expect(Object.isFrozen(FIPA_SERVES_ALL)).toBe(true);
    expect(Object.isFrozen(FIPA_SERVES_ALL.serves)).toBe(true);
  });
});
