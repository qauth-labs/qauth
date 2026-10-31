import { type JsonSchema, stepNamed } from '@qauth-labs/shared-interaction-contract';
import { describe, expect, it } from 'vitest';

import { createFipaMapper, FIPA_SERVES_ALL, type FipaRoundContext } from './fipa-mapper';
import { createInteractionMapper } from './interaction-mapper';
import { toJsonSchemaPart } from './json-schema';
import { StepMappingError } from './mapping-error';
import type { StepOffer } from './offer';
import {
  FIPA_STEP_NAMES,
  grammarStep,
  INTERACTION_ONLY_STEP_NAMES,
  STEP_ERROR_CODES,
  STEP_NAMES,
  STEP_URNS,
  type StepName,
  stepNameOfUrn,
} from './steps';

/**
 * The acceptance criterion: no mapper output carries `error_description` or
 * free text. Every output of both mappers, over every step offered with every
 * other step and with each of its errors, is walked: no prose member is
 * present anywhere, and every string is a step name, an error code, an
 * envelope value the transport fixes, or a params value at a place the
 * step's schema bounds with a `const`, an `enum` or a token pattern. The two
 * places where params carry words, a scope's consent text and the realm's
 * name in the passkey options, hold text the realm's admin set, under the
 * display rule: data from the realm's records, not text the server writes.
 * And the mappers refuse an offer that tries to carry a sentence.
 */

const ROUND: FipaRoundContext = {
  issuer: 'https://auth.example.com',
  authSession: 'YXV0aC1zZXNzaW9uLWhhbmRsZS1vZi0zMi1ieXRlcyE',
  // Every FiPA step, and seven of the eight only the Interaction API serves:
  // 16, the endpoint's limit. Listing those changes nothing.
  interactionTypesSupported: [...FIPA_STEP_NAMES, ...INTERACTION_ONLY_STEP_NAMES.slice(0, 7)].map(
    (name) => STEP_URNS[name]
  ),
};

/** Members that hold sentences in OAuth, RFC 9457 and common error formats. */
const PROSE_MEMBERS = [
  'error_description',
  'error_uri',
  'message',
  'detail',
  'description',
  'hint',
  'title',
  'reason',
  'errors',
];

const interaction = createInteractionMapper();
const fipa = createFipaMapper(FIPA_SERVES_ALL);
const paramsOf = (name: StepName) => stepNamed(name).example.step.params as never;

/** A step's example params as the engine would offer them: `reasons` only after `password_rejected`. */
function offeredParams(name: StepName, error?: string): never {
  const params = { ...(paramsOf(name) as Record<string, unknown>) };
  if (name === 'new_password' && error !== 'password_rejected') delete params['reasons'];
  return params as never;
}

/** Every offer the walk covers: each step alone, with each other step, and with each of its errors. */
function offers(): StepOffer[] {
  const all: StepOffer[] = [];
  for (const name of STEP_NAMES) {
    const errors = [undefined, ...grammarStep(name).errors];
    for (const error of errors) {
      const current = {
        step: name,
        params: offeredParams(name, error),
        ...(error === undefined ? {} : { error }),
      };
      all.push({ current, alternatives: [] } as never);
      // A bot challenge is offered alone, and never as an alternative.
      if (name === 'captcha') continue;
      for (const other of STEP_NAMES) {
        if (other !== name && other !== 'captcha') {
          all.push({
            current,
            alternatives: [{ step: other, params: offeredParams(other) }],
          } as never);
        }
      }
    }
  }
  return all;
}

/** The node of a step's params schema that describes the value at `path`. */
function schemaAt(
  schema: JsonSchema,
  value: unknown,
  path: readonly (string | number)[]
): JsonSchema {
  if (path.length === 0) return schema;
  const [head, ...rest] = path;
  const branches = schema['oneOf'] as JsonSchema[] | undefined;
  if (branches !== undefined) {
    const branch = branches.find((candidate) => {
      const properties = (candidate['properties'] ?? {}) as Record<string, JsonSchema>;
      return Object.entries(value as object).every(
        ([key, member]) =>
          key in properties &&
          (properties[key]['const'] === undefined || properties[key]['const'] === member)
      );
    });
    if (branch === undefined) throw new Error(`no branch describes ${JSON.stringify(value)}`);
    return schemaAt(branch, value, path);
  }
  const inner = (value as Record<string | number, unknown>)[head];
  if (typeof head === 'number') return schemaAt(schema['items'] as JsonSchema, inner, rest);
  const properties = schema['properties'] as Record<string, JsonSchema> | undefined;
  const member = properties?.[head];
  if (member === undefined) throw new Error(`no schema for member ${String(head)}`);
  return schemaAt(member, inner, rest);
}

/** Every string in `value`, with its path, and every object member name. */
function walk(
  value: unknown,
  path: (string | number)[],
  strings: { path: (string | number)[]; value: string }[],
  members: string[]
): void {
  if (typeof value === 'string') strings.push({ path, value });
  else if (Array.isArray(value))
    value.forEach((item, index) => walk(item, [...path, index], strings, members));
  else if (typeof value === 'object' && value !== null) {
    for (const [key, inner] of Object.entries(value)) {
      members.push(key);
      walk(inner, [...path, key], strings, members);
    }
  }
}

/**
 * The only params values that may hold words: text a realm admin set, shown
 * as data under the display rule (no markup, control or format character),
 * never text the server writes. Any other string must be a bounded token: a
 * `const`, an `enum`, or a pattern that is not the display rule. A new
 * display value in a step's params must be added here on purpose.
 */
const REALM_TEXT = new Set(['consent scopes.*.text', 'webauthn_create options.rp.name']);

/** Check one params object, keyed by its step's URN, against its step's schema. */
function checkParams(urn: string, params: unknown) {
  const name = stepNameOfUrn(urn);
  expect(name, urn).toBeDefined();
  const schema = toJsonSchemaPart(grammarStep(name as StepName).params);
  const strings: { path: (string | number)[]; value: string }[] = [];
  walk(params, [], strings, []);
  for (const string of strings) {
    const node = schemaAt(schema, params, string.path);
    const where = `${name} ${string.path.map((part) => (typeof part === 'number' ? '*' : part)).join('.')}`;
    if (node['x-qauth-display'] !== undefined) {
      expect(REALM_TEXT.has(where), `${where} holds display text`).toBe(true);
      expect(node['x-qauth-display'], where).toBe('realm');
      continue;
    }
    const token =
      node['const'] !== undefined ||
      node['enum'] !== undefined ||
      typeof node['pattern'] === 'string';
    expect(token, `${where} is not a bounded token`).toBe(true);
  }
}

describe('the mappers’ output', () => {
  const all = offers();

  it('covers every step, alone and with every other step', () => {
    expect(all.length).toBeGreaterThan(STEP_NAMES.length * (STEP_NAMES.length - 1));
  });

  it('on the Interaction API: no prose member; every string is a step name, an error code, a bounded token or a realm’s own display text', () => {
    for (const offer of all) {
      const view = interaction.stepView(offer);
      const members: string[] = [];
      walk(view, [], [], members);
      for (const member of PROSE_MEMBERS) expect(members).not.toContain(member);
      expect(Object.keys(view).sort()).toEqual(
        ['step', 'alternatives', 'params', ...(view.error === undefined ? [] : ['error'])].sort()
      );
      expect(stepNameOfUrn(view.step)).toBeDefined();
      for (const urn of view.alternatives) expect(stepNameOfUrn(urn)).toBeDefined();
      if (view.error !== undefined) expect(STEP_ERROR_CODES).toContain(view.error);
      for (const [urn, params] of Object.entries(view.params)) checkParams(urn, params);
    }
  });

  it('on the FiPA endpoint: no prose member; every string is a step name, an error code, an envelope value, a bounded token or a realm’s own display text', () => {
    for (const offer of all) {
      let response;
      try {
        response = fipa.challenge(offer, ROUND);
      } catch (error) {
        expect((error as StepMappingError).code).toBe('not_negotiated');
        continue;
      }
      const members: string[] = [];
      walk(response, [], [], members);
      for (const member of PROSE_MEMBERS) expect(members).not.toContain(member);
      expect(JSON.stringify(response)).not.toMatch(/error_description/);
      const { body } = response;
      if (body.error === 'redirect_to_web') {
        expect(body).toStrictEqual({ error: 'redirect_to_web', iss: ROUND.issuer });
        continue;
      }
      expect(body.error).toBe('insufficient_authorization');
      expect(body.iss).toBe(ROUND.issuer);
      expect(body.auth_session).toBe(ROUND.authSession);
      expect(Object.keys(body).sort()).toEqual(
        [
          'error',
          'iss',
          'auth_session',
          'interaction_type_required',
          'qauth_interaction_types_offered',
          'qauth_interaction_params',
          ...(body.qauth_interaction_error === undefined ? [] : ['qauth_interaction_error']),
        ].sort()
      );
      for (const urn of [body.interaction_type_required, ...body.qauth_interaction_types_offered]) {
        expect(stepNameOfUrn(urn)).toBeDefined();
      }
      if (body.qauth_interaction_error !== undefined) {
        expect(STEP_ERROR_CODES).toContain(body.qauth_interaction_error);
      }
      for (const [urn, params] of Object.entries(body.qauth_interaction_params))
        checkParams(urn, params);
    }
  });
});

describe('an offer that tries to carry prose', () => {
  const both = (offer: unknown) => [
    () => interaction.stepView(offer as StepOffer),
    () => fipa.challenge(offer as StepOffer, ROUND),
  ];

  function refusedWith(offer: unknown, code: string) {
    for (const run of both(offer)) {
      expect(run).toThrow(StepMappingError);
      try {
        run();
      } catch (error) {
        expect((error as StepMappingError).code, JSON.stringify(offer)).toBe(code);
      }
    }
  }

  it('is refused with an error_description or a message beside the step', () => {
    const sentence = 'The password is wrong. You have 2 tries left.';
    refusedWith(
      { current: { step: 'password', params: {} }, alternatives: [], error_description: sentence },
      'unknown_member'
    );
    refusedWith(
      { current: { step: 'password', params: {}, message: sentence }, alternatives: [] },
      'unknown_member'
    );
    refusedWith(
      {
        current: { step: 'password', params: {} },
        alternatives: [{ step: 'identifier', params: {}, hint: sentence }],
      },
      'unknown_member'
    );
  });

  it('is refused with a sentence inside the params, in a member or in a bounded value', () => {
    refusedWith(
      { current: { step: 'password', params: { message: 'Try again' } }, alternatives: [] },
      'invalid_params'
    );
    refusedWith(
      {
        current: {
          step: 'new_password',
          params: {
            purpose: 'reset',
            min_length: 15,
            max_length: 256,
            reasons: ['Your password is too short'],
          },
        },
        alternatives: [],
      },
      'invalid_params'
    );
    refusedWith(
      {
        current: {
          step: 'webauthn_create',
          params: {
            ...(paramsOf('webauthn_create') as object),
            options: {
              ...(paramsOf('webauthn_create') as { options: object }).options,
              rp: {
                id: 'auth.example.com',
                // A realm's display name is the realm's data; the display rule
                // still refuses a line break, so no second line can pose as a
                // message.
                name: 'Example\nPlease confirm your account at https://evil.example',
              },
            },
          },
        },
        alternatives: [],
      },
      'invalid_params'
    );
  });

  it('is refused with a sentence for an error', () => {
    refusedWith(
      {
        current: { step: 'password', params: {}, error: 'Wrong password, 2 tries left' },
        alternatives: [],
      },
      'invalid_error'
    );
  });
});
