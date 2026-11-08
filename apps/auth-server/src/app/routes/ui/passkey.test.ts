import { stepUrn } from '@qauth-labs/shared-interaction-contract';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { supplyRequestRealm, testRealm } from '../../../testing/request-realm';
import {
  readInteractionPersonalData,
  readInteractionStep,
  refuseForbidden,
} from '../../helpers/interaction';
import { InteractionExpiredError } from '../../helpers/interaction-expired';
import { buildRealmUrl } from '../../helpers/realm-url';
import passkeyRoutes from './passkey';

vi.mock('../../../config/env', () => ({
  env: {
    NODE_ENV: 'test',
    AUTHORIZE_RATE_LIMIT: 60,
    AUTHORIZE_RATE_LIMIT_LENIENT: 600,
    AUTHORIZE_RATE_WINDOW: 60,
  },
}));

vi.mock('../../helpers/interaction', () => ({
  readInteractionStep: vi.fn(),
  readInteractionPersonalData: vi.fn(),
  refuseForbidden: vi.fn(async () => {
    throw Object.assign(new Error('Forbidden'), { statusCode: 403 });
  }),
}));

const REALM = testRealm({ id: 'realm-1' });
const ID = 'i'.repeat(43);
const CSRF = 'csrf-value-of-the-step-view';
const WEBAUTHN_GET = stepUrn('webauthn_get');
const WEBAUTHN_CREATE = stepUrn('webauthn_create');
const PASSWORD = stepUrn('password');
const IDENTIFIER = stepUrn('identifier');
const REQUEST_OPTIONS = {
  challenge: 'c'.repeat(43),
  rpId: 'auth.example.com',
  timeout: 300_000,
  userVerification: 'required',
};
const CREATION_PARAMS = {
  optional: true,
  options: {
    challenge: 'r'.repeat(43),
    rp: { id: 'auth.example.com', name: 'Example' },
    pubKeyCredParams: [{ type: 'public-key', alg: -8 }],
    timeout: 300_000,
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    attestation: 'none',
  },
};
const CREATION_PERSONAL = {
  identifier: 'ada@example.com',
  user: { id: 'dXNlcg', name: 'ada@example.com', displayName: 'ada@example.com' },
  excludeCredentials: [],
};

/** A step view of the interaction, as `readInteractionStep` answers it. */
const viewOf = (step: Record<string, unknown>) =>
  ({
    step: { alternatives: [], params: {}, ...step },
    csrf: CSRF,
    revision: 3,
    expiresAt: Date.now() + 60_000,
    deadline: Date.now() + 60_000,
  }) as never;

/** The value of the form's `data-options`, unescaped and parsed. */
function optionsOf(body: string): unknown {
  const match = /data-options="([^"]*)"/.exec(body);
  if (match === null) throw new Error('no options on the page');
  return JSON.parse(
    match[1]
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
  );
}

/**
 * The passkey pages (#651): "sign in with a passkey" runs the `webauthn_get`
 * ceremony with options that name no account, and "add a passkey" the
 * `webauthn_create` one for the flow cookie's browser; both post to the
 * Interaction API's answer endpoint, and neither is cached.
 */
describe('the passkey pages (#651)', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    vi.mocked(readInteractionStep).mockReset();
    vi.mocked(readInteractionPersonalData).mockReset();
    vi.mocked(refuseForbidden).mockClear();
    app = Fastify({ logger: false });
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    app.decorateReply('cspNonce', null as never);
    app.addHook('onRequest', async (_request, reply) => {
      reply.cspNonce = { script: 'script-nonce', style: 'style-nonce' };
    });
    supplyRequestRealm(app, REALM);
    await app.register(passkeyRoutes, { prefix: '/ui' });
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  const action = () => buildRealmUrl(REALM, `/interaction/v1-rc.0/${ID}/answer`);

  describe('GET /ui/passkey/:id', () => {
    const get = () => app.inject({ method: 'GET', url: `/ui/passkey/${ID}` });

    it("allows the client's return in form-action: the finishing answer is a 303 there (Chromium and WebKit check it)", async () => {
      await app.close();
      app = Fastify({ logger: false });
      app.setValidatorCompiler(validatorCompiler);
      app.setSerializerCompiler(serializerCompiler);
      app.decorateReply('cspNonce', null as never);
      app.addHook('onRequest', async (_request, reply) => {
        reply.cspNonce = { script: 'script-nonce', style: 'style-nonce' };
        // What the security-headers plugin sets on every page.
        reply.header('Content-Security-Policy', "default-src 'self'; form-action 'self'");
      });
      supplyRequestRealm(app, REALM);
      await app.register(passkeyRoutes, { prefix: '/ui' });
      await app.ready();
      vi.mocked(readInteractionStep).mockResolvedValue({
        ...(viewOf({ name: WEBAUTHN_GET, params: REQUEST_OPTIONS }) as object),
        formAction: 'cursor:',
      } as never);

      const response = await get();

      expect(response.statusCode).toBe(200);
      expect(response.headers['content-security-policy']).toBe(
        "default-src 'self'; form-action 'self' cursor:"
      );
    });

    it('runs the current step’s ceremony, posting to the answer endpoint, never cached', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewOf({ name: WEBAUTHN_GET, params: REQUEST_OPTIONS, alternatives: [PASSWORD] })
      );

      const response = await get();

      expect(response.statusCode).toBe(200);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.body).toContain(`action="${action()}"`);
      expect(response.body).toContain(`name="type" value="${WEBAUTHN_GET}"`);
      expect(response.body).toContain(`name="csrf" value="${CSRF}"`);
      expect(response.body).toContain('name="webauthn_response"');
      expect(response.body).toContain('data-mode="get"');
      expect(response.body).toContain('<script nonce="script-nonce">');
      expect(optionsOf(response.body)).toEqual(REQUEST_OPTIONS);
      expect(response.body).not.toContain('did not work');
      // A way back to the password and the identifier, which works without JavaScript.
      expect(response.body).toContain(
        `<a href="${buildRealmUrl(REALM, `/ui/interaction/${ID}`)}">Sign in another way</a>`
      );
    });

    it('offers the passkey beside the password, with the alternative’s options', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewOf({
          name: PASSWORD,
          alternatives: [WEBAUTHN_GET],
          alternativeParams: { [WEBAUTHN_GET]: REQUEST_OPTIONS },
        })
      );

      const response = await get();

      expect(response.statusCode).toBe(200);
      expect(optionsOf(response.body)).toEqual(REQUEST_OPTIONS);
      expect(response.body).toContain(`name="type" value="${WEBAUTHN_GET}"`);
    });

    it('says a refused passkey did not work, the same for every refusal', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewOf({ name: WEBAUTHN_GET, params: REQUEST_OPTIONS, error: 'invalid_credentials' })
      );

      const response = await get();

      expect(response.body).toContain('That passkey did not work.');
    });

    it('sends an interaction that offers no passkey to its ceremony page', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(viewOf({ name: PASSWORD }));

      const response = await get();

      expect(response.statusCode).toBe(303);
      expect(response.headers.location).toBe(buildRealmUrl(REALM, `/ui/interaction/${ID}`));
    });

    it('answers an ended interaction, or an id that names none, with the ended page, 410', async () => {
      vi.mocked(readInteractionStep).mockRejectedValue(new InteractionExpiredError());

      const ended = await get();
      const malformed = await app.inject({ method: 'GET', url: '/ui/passkey/nope' });

      for (const response of [ended, malformed]) {
        expect(response.statusCode).toBe(410);
        expect(response.headers['cache-control']).toBe('no-store');
        expect(response.body).toContain('This sign-in has ended');
      }
    });
  });

  describe('GET /ui/passkey-enrolment/:id', () => {
    const get = (headers: Record<string, string> = {}) =>
      app.inject({ method: 'GET', url: `/ui/passkey-enrolment/${ID}`, headers });

    beforeEach(() => {
      vi.mocked(readInteractionPersonalData).mockResolvedValue({
        step: WEBAUTHN_CREATE,
        data: CREATION_PERSONAL,
      } as never);
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewOf({ name: WEBAUTHN_CREATE, params: CREATION_PARAMS })
      );
    });

    it('runs the registration with the account’s user entity, and lets the person decline', async () => {
      const response = await get({ 'sec-fetch-site': 'same-origin' });

      expect(response.statusCode).toBe(200);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.body).toContain('data-mode="create"');
      expect(response.body).toContain(`name="type" value="${WEBAUTHN_CREATE}"`);
      expect(optionsOf(response.body)).toEqual({
        ...CREATION_PARAMS.options,
        user: CREATION_PERSONAL.user,
        excludeCredentials: [],
      });
      // "Not now": a second form with the step's type and CSRF and no response.
      expect(response.body.match(/<form\b/g)).toHaveLength(2);
      expect(response.body).toContain('Not now');
    });

    it('offers no "Not now" for a step that is not optional', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewOf({ name: WEBAUTHN_CREATE, params: { ...CREATION_PARAMS, optional: false } })
      );

      const response = await get();

      expect(response.body).not.toContain('Not now');
    });

    it('refuses a request another site sent, before it reads the interaction', async () => {
      const response = await get({ 'sec-fetch-site': 'cross-site' });

      expect(response.statusCode).toBe(403);
      expect(refuseForbidden).toHaveBeenCalled();
      expect(readInteractionPersonalData).not.toHaveBeenCalled();
    });

    it('sends an interaction at another step to its ceremony page', async () => {
      vi.mocked(readInteractionPersonalData).mockResolvedValue({
        step: WEBAUTHN_GET,
        data: {},
      } as never);

      const response = await get();

      expect(response.statusCode).toBe(303);
      expect(response.headers.location).toBe(buildRealmUrl(REALM, `/ui/interaction/${ID}`));
    });

    it('creates an account by passkey at a registration, with the address beside it (#655)', async () => {
      const user = { id: 'aGFuZGxl', name: 'account-aGFuZGxl', displayName: 'account-aGFuZGxl' };
      vi.mocked(readInteractionPersonalData).mockResolvedValue({
        step: WEBAUTHN_CREATE,
        data: { user, excludeCredentials: [] },
      } as never);
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewOf({
          name: WEBAUTHN_CREATE,
          params: { ...CREATION_PARAMS, optional: false },
          alternatives: [IDENTIFIER],
        })
      );

      const response = await get();

      expect(response.statusCode).toBe(200);
      expect(response.body).toContain('Create your account with a passkey');
      expect(response.body).toContain('Use an email address instead');
      expect(response.body).toContain(`href="${buildRealmUrl(REALM, `/ui/interaction/${ID}`)}"`);
      expect(response.body).not.toContain('Not now');
      expect(optionsOf(response.body)).toEqual({
        ...CREATION_PARAMS.options,
        user,
        excludeCredentials: [],
      });
    });

    it('says a refused registration by passkey could not be created (#655)', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewOf({
          name: WEBAUTHN_CREATE,
          params: { ...CREATION_PARAMS, optional: false },
          alternatives: [IDENTIFIER],
          error: 'invalid_credentials',
        })
      );

      const response = await get();

      expect(response.body).toContain('The passkey could not be created.');
    });

    it('adds the new passkey a recovery code binds, with no way to decline (#655)', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewOf({ name: WEBAUTHN_CREATE, params: { ...CREATION_PARAMS, optional: false } })
      );

      const response = await get();

      expect(response.body).toContain('Add a new passkey');
      expect(response.body).toContain('Your recovery code worked.');
      expect(response.body).not.toContain('Not now');
      expect(response.body).not.toContain('Use an email address instead');
    });

    it('says a refused registration could not be added', async () => {
      vi.mocked(readInteractionStep).mockResolvedValue(
        viewOf({ name: WEBAUTHN_CREATE, params: CREATION_PARAMS, error: 'invalid_credentials' })
      );

      const response = await get();

      expect(response.body).toContain('The passkey could not be added.');
    });
  });
});
